using Microsoft.AspNetCore.Identity;
using Raven.Client.Documents;
using Raven.Client.Documents.Operations.CompareExchange;
using Raven.Client.Documents.Session;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace Raven.Identity
{
  /// <summary>
  /// UserStore for entities in a RavenDB database.
  /// </summary>
  /// <typeparam name="TUser"></typeparam>
  /// <typeparam name="TRole"></typeparam>
  public class UserStore<TUser, TRole> :
      IUserStore<TUser>,
      IUserLoginStore<TUser>,
      IUserClaimStore<TUser>,
      IUserRoleStore<TUser>,
      IUserPasswordStore<TUser>,
      IUserSecurityStampStore<TUser>,
      IUserEmailStore<TUser>,
      IUserLockoutStore<TUser>,
      IUserTwoFactorStore<TUser>,
      IUserPhoneNumberStore<TUser>,
      IUserAuthenticatorKeyStore<TUser>,
      IUserAuthenticationTokenStore<TUser>,
      IUserTwoFactorRecoveryCodeStore<TUser>,
      IQueryableUserStore<TUser>
      where TUser : IdentityUser
      where TRole : IdentityRole, new()
  {
    private bool _disposed;
    private IDocumentStore _store;

    private const string emailReservationKeyPrefix = "emails/";

    /// <summary>
    /// Creates a new user store that uses the specified Raven document store.
    /// </summary>
    /// <param name="store"></param>
    public UserStore(IDocumentStore store)
    {
      this._store = store;
    }

    #region IDispoable implementation

    /// <summary>
    /// Disposes the user store.
    /// </summary>
    public void Dispose()
    {
      _disposed = true;
    }

    #endregion

    #region IUserStore implementation

    /// <inheritdoc />
    public Task<string> GetUserIdAsync(TUser user, CancellationToken cancellationToken)
    {
      ThrowIfNullDisposedCancelled(user, cancellationToken);

      return Task.FromResult(user.Id);
    }

    /// <inheritdoc />
    public Task<string> GetUserNameAsync(TUser user, CancellationToken cancellationToken)
    {
      ThrowIfNullDisposedCancelled(user, cancellationToken);

      return Task.FromResult(user.UserName);
    }

    /// <inheritdoc />
    public async Task SetUserNameAsync(TUser user, string userName, CancellationToken cancellationToken)
    {
      ThrowIfNullDisposedCancelled(user, cancellationToken);

      user.UserName = userName;

      using (IAsyncDocumentSession session = _store.OpenAsyncSession())
      {
        await session.SaveChangesAsync(cancellationToken);
      }
    }

    /// <inheritdoc />
    public Task<string> GetNormalizedUserNameAsync(TUser user, CancellationToken cancellationToken)
    {
      ThrowIfNullDisposedCancelled(user, cancellationToken);

      // Raven string comparison queries are case-insensitive. We can just return the user name.
      return Task.FromResult(user.UserName);
    }

    /// <inheritdoc />
    public async Task SetNormalizedUserNameAsync(TUser user, string normalizedName, CancellationToken cancellationToken)
    {
      ThrowIfNullDisposedCancelled(user, cancellationToken);

      user.UserName = normalizedName.ToLowerInvariant();

      using (IAsyncDocumentSession session = _store.OpenAsyncSession())
      {
        await session.SaveChangesAsync(cancellationToken);
      }
    }

    /// <inheritdoc />
    public async Task<IdentityResult> CreateAsync(TUser user, CancellationToken cancellationToken)
    {
      ThrowIfNullDisposedCancelled(user, cancellationToken);

      // Make sure we have a valid email address.
      if (string.IsNullOrWhiteSpace(user.Email))
      {
        throw new ArgumentException("The user's email address can't be null or empty.", nameof(user));
      }

      if (string.IsNullOrEmpty(user.Id))
      {
        var conventions = _store.Conventions;
        var entityName = conventions.GetCollectionName(typeof(TUser));
        var prefix = conventions.TransformTypeCollectionNameToDocumentIdPrefix(entityName);
        var separator = conventions.IdentityPartsSeparator;
        var id = $"{prefix}{separator}{user.Email}";
        user.Id = id;
      }

      if (string.IsNullOrEmpty(user.UserName))
      {
        user.UserName = user.Email;
      }

      cancellationToken.ThrowIfCancellationRequested();

      // See if the email address is already taken.
      // We do this using Raven's compare/exchange functionality, which works cluster-wide.
      // https://ravendb.net/docs/article-page/4.1/csharp/client-api/operations/compare-exchange/overview#creating-a-key
      //
      // Try to reserve a new user email 
      // Note: This operation takes place outside of the session transaction it is a cluster-wide reservation.
      var compareExchangeKey = GetCompareExchangeKeyFromEmail(user.Email);
      var reserveEmailOperation = new PutCompareExchangeValueOperation<string>(compareExchangeKey, user.Id, 0);
      var reserveEmailResult = await _store.Operations.SendAsync(reserveEmailOperation);
      if (!reserveEmailResult.Successful)
      {
        return IdentityResult.Failed(new[]
        {
                    new IdentityError
                    {
                        Code = "DuplicateEmail",
                        Description = $"The email address {user.Email} is already taken."
                    }
                });
      }

      using (IAsyncDocumentSession session = _store.OpenAsyncSession())
      {
        // This model allows us to lookup a user by name in order to get the id
        await session.StoreAsync(user, cancellationToken);

        // Because this a a cluster-wide operation due to compare/exchange tokens,
        // we need to save changes here; if we can't store the user, 
        // we need to roll back the email reservation.
        try
        {
          await session.SaveChangesAsync(cancellationToken);
        }
        catch (Exception)
        {
          // The compare/exchange email reservation is cluster-wide, outside of the session scope. 
          // We need to manually roll it back.
          await this.DeleteUserEmailReservation(user.Email);
          throw;
        }
      }

      return IdentityResult.Success;
    }

    /// <inheritdoc />
    public Task<IdentityResult> UpdateAsync(TUser user, CancellationToken cancellationToken)
    {
      ThrowIfNullDisposedCancelled(user, cancellationToken);

      return Task.FromResult(IdentityResult.Success);
    }

    /// <inheritdoc />
    public async Task<IdentityResult> DeleteAsync(TUser user, CancellationToken cancellationToken)
    {
      ThrowIfNullDisposedCancelled(user, cancellationToken);
      cancellationToken.ThrowIfCancellationRequested();

      // Remove the cluster-wide compare/exchange key.
      var deletionResult = await DeleteUserEmailReservation(user.Email);
      if (!deletionResult.Successful)
      {
        return IdentityResult.Failed(new[]
        {
                    new IdentityError
                    {
                        Code = "ConcurrencyFailure",
                        Description = "Unable to delete user email compare/exchange value"
                    }
                });
      }


      // Delete the user and save it. We must save it because deleting is a cluster-wide operation.
      // Only if the deletion succeeds will we remove the cluseter-wide compare/exchange key.
      using (IAsyncDocumentSession session = _store.OpenAsyncSession())
      {
        session.Delete(user);
        await session.SaveChangesAsync(cancellationToken);
      }

      return IdentityResult.Success;
    }

    /// <inheritdoc />
    public Task<TUser> FindByIdAsync(string userId, CancellationToken cancellationToken)
    {
      ThrowIfDisposedOrCancelled(cancellationToken);

      using (IAsyncDocumentSession session = _store.OpenAsyncSession())
      {
        return session.LoadAsync<TUser>(userId);
      }
    }

    /// <inheritdoc />
    public async Task<TUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
    {
      ThrowIfDisposedOrCancelled(cancellationToken);
      if (string.IsNullOrEmpty(normalizedUserName))
      {
        throw new ArgumentNullException(nameof(normalizedUserName));
      }

      var compareExchangeKey = GetCompareExchangeKeyFromEmail(normalizedUserName);
      var getEmailReservationOperation = new GetCompareExchangeValueOperation<string>(compareExchangeKey);

      var emailReservationResultOrNull = await _store.Operations.SendAsync(getEmailReservationOperation);
      var userId = emailReservationResultOrNull?.Value;
      if (string.IsNullOrEmpty(userId))
      {
        return null;
      }

      cancellationToken.ThrowIfCancellationRequested();

      return await FindByIdAsync(userId, cancellationToken);
    }

    #endregion

    #region IUserLoginStore implementation

    /// <inheritdoc />
    public async Task AddLoginAsync(TUser user, UserLoginInfo login, CancellationToken cancellationToken)
    {
      ThrowIfNullDisposedCancelled(user, cancellationToken);
      if (login == null)
      {
        throw new ArgumentNullException(nameof(login));
      }

      if (!user.Logins.Any(x => x.LoginProvider == login.LoginProvider && x.ProviderKey == login.ProviderKey))
      {
        user.Logins.Add(login);

        var userLogin = new IdentityUserLogin
        {
          Id = Util.GetLoginId(login),
          UserId = user.Id,
          Provider = login.LoginProvider,
          ProviderKey = login.ProviderKey
        };

        using (IAsyncDocumentSession session = _store.OpenAsyncSession())
        {
          await session.StoreAsync(userLogin);
          await session.SaveChangesAsync(cancellationToken);
        }
      }
    }

    /// <inheritdoc />
    public async Task RemoveLoginAsync(TUser user, string loginProvider, string providerKey, CancellationToken cancellationToken)
    {
      ThrowIfNullDisposedCancelled(user, cancellationToken);

      var login = new UserLoginInfo(loginProvider, providerKey, string.Empty);
      string loginId = Util.GetLoginId(login);

      using (IAsyncDocumentSession session = _store.OpenAsyncSession())
      {
        var loginDoc = await session.LoadAsync<IdentityUserLogin>(loginId);
        if (loginDoc != null)
        {
          session.Delete(loginDoc);
          await session.SaveChangesAsync(cancellationToken);
        }
      }

      cancellationToken.ThrowIfCancellationRequested();

      user.Logins.RemoveAll(x => x.LoginProvider == login.LoginProvider && x.ProviderKey == login.ProviderKey);
    }

    /// <inheritdoc />
    public Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user, CancellationToken cancellationToken)
    {
      ThrowIfNullDisposedCancelled(user, cancellationToken);

      return Task.FromResult(user.Logins.ToIList());
    }

    /// <inheritdoc />
    public async Task<TUser> FindByLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken)
    {
      var login = new UserLoginInfo(loginProvider, providerKey, string.Empty);
      string loginId = Util.GetLoginId(login);

      using (IAsyncDocumentSession session = _store.OpenAsyncSession())
      {
        var loginDoc = await session.LoadAsync<IdentityUserLogin>(loginId);
        if (loginDoc != null)
        {
          return await session.LoadAsync<TUser>(loginDoc.UserId);
        }
      }

      return null;
    }

    #endregion

    #region IUserClaimStore implementation

    /// <inheritdoc />
    public Task<IList<Claim>> GetClaimsAsync(TUser user, CancellationToken cancellationToken)
    {
      ThrowIfNullDisposedCancelled(user, cancellationToken);

      IList<Claim> result = user.Claims
          .Select(c => new Claim(c.ClaimType, c.ClaimValue))
          .ToList();
      return Task.FromResult(result);
    }

    /// <inheritdoc />
    public async Task AddClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
    {
      ThrowIfNullDisposedCancelled(user, cancellationToken);

      using (IAsyncDocumentSession session = _store.OpenAsyncSession())
      {
        user.Claims.AddRange(claims.Select(c => new IdentityUserClaim { ClaimType = c.Type, ClaimValue = c.Value }));
        await session.SaveChangesAsync(cancellationToken);
      }
    }

    /// <inheritdoc />
    public async Task ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken)
    {
      ThrowIfNullDisposedCancelled(user, cancellationToken);

      var indexOfClaim = user.Claims.FindIndex(c => c.ClaimType == claim.Type && c.ClaimValue == claim.Value);
      if (indexOfClaim != -1)
      {
        user.Claims.RemoveAt(indexOfClaim);
        await AddClaimsAsync(user, new[] { newClaim }, cancellationToken);
      }
    }

    /// <inheritdoc />
    public async Task RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
    {
      ThrowIfNullDisposedCancelled(user, cancellationToken);

      using (IAsyncDocumentSession session = _store.OpenAsyncSession())
      {
        user.Claims.RemoveAll(identityClaim => claims.Any(c => c.Type == identityClaim.ClaimType && c.Value == identityClaim.ClaimValue));
        await session.SaveChangesAsync(cancellationToken);
      }
    }

    /// <inheritdoc />
    public async Task<IList<TUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken)
    {
      ThrowIfDisposedOrCancelled(cancellationToken);
      if (claim == null)
      {
        throw new ArgumentNullException(nameof(claim));
      }

      using (IAsyncDocumentSession session = _store.OpenAsyncSession())
      {
        return await session.Query<TUser>()
          .Where(u => u.Claims.Any(c => c.ClaimType == claim.Type && c.ClaimValue == claim.Value))
          .ToListAsync();
      }
    }

    #endregion

    #region IUserRoleStore implementation

    /// <inheritdoc />
    public async Task AddToRoleAsync(TUser user, string roleName, CancellationToken cancellationToken)
    {
      ThrowIfNullDisposedCancelled(user, cancellationToken);

      // See if we have an IdentityRole with that name.
      var identityUserCollection = _store.Conventions.GetCollectionName(typeof(TRole));
      var prefix = _store.Conventions.TransformTypeCollectionNameToDocumentIdPrefix(identityUserCollection);
      var identityPartSeperator = _store.Conventions.IdentityPartsSeparator;
      var roleNameLowered = roleName.ToLowerInvariant();
      var roleId = prefix + identityPartSeperator + roleNameLowered;

      using (IAsyncDocumentSession session = _store.OpenAsyncSession())
      {
        var existingRoleOrNull = await session.LoadAsync<IdentityRole>(roleId, cancellationToken);
        if (existingRoleOrNull == null)
        {
          ThrowIfDisposedOrCancelled(cancellationToken);
          existingRoleOrNull = new TRole();
          existingRoleOrNull.Name = roleNameLowered;
          await session.StoreAsync(existingRoleOrNull, roleId, cancellationToken);
        }

        // Use the real name (not normalized/uppered/lowered) of the role, as specified by the user.
        var roleRealName = existingRoleOrNull.Name;
        if (!user.Roles.Contains(roleRealName, StringComparer.InvariantCultureIgnoreCase))
        {
          user.GetRolesList().Add(roleRealName);
        }

        if (!existingRoleOrNull.Users.Contains(user.Id, StringComparer.InvariantCultureIgnoreCase))
        {
          existingRoleOrNull.Users.Add(user.Id);
        }

        await session.SaveChangesAsync(cancellationToken);
      }
    }

    /// <inheritdoc />
    public async Task RemoveFromRoleAsync(TUser user, string roleName, CancellationToken cancellationToken)
    {
      ThrowIfNullDisposedCancelled(user, cancellationToken);

      user.GetRolesList().RemoveAll(r => string.Equals(r, roleName, StringComparison.InvariantCultureIgnoreCase));

      var roleId = RoleStore<TRole>.GetRavenIdFromRoleName(roleName, _store);

      using (IAsyncDocumentSession session = _store.OpenAsyncSession())
      {
        var roleOrNull = await session.LoadAsync<IdentityRole>(roleId, cancellationToken);
        if (roleOrNull != null)
        {
          roleOrNull.Users.Remove(user.Id);
        }
        await session.SaveChangesAsync(cancellationToken);
      }
    }

    /// <inheritdoc />
    public Task<IList<string>> GetRolesAsync(TUser user, CancellationToken cancellationToken)
    {
      ThrowIfNullDisposedCancelled(user, cancellationToken);

      return Task.FromResult<IList<string>>(new List<string>(user.Roles));
    }

    /// <inheritdoc />
    public Task<bool> IsInRoleAsync(TUser user, string roleName, CancellationToken cancellationToken)
    {
      if (string.IsNullOrEmpty(roleName))
      {
        throw new ArgumentNullException(nameof(roleName));
      }

      return Task.FromResult(user.Roles.Contains(roleName, StringComparer.InvariantCultureIgnoreCase));
    }

    /// <inheritdoc />
    public async Task<IList<TUser>> GetUsersInRoleAsync(string roleName, CancellationToken cancellationToken)
    {
      ThrowIfDisposedOrCancelled(cancellationToken);
      if (string.IsNullOrEmpty(roleName))
      {
        throw new ArgumentNullException(nameof(roleName));
      }

      using (IAsyncDocumentSession session = _store.OpenAsyncSession())
      {
        return await session.Query<TUser>()
            .Where(u => u.Roles.Contains(roleName, StringComparer.InvariantCultureIgnoreCase))
            .Take(1024)
            .ToListAsync();
      }
    }

    #endregion

    #region IUserPasswordStore implementation

    /// <inheritdoc />
    public async Task SetPasswordHashAsync(TUser user, string passwordHash, CancellationToken cancellationToken)
    {
      ThrowIfNullDisposedCancelled(user, cancellationToken);

      using (IAsyncDocumentSession session = _store.OpenAsyncSession())
      {
        user.PasswordHash = passwordHash;
        await session.SaveChangesAsync(cancellationToken);
      }
    }

    /// <inheritdoc />
    public Task<string> GetPasswordHashAsync(TUser user, CancellationToken cancellationToken)
    {
      ThrowIfNullDisposedCancelled(user, cancellationToken);

      return Task.FromResult(user.PasswordHash);
    }

    /// <inheritdoc />
    public Task<bool> HasPasswordAsync(TUser user, CancellationToken cancellationToken)
    {
      ThrowIfNullDisposedCancelled(user, cancellationToken);

      return Task.FromResult(user.PasswordHash != null);
    }

    #endregion

    #region IUserSecurityStampStore implementation

    /// <inheritdoc />
    public async Task SetSecurityStampAsync(TUser user, string stamp, CancellationToken cancellationToken)
    {
      ThrowIfNullDisposedCancelled(user, cancellationToken);

      using (IAsyncDocumentSession session = _store.OpenAsyncSession())
      {
        user.SecurityStamp = stamp;
        await session.SaveChangesAsync(cancellationToken);
      }
    }

    /// <inheritdoc />
    public Task<string> GetSecurityStampAsync(TUser user, CancellationToken cancellationToken)
    {
      ThrowIfNullDisposedCancelled(user, cancellationToken);

      return Task.FromResult(user.SecurityStamp);
    }

    #endregion

    #region IUserEmailStore implementation

    /// <inheritdoc />
    public async Task SetEmailAsync(TUser user, string email, CancellationToken cancellationToken)
    {
      ThrowIfDisposedOrCancelled(cancellationToken);
      using (IAsyncDocumentSession session = _store.OpenAsyncSession())
      {
        user.Email = email ?? throw new ArgumentNullException(nameof(email));
        await session.SaveChangesAsync(cancellationToken);
      }
    }

    /// <inheritdoc />
    public Task<string> GetEmailAsync(TUser user, CancellationToken cancellationToken)
    {
      ThrowIfNullDisposedCancelled(user, cancellationToken);

      return Task.FromResult(user.Email);
    }

    /// <inheritdoc />
    public Task<bool> GetEmailConfirmedAsync(TUser user, CancellationToken cancellationToken)
    {
      ThrowIfNullDisposedCancelled(user, cancellationToken);

      return Task.FromResult(user.EmailConfirmed);
    }

    /// <inheritdoc />
    public async Task SetEmailConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken)
    {
      ThrowIfNullDisposedCancelled(user, cancellationToken);

      using (IAsyncDocumentSession session = _store.OpenAsyncSession())
      {
        user.EmailConfirmed = confirmed;
        await session.SaveChangesAsync(cancellationToken);
      }
    }

    /// <inheritdoc />
    public Task<TUser> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken)
    {
      ThrowIfDisposedOrCancelled(cancellationToken);

      using (IAsyncDocumentSession session = _store.OpenAsyncSession())
      {
        return session.Query<TUser>()
          .FirstOrDefaultAsync(u => u.Email == normalizedEmail, cancellationToken);
      }
    }

    /// <inheritdoc />
    public Task<string> GetNormalizedEmailAsync(TUser user, CancellationToken cancellationToken)
    {
      ThrowIfNullDisposedCancelled(user, cancellationToken);

      // Raven string comparison queries are case-insensitive. We can just return the user name.
      return Task.FromResult(user.Email);
    }

    /// <inheritdoc />
    public async Task SetNormalizedEmailAsync(TUser user, string normalizedEmail, CancellationToken cancellationToken)
    {
      ThrowIfNullDisposedCancelled(user, cancellationToken);
      if (string.IsNullOrEmpty(normalizedEmail))
      {
        throw new ArgumentNullException(nameof(normalizedEmail));
      }

      using (IAsyncDocumentSession session = _store.OpenAsyncSession())
      {
        user.Email = normalizedEmail.ToLowerInvariant(); // I don't like the ALL CAPS default. We're going all lower.
        await session.SaveChangesAsync(cancellationToken);
      }
    }

    #endregion

    #region IUserLockoutStore implementation

    /// <inheritdoc />
    public Task<DateTimeOffset?> GetLockoutEndDateAsync(TUser user, CancellationToken cancellationToken)
    {
      ThrowIfNullDisposedCancelled(user, cancellationToken);

      return Task.FromResult(user.LockoutEnd);
    }

    /// <inheritdoc />
    public async Task SetLockoutEndDateAsync(TUser user, DateTimeOffset? lockoutEnd, CancellationToken cancellationToken)
    {
      ThrowIfNullDisposedCancelled(user, cancellationToken);

      using (IAsyncDocumentSession session = _store.OpenAsyncSession())
      {
        user.LockoutEnd = lockoutEnd;
        await session.SaveChangesAsync(cancellationToken);
      }
    }

    /// <inheritdoc />
    public async Task<int> IncrementAccessFailedCountAsync(TUser user, CancellationToken cancellationToken)
    {
      ThrowIfNullDisposedCancelled(user, cancellationToken);

      using (IAsyncDocumentSession session = _store.OpenAsyncSession())
      {
        user.AccessFailedCount++;
        await session.SaveChangesAsync(cancellationToken);
      }

      return user.AccessFailedCount;
    }

    /// <inheritdoc />
    public async Task ResetAccessFailedCountAsync(TUser user, CancellationToken cancellationToken)
    {
      ThrowIfNullDisposedCancelled(user, cancellationToken);

      using (IAsyncDocumentSession session = _store.OpenAsyncSession())
      {
        user.AccessFailedCount = 0;
        await session.SaveChangesAsync(cancellationToken);
      }
    }

    /// <inheritdoc />
    public Task<int> GetAccessFailedCountAsync(TUser user, CancellationToken cancellationToken)
    {
      ThrowIfNullDisposedCancelled(user, cancellationToken);

      return Task.FromResult(user.AccessFailedCount);
    }

    /// <inheritdoc />
    public Task<bool> GetLockoutEnabledAsync(TUser user, CancellationToken cancellationToken)
    {
      ThrowIfNullDisposedCancelled(user, cancellationToken);
      return Task.FromResult(user.LockoutEnabled);
    }

    /// <inheritdoc />
    public async Task SetLockoutEnabledAsync(TUser user, bool enabled, CancellationToken cancellationToken)
    {
      ThrowIfNullDisposedCancelled(user, cancellationToken);

      using (IAsyncDocumentSession session = _store.OpenAsyncSession())
      {
        user.LockoutEnabled = enabled;
        await session.SaveChangesAsync(cancellationToken);
      }
    }

    #endregion

    #region IUserTwoFactorStore implementation

    /// <inheritdoc />
    public async Task SetTwoFactorEnabledAsync(TUser user, bool enabled, CancellationToken cancellationToken)
    {
      ThrowIfNullDisposedCancelled(user, cancellationToken);

      using (IAsyncDocumentSession session = _store.OpenAsyncSession())
      {
        user.TwoFactorEnabled = enabled;
        await session.SaveChangesAsync(cancellationToken);
      }
    }

    /// <inheritdoc />
    public Task<bool> GetTwoFactorEnabledAsync(TUser user, CancellationToken cancellationToken)
    {
      ThrowIfNullDisposedCancelled(user, cancellationToken);

      return Task.FromResult(user.TwoFactorEnabled);
    }

    #endregion

    #region IUserPhoneNumberStore implementation

    /// <inheritdoc />
    public async Task SetPhoneNumberAsync(TUser user, string phoneNumber, CancellationToken cancellationToken)
    {
      ThrowIfNullDisposedCancelled(user, cancellationToken);

      using (IAsyncDocumentSession session = _store.OpenAsyncSession())
      {
        user.PhoneNumber = phoneNumber;
        await session.SaveChangesAsync(cancellationToken);
      }
    }

    /// <inheritdoc />
    public Task<string> GetPhoneNumberAsync(TUser user, CancellationToken cancellationToken)
    {
      ThrowIfNullDisposedCancelled(user, cancellationToken);

      return Task.FromResult(user.PhoneNumber);
    }

    /// <inheritdoc />
    public Task<bool> GetPhoneNumberConfirmedAsync(TUser user, CancellationToken cancellationToken)
    {
      ThrowIfNullDisposedCancelled(user, cancellationToken);

      return Task.FromResult(user.PhoneNumberConfirmed);
    }

    /// <inheritdoc />
    public async Task SetPhoneNumberConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken)
    {
      ThrowIfNullDisposedCancelled(user, cancellationToken);

      using (IAsyncDocumentSession session = _store.OpenAsyncSession())
      {
        user.PhoneNumberConfirmed = confirmed;
        await session.SaveChangesAsync(cancellationToken);
      }
    }

    #endregion

    #region IUserAuthenticatorKeyStore implementation

    /// <inheritdoc />
    public async Task SetAuthenticatorKeyAsync(TUser user, string key, CancellationToken cancellationToken)
    {
      using (IAsyncDocumentSession session = _store.OpenAsyncSession())
      {
        user.TwoFactorAuthenticatorKey = key;
        await session.SaveChangesAsync(cancellationToken);
      }
    }

    /// <inheritdoc />
    public Task<string> GetAuthenticatorKeyAsync(TUser user, CancellationToken cancellationToken)
    {
      return Task.FromResult(user.TwoFactorAuthenticatorKey);
    }

    #endregion

    #region IUserAuthenticationTokenStore

    /// <inheritdoc />
    public async Task SetTokenAsync(TUser user, string loginProvider, string name, string value, CancellationToken cancellationToken)
    {
      var id = IdentityUserAuthToken.GetWellKnownId(_store, user.Id, loginProvider, name);
      ThrowIfDisposedOrCancelled(cancellationToken);

      using (IAsyncDocumentSession session = _store.OpenAsyncSession())
      {
        var existingOrNull = await session.LoadAsync<IdentityUserAuthToken>(id);
        if (existingOrNull == null)
        {
          existingOrNull = new IdentityUserAuthToken
          {
            Id = id,
            LoginProvider = loginProvider,
            Name = name,
            UserId = user.Id,
            Value = value
          };
          await session.StoreAsync(existingOrNull);
        }

        existingOrNull.Value = value;

        await session.SaveChangesAsync(cancellationToken);
      }
    }

    /// <inheritdoc />
    public async Task RemoveTokenAsync(TUser user, string loginProvider, string name, CancellationToken cancellationToken)
    {
      var id = IdentityUserAuthToken.GetWellKnownId(_store, user.Id, loginProvider, name);

      using (IAsyncDocumentSession session = _store.OpenAsyncSession())
      {
        session.Delete(id);
        await session.SaveChangesAsync(cancellationToken);
      }
    }

    /// <inheritdoc />
    public async Task<string> GetTokenAsync(TUser user, string loginProvider, string name, CancellationToken cancellationToken)
    {
      var id = IdentityUserAuthToken.GetWellKnownId(_store, user.Id, loginProvider, name);

      using (IAsyncDocumentSession session = _store.OpenAsyncSession())
      {
        var tokenOrNull = await session.LoadAsync<IdentityUserAuthToken>(id);
        if (tokenOrNull == null)
        {
          return null;
        }

        return tokenOrNull.Value;
      }
    }

    /// <inheritdoc />
    public async Task ReplaceCodesAsync(TUser user, IEnumerable<string> recoveryCodes, CancellationToken cancellationToken)
    {
      using (IAsyncDocumentSession session = _store.OpenAsyncSession())
      {
        user.TwoFactorRecoveryCodes = new List<string>(recoveryCodes);
        await session.SaveChangesAsync(cancellationToken);
      }
    }

    /// <inheritdoc />
    public async Task<bool> RedeemCodeAsync(TUser user, string code, CancellationToken cancellationToken)
    {
      using (IAsyncDocumentSession session = _store.OpenAsyncSession())
      {
        bool isRemoved = user.TwoFactorRecoveryCodes.Remove(code);
        await session.SaveChangesAsync(cancellationToken);
        return isRemoved;
      }
    }

    /// <inheritdoc />
    public Task<int> CountCodesAsync(TUser user, CancellationToken cancellationToken)
    {
      return Task.FromResult(user.TwoFactorRecoveryCodes.Count);
    }

    #endregion

    #region IQueryableUserStore

    /// <summary>
    /// Gets the users as an IQueryable.
    /// </summary>
    public IQueryable<TUser> Users
    {
      get
      {
        using (IAsyncDocumentSession session = _store.OpenAsyncSession())
        {
          return session.Query<TUser>();
        }
      }
    }

    #endregion

    private void ThrowIfNullDisposedCancelled(TUser user, CancellationToken token)
    {
      if (_disposed)
      {
        throw new ObjectDisposedException(this.GetType().Name);
      }
      if (user == null)
      {
        throw new ArgumentNullException(nameof(user));
      }
      token.ThrowIfCancellationRequested();
    }

    private void ThrowIfDisposedOrCancelled(CancellationToken token)
    {
      if (_disposed)
      {
        throw new ObjectDisposedException(this.GetType().Name);
      }
      token.ThrowIfCancellationRequested();
    }

    private Task<CompareExchangeResult<string>> DeleteUserEmailReservation(string email)
    {
      var key = GetCompareExchangeKeyFromEmail(email);
      var store = _store;

      var readResult = store.Operations.Send(new GetCompareExchangeValueOperation<string>(key));
      if (readResult == null)
      {
        return Task.FromResult(new CompareExchangeResult<string>() { Successful = false });
      }

      var deleteEmailOperation = new DeleteCompareExchangeValueOperation<string>(key, readResult.Index);
      return _store.Operations.SendAsync(deleteEmailOperation);
    }

    private static string GetCompareExchangeKeyFromEmail(string email)
    {
      return emailReservationKeyPrefix + email.ToLowerInvariant();
    }
  }
}
