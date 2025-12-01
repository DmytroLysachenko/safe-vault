// Services/RoleAuthorizationService.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

namespace SafeVault.Services;

public interface IRoleAuthorizationService
{
    Task AssignRoleAsync(
        string username,
        string role,
        CancellationToken cancellationToken = default
    );

    Task<bool> HasRoleAsync(
        string username,
        string role,
        CancellationToken cancellationToken = default
    );

    Task<IReadOnlyCollection<string>> GetRolesAsync(
        string username,
        CancellationToken cancellationToken = default
    );
}

public sealed class RoleAuthorizationService : IRoleAuthorizationService
{
    private static readonly StringComparer RoleComparer = StringComparer.OrdinalIgnoreCase;
    private readonly ISecureUserRepository _repository;

    public RoleAuthorizationService(ISecureUserRepository repository)
    {
        _repository = repository;
    }

    public async Task AssignRoleAsync(
        string username,
        string role,
        CancellationToken cancellationToken = default
    )
    {
        // Resolve the user first so we can fail clearly before touching roles.
        var user = await _repository
            .GetUserCredentialsAsync(NormalizeUsername(username), cancellationToken)
            .ConfigureAwait(false);
        if (user is null)
        {
            throw new InvalidOperationException($"User '{username}' was not found.");
        }

        var normalizedRole = NormalizeRole(role);
        if (user.Roles.Any(r => RoleComparer.Equals(r, normalizedRole)))
        {
            return;
        }

        await _repository
            .AssignRoleAsync(user.User.UserId, normalizedRole, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<bool> HasRoleAsync(
        string username,
        string role,
        CancellationToken cancellationToken = default
    )
    {
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(role))
        {
            return false;
        }

        var user = await _repository
            .GetUserCredentialsAsync(NormalizeUsername(username), cancellationToken)
            .ConfigureAwait(false);
        if (user is null)
        {
            return false;
        }

        var normalizedRole = NormalizeRole(role);
        return user.Roles.Any(r => RoleComparer.Equals(r, normalizedRole));
    }

    public async Task<IReadOnlyCollection<string>> GetRolesAsync(
        string username,
        CancellationToken cancellationToken = default
    )
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            return Array.Empty<string>();
        }

        var user = await _repository
            .GetUserCredentialsAsync(NormalizeUsername(username), cancellationToken)
            .ConfigureAwait(false);
        return user?.Roles ?? Array.Empty<string>();
    }

    private static string NormalizeRole(string role)
    {
        if (string.IsNullOrWhiteSpace(role))
        {
            throw new ArgumentException("Role name cannot be empty.", nameof(role));
        }

        return role.Trim();
    }

    private static string NormalizeUsername(string username)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            throw new ArgumentException("Username cannot be empty.", nameof(username));
        }

        return username.Trim();
    }
}
