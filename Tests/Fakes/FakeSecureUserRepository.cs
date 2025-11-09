using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using SafeVault.Services;

namespace SafeVault.Tests.Fakes;

public sealed class FakeSecureUserRepository : ISecureUserRepository
{
    private readonly Dictionary<string, FakeUserEntry> _users = new(
        StringComparer.OrdinalIgnoreCase
    );

    public Task<UserCredentials?> GetUserCredentialsAsync(string username)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            return Task.FromResult<UserCredentials?>(null);
        }

        if (_users.TryGetValue(username, out var entry))
        {
            return Task.FromResult<UserCredentials?>(entry.ToCredentials());
        }

        return Task.FromResult<UserCredentials?>(null);
    }

    public Task<DataTable> SearchUsersByUsernameAsync(string searchTerm) =>
        Task.FromResult(new DataTable());

    public Task<IReadOnlyCollection<string>> GetUserRolesAsync(int userId)
    {
        var entry = FindByUserId(userId);
        return Task.FromResult<IReadOnlyCollection<string>>(
            entry?.Roles.ToArray() ?? Array.Empty<string>()
        );
    }

    public Task AssignRoleAsync(int userId, string role)
    {
        if (string.IsNullOrWhiteSpace(role))
        {
            throw new ArgumentException("Role cannot be empty.", nameof(role));
        }

        var entry = FindByUserId(userId);
        if (entry is null)
        {
            throw new InvalidOperationException($"User with ID {userId} not found.");
        }

        entry.Roles.Add(role.Trim());
        return Task.CompletedTask;
    }

    public void SeedUser(UserRecord user, string passwordHash, IEnumerable<string>? roles = null)
    {
        _users[user.Username] = new FakeUserEntry(user, passwordHash, roles);
    }

    private FakeUserEntry? FindByUserId(int userId) =>
        _users.Values.FirstOrDefault(entry => entry.User.UserId == userId);

    private sealed class FakeUserEntry
    {
        public FakeUserEntry(UserRecord user, string passwordHash, IEnumerable<string>? roles)
        {
            User = user;
            PasswordHash = passwordHash;
            Roles = new HashSet<string>(
                roles ?? Array.Empty<string>(),
                StringComparer.OrdinalIgnoreCase
            );
        }

        public UserRecord User { get; }
        public string PasswordHash { get; }
        public HashSet<string> Roles { get; }

        public UserCredentials ToCredentials() => new(User, PasswordHash, Roles.ToArray());
    }
}
