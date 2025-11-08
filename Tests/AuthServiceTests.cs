using System;
using System.Collections.Generic;
using System.Data;
using NUnit.Framework;
using SafeVault.Services;

namespace SafeVault.Tests;

[TestFixture]
public sealed class AuthServiceTests
{
    [Test]
    public async Task AuthenticateAsyncReturnsUserWhenPasswordMatches()
    {
        var repository = new FakeSecureUserRepository();
        var passwordHasher = new BcryptPasswordHasher();
        var service = new UserAuthenticationService(repository, passwordHasher);

        var hash = service.HashPassword("super-secret!");
        repository.SeedUser(new UserRecord(1, "alice", "alice@example.com", DateTime.UtcNow), hash);

        var user = await service.AuthenticateAsync("alice", "super-secret!");

        Assert.That(user.HasValue, Is.True);
        Assert.That(user.Value.Username, Is.EqualTo("alice"));
    }

    [Test]
    public async Task AuthenticateAsyncReturnsNullWhenPasswordDoesNotMatch()
    {
        var repository = new FakeSecureUserRepository();
        var passwordHasher = new BcryptPasswordHasher();
        var service = new UserAuthenticationService(repository, passwordHasher);

        var hash = service.HashPassword("correct horse battery staple");
        repository.SeedUser(new UserRecord(42, "bob", "bob@example.com", DateTime.UtcNow), hash);

        var user = await service.AuthenticateAsync("bob", "wrong-password");

        Assert.That(user.HasValue, Is.False);
    }

    [Test]
    public void HashPasswordThrowsForBlankInput()
    {
        var service = new UserAuthenticationService(
            new FakeSecureUserRepository(),
            new BcryptPasswordHasher()
        );

        Assert.That(() => service.HashPassword(" "), Throws.ArgumentException);
    }

    private sealed class FakeSecureUserRepository : ISecureUserRepository
    {
        private readonly Dictionary<string, UserCredentials> _users = new(
            StringComparer.OrdinalIgnoreCase
        );

        public Task<UserCredentials?> GetUserCredentialsAsync(string username)
        {
            _users.TryGetValue(username, out var credentials);
            return Task.FromResult<UserCredentials?>(credentials);
        }

        public Task<DataTable> SearchUsersByUsernameAsync(string searchTerm) =>
            Task.FromResult(new DataTable());

        public void SeedUser(UserRecord user, string passwordHash)
        {
            _users[user.Username] = new UserCredentials(user, passwordHash);
        }
    }
}
