using System;
using System.Threading.Tasks;
using NUnit.Framework;
using SafeVault.Services;
using SafeVault.Tests.Fakes;

namespace SafeVault.Tests;

[TestFixture]
public sealed class RoleAuthorizationServiceTests
{
    [Test]
    public async Task AssignRoleAsyncAddsRoleOnce()
    {
        var repository = new FakeSecureUserRepository();
        var hasher = new BcryptPasswordHasher();
        var passwordHash = hasher.Hash("opensesame");
        repository.SeedUser(
            new UserRecord(1, "admin-user", "admin@example.com", DateTime.UtcNow),
            passwordHash
        );

        var service = new RoleAuthorizationService(repository);

        await service.AssignRoleAsync("admin-user", "admin");
        await service.AssignRoleAsync("admin-user", "admin"); // second call is a no-op

        var roles = await service.GetRolesAsync("admin-user");

        Assert.That(roles, Does.Contain("admin"));
        Assert.That(roles, Has.Count.EqualTo(1));
    }

    [Test]
    public async Task HasRoleAsyncReturnsFalseForNonAdmins()
    {
        var repository = new FakeSecureUserRepository();
        repository.SeedUser(
            new UserRecord(7, "standard", "standard@example.com", DateTime.UtcNow),
            "$2a$11$abcdefghijklmnopqrstuv"
        );

        var service = new RoleAuthorizationService(repository);

        var result = await service.HasRoleAsync("standard", "admin");

        Assert.That(result, Is.False);
    }

    [Test]
    public void AssignRoleAsyncThrowsWhenUserMissing()
    {
        var service = new RoleAuthorizationService(new FakeSecureUserRepository());

        Assert.That(
            () => service.AssignRoleAsync("ghost", "admin"),
            Throws.InvalidOperationException
        );
    }
}
