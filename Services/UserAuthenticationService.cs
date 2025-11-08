// Services/UserAuthenticationService.cs
namespace SafeVault.Services;

public interface IUserAuthenticationService
{
    Task<UserRecord?> AuthenticateAsync(
        string? username,
        string? password,
        CancellationToken cancellationToken = default
    );

    string HashPassword(string password);

    bool VerifyPassword(string password, string passwordHash);
}

public sealed class UserAuthenticationService : IUserAuthenticationService
{
    private readonly ISecureUserRepository _repository;
    private readonly IPasswordHasher _passwordHasher;

    public UserAuthenticationService(
        ISecureUserRepository repository,
        IPasswordHasher passwordHasher
    )
    {
        _repository = repository;
        _passwordHasher = passwordHasher;
    }

    public async Task<UserRecord?> AuthenticateAsync(
        string? username,
        string? password,
        CancellationToken cancellationToken = default
    )
    {
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
        {
            return null;
        }

        var credentials = await _repository
            .GetUserCredentialsAsync(username.Trim())
            .ConfigureAwait(false);
        if (credentials is null)
        {
            return null;
        }

        return VerifyPassword(password, credentials.PasswordHash) ? credentials.User : null;
    }

    public string HashPassword(string password) => _passwordHasher.Hash(password);

    public bool VerifyPassword(string password, string passwordHash) =>
        _passwordHasher.Verify(password, passwordHash);
}
