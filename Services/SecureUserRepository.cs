// Services/SecureUserRepository.cs
using System.Collections.Generic;
using System.Data;
using Microsoft.Data.SqlClient;

namespace SafeVault.Services;

public interface ISecureUserRepository
{
    Task<UserCredentials?> GetUserCredentialsAsync(
        string username,
        CancellationToken cancellationToken = default
    );

    Task<DataTable> SearchUsersByUsernameAsync(
        string searchTerm,
        CancellationToken cancellationToken = default
    );

    Task<IReadOnlyCollection<string>> GetUserRolesAsync(
        int userId,
        CancellationToken cancellationToken = default
    );

    Task AssignRoleAsync(int userId, string role, CancellationToken cancellationToken = default);
}

public sealed class SecureUserRepository : ISecureUserRepository
{
    private readonly string _connectionString;

    public SecureUserRepository(string connectionString)
    {
        _connectionString =
            connectionString ?? throw new ArgumentNullException(nameof(connectionString));
    }

    public async Task<UserCredentials?> GetUserCredentialsAsync(
        string username,
        CancellationToken cancellationToken = default
    )
    {
        using var connection = new SqlConnection(_connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);

        // Parameterized query ensures user lookups stay safe from injection.
        using var command = new SqlCommand(
            """
            SELECT UserID, Username, Email, CreatedAt, PasswordHash
            FROM Users
            WHERE Username = @Username
            """,
            connection
        );

        command.Parameters.Add("@Username", SqlDbType.NVarChar, 100).Value = username;

        using var reader = await command
            .ExecuteReaderAsync(CommandBehavior.SingleRow, cancellationToken)
            .ConfigureAwait(false);
        if (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            var user = new UserRecord(
                reader.GetInt32(reader.GetOrdinal("UserID")),
                reader.GetString(reader.GetOrdinal("Username")),
                reader.GetString(reader.GetOrdinal("Email")),
                reader.GetDateTime(reader.GetOrdinal("CreatedAt"))
            );

            var passwordHash = reader.GetString(reader.GetOrdinal("PasswordHash"));
            await reader.CloseAsync().ConfigureAwait(false);
            var roles = await LoadRolesAsync(connection, user.UserId, cancellationToken)
                .ConfigureAwait(false);
            return new UserCredentials(user, passwordHash, roles);
        }

        return null;
    }

    public async Task<DataTable> SearchUsersByUsernameAsync(
        string searchTerm,
        CancellationToken cancellationToken = default
    )
    {
        using var connection = new SqlConnection(_connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);

        using var command = new SqlCommand(
            """
            SELECT UserID, Username, Email
            FROM Users
            WHERE Username LIKE @SearchTerm
            ORDER BY Username
            """,
            connection
        );

        command.Parameters.Add("@SearchTerm", SqlDbType.NVarChar, 100).Value = $"%{searchTerm}%";

        cancellationToken.ThrowIfCancellationRequested();
        using var adapter = new SqlDataAdapter(command);
        var results = new DataTable();
        adapter.Fill(results);
        return results;
    }

    public async Task<IReadOnlyCollection<string>> GetUserRolesAsync(
        int userId,
        CancellationToken cancellationToken = default
    )
    {
        using var connection = new SqlConnection(_connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        return await LoadRolesAsync(connection, userId, cancellationToken).ConfigureAwait(false);
    }

    public async Task AssignRoleAsync(
        int userId,
        string role,
        CancellationToken cancellationToken = default
    )
    {
        var normalizedRole = NormalizeRole(role);
        using var connection = new SqlConnection(_connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);

        using var command = new SqlCommand(
            """
            IF NOT EXISTS (
                SELECT 1
                FROM UserRoles
                WHERE UserID = @UserID AND RoleName = @RoleName
            )
            BEGIN
                INSERT INTO UserRoles (UserID, RoleName)
                VALUES (@UserID, @RoleName);
            END
            """,
            connection
        );

        command.Parameters.Add("@UserID", SqlDbType.Int).Value = userId;
        command.Parameters.Add("@RoleName", SqlDbType.NVarChar, 50).Value = normalizedRole;

        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task<IReadOnlyCollection<string>> LoadRolesAsync(
        SqlConnection connection,
        int userId,
        CancellationToken cancellationToken = default
    )
    {
        using var command = new SqlCommand(
            """
            SELECT RoleName
            FROM UserRoles
            WHERE UserID = @UserID
            ORDER BY RoleName
            """,
            connection
        );

        command.Parameters.Add("@UserID", SqlDbType.Int).Value = userId;

        using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        var roles = new List<string>();
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            roles.Add(reader.GetString(0));
        }

        return roles;
    }

    private static string NormalizeRole(string role)
    {
        if (string.IsNullOrWhiteSpace(role))
        {
            throw new ArgumentException("Role cannot be empty.", nameof(role));
        }

        return role.Trim();
    }
}

public readonly record struct UserRecord(
    int UserId,
    string Username,
    string Email,
    DateTime CreatedAt
);

public sealed record UserCredentials(
    UserRecord User,
    string PasswordHash,
    IReadOnlyCollection<string> Roles
);
