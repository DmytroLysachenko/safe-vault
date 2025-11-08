// Services/SecureUserRepository.cs
using System.Data;
using Microsoft.Data.SqlClient;

namespace SafeVault.Services;

public interface ISecureUserRepository
{
    Task<UserCredentials?> GetUserCredentialsAsync(string username);
    Task<DataTable> SearchUsersByUsernameAsync(string searchTerm);
}

public sealed class SecureUserRepository : ISecureUserRepository
{
    private readonly string _connectionString;

    public SecureUserRepository(string connectionString)
    {
        _connectionString =
            connectionString ?? throw new ArgumentNullException(nameof(connectionString));
    }

    public async Task<UserCredentials?> GetUserCredentialsAsync(string username)
    {
        using var connection = new SqlConnection(_connectionString);
        await connection.OpenAsync().ConfigureAwait(false);

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
            .ExecuteReaderAsync(CommandBehavior.SingleRow)
            .ConfigureAwait(false);
        if (await reader.ReadAsync().ConfigureAwait(false))
        {
            var user = new UserRecord(
                reader.GetInt32(reader.GetOrdinal("UserID")),
                reader.GetString(reader.GetOrdinal("Username")),
                reader.GetString(reader.GetOrdinal("Email")),
                reader.GetDateTime(reader.GetOrdinal("CreatedAt"))
            );

            var passwordHash = reader.GetString(reader.GetOrdinal("PasswordHash"));
            return new UserCredentials(user, passwordHash);
        }

        return null;
    }

    public async Task<DataTable> SearchUsersByUsernameAsync(string searchTerm)
    {
        using var connection = new SqlConnection(_connectionString);
        await connection.OpenAsync().ConfigureAwait(false);

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

        using var adapter = new SqlDataAdapter(command);
        var results = new DataTable();
        adapter.Fill(results);
        return results;
    }
}

public readonly record struct UserRecord(
    int UserId,
    string Username,
    string Email,
    DateTime CreatedAt
);

public sealed record UserCredentials(UserRecord User, string PasswordHash);
