// Services/SecureUserRepository.cs
using System.Data;
using Microsoft.Data.SqlClient;

namespace SafeVault.Services;

public interface ISecureUserRepository
{
    Task<UserRecord?> GetUserByCredentialsAsync(string username, byte[] passwordHash);
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

    public async Task<UserRecord?> GetUserByCredentialsAsync(string username, byte[] passwordHash)
    {
        using var connection = new SqlConnection(_connectionString);
        await connection.OpenAsync().ConfigureAwait(false);

        using var command = new SqlCommand(
            """
            SELECT UserID, Username, Email, CreatedAt
            FROM Users
            WHERE Username = @Username
              AND PasswordHash = @PasswordHash
            """,
            connection
        );

        command.Parameters.Add("@Username", SqlDbType.NVarChar, 100).Value = username;
        command.Parameters.Add("@PasswordHash", SqlDbType.VarBinary, 256).Value = passwordHash;

        using var reader = await command
            .ExecuteReaderAsync(CommandBehavior.SingleRow)
            .ConfigureAwait(false);
        if (await reader.ReadAsync().ConfigureAwait(false))
        {
            return new UserRecord(
                reader.GetInt32(reader.GetOrdinal("UserID")),
                reader.GetString(reader.GetOrdinal("Username")),
                reader.GetString(reader.GetOrdinal("Email")),
                reader.GetDateTime(reader.GetOrdinal("CreatedAt"))
            );
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
