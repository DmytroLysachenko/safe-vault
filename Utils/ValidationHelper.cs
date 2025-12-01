// Utils/ValidationHelper.cs
using System.Data;
using System.Globalization;
using Microsoft.Data.SqlClient;

namespace SafeVault.Utils;

public static class ValidationHelpers
{
    // Quick heuristics for catching obvious XSS markers before DB/network work.
    private static readonly HashSet<string> XssIndicators = new(StringComparer.OrdinalIgnoreCase)
    {
        "<script",
        "<iframe",
        "javascript:",
        "onerror",
        "onload",
    };

    public static bool IsValidInput(string? input, string allowedSpecialCharacters = "")
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return false;
        }

        var permitted = new HashSet<char>(allowedSpecialCharacters ?? string.Empty);
        return input.All(c => char.IsLetterOrDigit(c) || permitted.Contains(c));
    }

    public static bool IsValidXssInput(string? input)
    {
        if (string.IsNullOrEmpty(input))
        {
            return true;
        }

        foreach (var indicator in XssIndicators)
        {
            if (input.IndexOf(indicator, StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return false;
            }
        }

        return true;
    }

    public static bool RunXssDiagnostic()
    {
        const string maliciousInput = "<script>alert('XSS');</script>";
        return !IsValidXssInput(maliciousInput);
    }

    public static bool LoginUser(string username, byte[] passwordHash, string connectionString)
    {
        if (!IsValidInput(username))
        {
            return false;
        }

        if (passwordHash is null || passwordHash.Length == 0)
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(connectionString))
        {
            throw new ArgumentException(
                "Connection string must be provided.",
                nameof(connectionString)
            );
        }

        using var connection = new SqlConnection(connectionString);
        using var command = new SqlCommand(
            "SELECT COUNT(1) FROM Users WHERE Username = @Username AND PasswordHash = @PasswordHash",
            connection
        );

        command.Parameters.Add("@Username", SqlDbType.NVarChar, 100).Value = username;
        command.Parameters.Add("@PasswordHash", SqlDbType.VarBinary, 256).Value = passwordHash;

        connection.Open();
        var scalar = command.ExecuteScalar();
        var count = scalar switch
        {
            int value => value,
            null => 0,
            _ => Convert.ToInt32(scalar, CultureInfo.InvariantCulture),
        };
        return count > 0;
    }
}
