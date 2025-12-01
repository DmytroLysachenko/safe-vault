// Services/PasswordHasher.cs
using System;

namespace SafeVault.Services;

public interface IPasswordHasher
{
    string Hash(string password);

    bool Verify(string password, string passwordHash);
}

public sealed class BcryptPasswordHasher : IPasswordHasher
{
    private readonly int _workFactor;

    public BcryptPasswordHasher(int workFactor = 12)
    {
        if (workFactor < 10 || workFactor > 16)
        {
            throw new ArgumentOutOfRangeException(
                nameof(workFactor),
                "Work factor should be between 10 and 16 for balance between security and performance."
            );
        }

        _workFactor = workFactor;
    }

    public string Hash(string password)
    {
        // BCrypt with tunable work factor protects against brute force.
        if (string.IsNullOrWhiteSpace(password))
        {
            throw new ArgumentException("Password cannot be empty.", nameof(password));
        }

        return BCrypt.Net.BCrypt.EnhancedHashPassword(password, _workFactor);
    }

    public bool Verify(string password, string passwordHash)
    {
        if (string.IsNullOrEmpty(passwordHash))
        {
            return false;
        }

        return BCrypt.Net.BCrypt.EnhancedVerify(password, passwordHash);
    }
}
