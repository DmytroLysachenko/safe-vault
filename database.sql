CREATE TABLE Users (
    UserID INT PRIMARY KEY AUTO_INCREMENT,
    Username VARCHAR(100) NOT NULL UNIQUE,
    Email VARCHAR(100) NOT NULL UNIQUE,
    PasswordHash VARBINARY(256) NOT NULL,
    CreatedAt DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Parameterized select for login verification.
-- Application code supplies @Username and @PasswordHash values.
SELECT
    UserID,
    Username,
    Email,
    CreatedAt
FROM Users
WHERE Username = @Username
  AND PasswordHash = @PasswordHash;

-- Parameterized search that safely matches partial usernames.
-- The calling code binds @SearchTerm with surrounding wildcards (e.g. '%term%').
SELECT
    UserID,
    Username,
    Email
FROM Users
WHERE Username LIKE @SearchTerm
ORDER BY Username;

-- Insert new user using named parameters to prevent SQL injection.
INSERT INTO Users (Username, Email, PasswordHash)
VALUES (@Username, @Email, @PasswordHash);
