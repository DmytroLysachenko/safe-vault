CREATE TABLE Users (
    UserID INT PRIMARY KEY AUTO_INCREMENT,
    Username VARCHAR(100) NOT NULL UNIQUE,
    Email VARCHAR(100) NOT NULL UNIQUE,
    PasswordHash VARCHAR(200) NOT NULL,
    CreatedAt DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Parameterized select for login verification.
-- Application code supplies @Username to retrieve the stored hash.
SELECT
    UserID,
    Username,
    Email,
    CreatedAt,
    PasswordHash
FROM Users
WHERE Username = @Username;

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
-- @PasswordHash should contain a bcrypt/Argon2 hash string.
INSERT INTO Users (Username, Email, PasswordHash)
VALUES (@Username, @Email, @PasswordHash);
