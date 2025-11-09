CREATE TABLE Users (
    UserID INT PRIMARY KEY AUTO_INCREMENT,
    Username VARCHAR(100) NOT NULL UNIQUE,
    Email VARCHAR(100) NOT NULL UNIQUE,
    PasswordHash VARCHAR(200) NOT NULL,
    CreatedAt DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE UserRoles (
    UserRoleID INT PRIMARY KEY AUTO_INCREMENT,
    UserID INT NOT NULL,
    RoleName VARCHAR(50) NOT NULL,
    CONSTRAINT FK_UserRoles_Users FOREIGN KEY (UserID) REFERENCES Users(UserID),
    CONSTRAINT UQ_UserRoles UNIQUE (UserID, RoleName)
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

-- Select distinct roles for a user.
SELECT
    RoleName
FROM UserRoles
WHERE UserID = @UserID
ORDER BY RoleName;

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

-- Idempotent role assignment that prevents duplicates.
INSERT INTO UserRoles (UserID, RoleName)
SELECT @UserID, @RoleName
WHERE NOT EXISTS (
    SELECT 1 FROM UserRoles WHERE UserID = @UserID AND RoleName = @RoleName
);
