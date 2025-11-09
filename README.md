# Safe Vault

Hardened ASP.NET Core 9.0 Web API that demonstrates how to collect user input safely, authenticate against a SQL Server backend, and issue JWT access tokens for role-based administration flows. It ships with a static `webform.html`, multi-format submission endpoint, and NUnit-based regression tests for the critical services.

## Highlights
- JWT authentication with short-lived tokens, issuer/audience validation, and role claims enforced by policy-based authorization.
- Parameterized SQL access layer (`SecureUserRepository`) plus bcrypt hashing via `BCrypt.Net-Next` to keep credentials safe at rest.
- Aggressive input sanitization on both the HTML form and API (`InputSanitizer`, `UserSubmissionService`) to block XSS / SQLi payloads.
- Admin workflows protected by the `admin` role: assign roles, inspect dashboards, and verify access via `/api/admin/*`.
- Helpful developer tooling: Swagger UI during development, `safe-vault.http` request collection, and NUnit tests in `safe-vault.Tests`.

## Project Layout
```
safe-vault/
|- Controllers/          # Auth, admin, and form endpoints
|- Services/             # Auth, role, token, repository, hashing, submission logic
|- Helpers/              # JwtOptions + RoleNames constants
|- Utils/                # Input sanitization helpers shared by API & tests
|- Tests/                # NUnit test suite with fakes
|- webform.html          # Static form served from GET /
|- database.sql          # Reference schema & seed queries
|- appsettings*.json     # Environment-specific config (connection string, JWT)
|- safe-vault.sln        # API + test projects
```

## Prerequisites
- [.NET SDK 9.0](https://dotnet.microsoft.com/download) (builds the API) and .NET 8.0 support for the test project.
- SQL Server 2019+ (localdb or full instance). The repository uses `Microsoft.Data.SqlClient`.
- Powershell or Bash shell for running CLI commands.
- Optional: [Visual Studio Code REST Client](https://marketplace.visualstudio.com/items?itemName=humao.rest-client) to execute `safe-vault.http`.

## 1. Restore dependencies
```powershell
dotnet restore safe-vault.sln
```

## 2. Configure the database
1. Create a database (default name `safe-vault`).
2. Run `database.sql` against that database to create `Users` and `UserRoles` tables.
3. Seed at least one account. Passwords **must** be bcrypt hashes produced with the same work factor (12 by default). You can generate one from a short C# script:

```powershell
dotnet script -e "Console.WriteLine(BCrypt.Net.BCrypt.EnhancedHashPassword(\"P@ssw0rd!\", 12));"
```

Then insert the record:
```sql
INSERT INTO Users (Username, Email, PasswordHash)
VALUES ('admin', 'admin@example.com', '<hash from step above>');
```

Add roles as needed:
```sql
INSERT INTO UserRoles (UserID, RoleName)
VALUES (1, 'admin');
```

*If you prefer not to install `dotnet-script`, open a temporary console project, reference `BCrypt.Net-Next`, and `Console.WriteLine` the hash via `UserAuthenticationService.HashPassword`.*

## 3. Configure application settings
Update `appsettings.Development.json` (local) or supply environment variables for production:

| Setting | Description |
| --- | --- |
| `ConnectionStrings:DefaultConnection` | SQL Server connection string. In production set `ConnectionStrings__DefaultConnection` env var. |
| `Jwt:Issuer` / `Jwt:Audience` | Values the token service embeds and the JWT middleware validates. |
| `Jwt:SigningKey` | Long, random secret used for HMAC signing. Override via `Jwt__SigningKey` env var or [Secret Manager](https://learn.microsoft.com/aspnet/core/security/app-secrets). |
| `Jwt:AccessTokenMinutes` | Token lifetime. Defaults to 60 minutes (120 in Development). |

> Never commit production secrets. Use `dotnet user-secrets`, Azure Key Vault, or equivalent secret stores when hosting the API.

## 4. Run the API
```powershell
dotnet run --project safe-vault.csproj --configuration Debug
```

The `Properties/launchSettings.json` profile exposes the app at:
- `https://localhost:7089` (HTTPS)
- `http://localhost:5181` (HTTP)

When `ASPNETCORE_ENVIRONMENT=Development`, Swagger UI is available at `/swagger`.

For hot reload during development:
```powershell
dotnet watch --project safe-vault.csproj run
```

## 5. Use the endpoints
### Public form
- `GET /` - returns `webform.html` with client-side sanitization.
- `POST /submit` - accepts `application/json`, `multipart/form-data`, or URL-encoded form submissions. Responses echo sanitized username and email.

### Authentication
- `POST /api/auth/login` - body `{ "username": "", "password": "" }`. Returns JWT plus user info. Requires credentials that exist in the database.

### Admin (JWT + `admin` role required)
- `GET /api/admin/dashboard` - simple welcome payload.
- `POST /api/admin/assign-role` - `{ "username": "", "role": "" }` adds a role if it does not already exist.
- `GET /api/admin/roles/{username}` - lists assigned roles.
- `GET /api/admin/login-and-access` - echoes claims to help troubleshoot authentication.

Attach tokens to protected calls:
```
Authorization: Bearer <token>
```

The `safe-vault.http` file contains ready-to-run requests; update credentials/token before executing them from VS Code or Rider.

## Testing
Unit tests live in `safe-vault.Tests` (NUnit). Run them from the solution root:
```powershell
dotnet test safe-vault.sln
```

Artifacts land in `bin/safe-vault.Tests` (see `Directory.Build.props`). Target framework is `net8.0`, so ensure your SDK supports multi-targeting when running on CI.

## Deployment tips
- Use `dotnet publish -c Release` for production builds (`artifacts/` is ignored by git and safe to use as the publish directory).
- Override config via environment variables and set `ASPNETCORE_ENVIRONMENT=Production` to disable Swagger and enable HSTS.
- Host SQL Server behind a VNet / private endpoint. The repository already parameterizes all queries; keep enforcing least privilege at the DB level.
- Rotate the JWT signing key periodically; doing so invalidates outstanding tokens by design.

## Troubleshooting
- **`InvalidOperationException: JWT signing key is not configured.`** - set `Jwt__SigningKey` or update `appsettings*.json`.
- **Database connectivity errors** - confirm SQL Server is reachable and the connection string sets `Encrypt=False` only for local dev. Always use TLS with trusted certificates in hosted environments.
- **403 on admin endpoints** - ensure the calling user has the `admin` role. Use `GET /api/admin/roles/{username}` or inspect the JWT payload.

## Contributing
1. Fork / branch.
2. Run `dotnet format` (if installed) and `dotnet test` before opening a PR.
3. Document new endpoints or configuration changes in this README.

With the steps above you can stand up Safe Vault locally, exercise the form and admin APIs, and extend the project with your own secure workflows.
