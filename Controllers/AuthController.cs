// Controllers/AuthController.cs
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SafeVault.Services;

namespace SafeVault.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private readonly IUserAuthenticationService _authenticationService;
    private readonly IRoleAuthorizationService _roleAuthorizationService;
    private readonly ITokenService _tokenService;

    public AuthController(
        IUserAuthenticationService authenticationService,
        IRoleAuthorizationService roleAuthorizationService,
        ITokenService tokenService
    )
    {
        _authenticationService = authenticationService;
        _roleAuthorizationService = roleAuthorizationService;
        _tokenService = tokenService;
    }

    [AllowAnonymous]
    [HttpPost("login")]
    public async Task<IActionResult> LoginAsync(
        [FromBody] LoginRequest? request,
        CancellationToken cancellationToken
    )
    {
        if (
            request is null
            || string.IsNullOrWhiteSpace(request.Username)
            || string.IsNullOrWhiteSpace(request.Password)
        )
        {
            return BadRequest(
                new { error = "Username and password are required for authentication." }
            );
        }

        var user = await _authenticationService
            .AuthenticateAsync(request.Username, request.Password, cancellationToken)
            .ConfigureAwait(false);
        if (user is null)
        {
            return Unauthorized(new { error = "Invalid username or password." });
        }

        var userRecord = user.Value;

        var roles = await _roleAuthorizationService
            .GetRolesAsync(userRecord.Username, cancellationToken)
            .ConfigureAwait(false);

        var token = _tokenService.GenerateToken(userRecord, roles);

        return Ok(
            new
            {
                message = "Login successful.",
                token = token.Token,
                expiresAt = token.ExpiresAt,
                user = new
                {
                    userRecord.UserId,
                    userRecord.Username,
                    userRecord.Email,
                    roles,
                },
            }
        );
    }
}

public sealed record LoginRequest(string Username, string Password);
