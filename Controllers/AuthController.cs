// Controllers/AuthController.cs
using Microsoft.AspNetCore.Mvc;
using SafeVault.Services;

namespace SafeVault.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private readonly IUserAuthenticationService _authenticationService;
    private readonly IRoleAuthorizationService _roleAuthorizationService;

    public AuthController(
        IUserAuthenticationService authenticationService,
        IRoleAuthorizationService roleAuthorizationService
    )
    {
        _authenticationService = authenticationService;
        _roleAuthorizationService = roleAuthorizationService;
    }

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

        var roles = await _roleAuthorizationService
            .GetRolesAsync(user.Value.Username, cancellationToken)
            .ConfigureAwait(false);

        return Ok(
            new
            {
                message = "Login successful.",
                user.UserId,
                user.Username,
                user.Email,
                roles,
            }
        );
    }
}

public sealed record LoginRequest(string Username, string Password);
