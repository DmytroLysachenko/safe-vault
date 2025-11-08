// Controllers/AuthController.cs
using Microsoft.AspNetCore.Mvc;
using SafeVault.Services;

namespace SafeVault.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private readonly IUserAuthenticationService _authenticationService;

    public AuthController(IUserAuthenticationService authenticationService)
    {
        _authenticationService = authenticationService;
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

        return Ok(
            new
            {
                message = "Login successful.",
                user.UserId,
                user.Username,
                user.Email,
            }
        );
    }
}

public sealed record LoginRequest(string Username, string Password);
