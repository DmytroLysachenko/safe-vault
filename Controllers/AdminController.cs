// Controllers/AdminController.cs
using Microsoft.AspNetCore.Mvc;
using SafeVault.Helpers;
using SafeVault.Services;

namespace SafeVault.Controllers;

[ApiController]
[Route("api/admin")]
public sealed class AdminController : ControllerBase
{
    private readonly IRoleAuthorizationService _roleAuthorizationService;
    private readonly IUserAuthenticationService _authenticationService;

    public AdminController(
        IRoleAuthorizationService roleAuthorizationService,
        IUserAuthenticationService authenticationService
    )
    {
        _roleAuthorizationService = roleAuthorizationService;
        _authenticationService = authenticationService;
    }

    [HttpPost("assign-role")]
    public async Task<IActionResult> AssignRoleAsync(
        [FromBody] AssignRoleRequest? request,
        CancellationToken cancellationToken
    )
    {
        if (
            request is null
            || string.IsNullOrWhiteSpace(request.Username)
            || string.IsNullOrWhiteSpace(request.Role)
        )
        {
            return BadRequest(new { error = "Username and role are required." });
        }

        try
        {
            await _roleAuthorizationService
                .AssignRoleAsync(request.Username, request.Role, cancellationToken)
                .ConfigureAwait(false);
            return Ok(
                new
                {
                    message = $"Role '{request.Role}' assigned to '{request.Username}'.",
                }
            );
        }
        catch (InvalidOperationException ex)
        {
            return NotFound(new { error = ex.Message });
        }
    }

    [HttpGet("dashboard")]
    public async Task<IActionResult> GetDashboardAsync(
        [FromQuery] string? username,
        CancellationToken cancellationToken
    )
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            return BadRequest(new { error = "Username is required to access the dashboard." });
        }

        var isAdmin = await _roleAuthorizationService
            .HasRoleAsync(username, RoleNames.Admin, cancellationToken)
            .ConfigureAwait(false);

        if (!isAdmin)
        {
            return Forbid();
        }

        return Ok(
            new
            {
                message = $"Welcome to the admin dashboard, {username}.",
                sections = new[] { "system-status", "audit-logs", "user-management" },
            }
        );
    }

    [HttpGet("roles/{username}")]
    public async Task<IActionResult> GetRolesAsync(string username, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(username))
        {
            return BadRequest(new { error = "Username is required." });
        }

        var roles = await _roleAuthorizationService
            .GetRolesAsync(username, cancellationToken)
            .ConfigureAwait(false);
        if (roles.Count == 0)
        {
            return NotFound(new { error = $"No roles found for '{username}'." });
        }

        return Ok(new { username, roles });
    }

    [HttpPost("login-and-access")]
    public async Task<IActionResult> LoginAndAccessAsync(
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
            return BadRequest(new { error = "Username and password are required." });
        }

        var user = await _authenticationService
            .AuthenticateAsync(request.Username, request.Password, cancellationToken)
            .ConfigureAwait(false);

        if (user is null)
        {
            return Unauthorized(new { error = "Invalid credentials." });
        }

        var isAdmin = await _roleAuthorizationService
            .HasRoleAsync(user.Value.Username, RoleNames.Admin, cancellationToken)
            .ConfigureAwait(false);

        if (!isAdmin)
        {
            return Forbid();
        }

        return Ok(
            new
            {
                message = "Authenticated with admin access.",
                user.UserId,
                user.Username,
                user.Email,
            }
        );
    }
}

public sealed record AssignRoleRequest(string Username, string Role);
