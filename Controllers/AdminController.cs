// Controllers/AdminController.cs
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SafeVault.Helpers;
using SafeVault.Services;

namespace SafeVault.Controllers;

[ApiController]
[Route("api/admin")]
[Authorize(Roles = RoleNames.Admin)]
public sealed class AdminController : ControllerBase
{
    private readonly IRoleAuthorizationService _roleAuthorizationService;

    public AdminController(IRoleAuthorizationService roleAuthorizationService)
    {
        _roleAuthorizationService = roleAuthorizationService;
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
    public IActionResult GetDashboardAsync()
    {
        var username = User.Identity?.Name ?? "admin";
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

    [HttpGet("login-and-access")]
    public IActionResult LoginAndAccess()
    {
        return Ok(
            new
            {
                message = "Authenticated with admin access.",
                userId = User.FindFirstValue(ClaimTypes.NameIdentifier),
                username = User.Identity?.Name,
                email = User.FindFirstValue(ClaimTypes.Email),
            }
        );
    }
}

public sealed record AssignRoleRequest(string Username, string Role);
