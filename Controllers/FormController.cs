// Controllers/FormController.cs
using Microsoft.AspNetCore.Mvc;
using SafeVault.Services;

namespace SafeVault.Controllers;

[ApiController]
[Route("/")]
public class FormController : ControllerBase
{
    private static readonly string[] SupportedContentTypes =
    {
        "application/json",
        "application/x-www-form-urlencoded",
        "multipart/form-data",
    };

    private readonly IWebHostEnvironment _environment;
    private readonly IUserSubmissionService _submissionService;

    public FormController(IWebHostEnvironment environment, IUserSubmissionService submissionService)
    {
        _environment = environment;
        _submissionService = submissionService;
    }

    [HttpGet]
    public IActionResult GetForm()
    {
        var formPath = Path.Combine(_environment.ContentRootPath, "webform.html");
        if (!System.IO.File.Exists(formPath))
        {
            return NotFound(new { error = "Form file not found." });
        }

        return PhysicalFile(formPath, "text/html; charset=utf-8");
    }

    [HttpPost("submit")]
    [Consumes("application/json", "application/x-www-form-urlencoded", "multipart/form-data")]
    public async Task<IActionResult> SubmitAsync()
    {
        var submission = await ReadSubmissionAsync().ConfigureAwait(false);
        if (submission is null)
        {
            return BadRequest(
                new
                {
                    error = $"Unsupported content type. Supported types: {string.Join(", ", SupportedContentTypes)}",
                }
            );
        }

        var validationResult = _submissionService.Validate(submission);
        if (!validationResult.IsValid || validationResult.Sanitized is null)
        {
            return BadRequest(new { error = validationResult.ErrorMessage });
        }

        return Ok(
            new
            {
                message = "Submission accepted.",
                validationResult.Sanitized.Username,
                validationResult.Sanitized.Email,
            }
        );
    }

    private async Task<UserSubmission?> ReadSubmissionAsync()
    {
        if (Request.HasFormContentType)
        {
            var form = await Request.ReadFormAsync().ConfigureAwait(false);
            return new UserSubmission(form["username"], form["email"]);
        }

        if (
            Request.ContentType?.Contains("application/json", StringComparison.OrdinalIgnoreCase)
            == true
        )
        {
            try
            {
                return await Request.ReadFromJsonAsync<UserSubmission>().ConfigureAwait(false);
            }
            catch (System.Text.Json.JsonException)
            {
                return null;
            }
        }

        return null;
    }
}
