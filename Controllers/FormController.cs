// Controllers/FormController.cs
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SafeVault.Services;

namespace SafeVault.Controllers;

[ApiController]
[AllowAnonymous]
[Route("/")]
public class FormController : ControllerBase
{
    // Limit the incoming content types to predictable, validated formats.
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

        // Serve the static HTML form without touching user input.
        return PhysicalFile(formPath, "text/html; charset=utf-8");
    }

    [HttpPost("submit")]
    [Consumes("application/json", "application/x-www-form-urlencoded", "multipart/form-data")]
    public async Task<IActionResult> SubmitAsync()
    {
        var submission = await ReadSubmissionAsync().ConfigureAwait(false);
        if (submission.Submission is null)
        {
            return BadRequest(
                new
                {
                    error = submission.ErrorMessage
                        ?? $"Unsupported content type. Supported types: {string.Join(", ", SupportedContentTypes)}",
                }
            );
        }

        var validationResult = _submissionService.Validate(submission.Submission);
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

    private async Task<SubmissionReadResult> ReadSubmissionAsync()
    {
        if (Request.HasFormContentType)
        {
            var form = await Request.ReadFormAsync().ConfigureAwait(false);
            return SubmissionReadResult.Success(new UserSubmission(form["username"], form["email"]));
        }

        if (
            Request.ContentType?.Contains("application/json", StringComparison.OrdinalIgnoreCase)
            == true
        )
        {
            try
            {
                var body = await Request.ReadFromJsonAsync<UserSubmission>().ConfigureAwait(false);
                return body is null
                    ? SubmissionReadResult.Failure("Request body is missing or empty.")
                    : SubmissionReadResult.Success(body);
            }
            catch (JsonException)
            {
                return SubmissionReadResult.Failure("Malformed JSON payload.");
            }
        }

        return SubmissionReadResult.Failure(
            $"Unsupported content type. Supported types: {string.Join(", ", SupportedContentTypes)}"
        );
    }
}

internal readonly record struct SubmissionReadResult(UserSubmission? Submission, string? ErrorMessage)
{
    public static SubmissionReadResult Success(UserSubmission submission) => new(submission, null);
    public static SubmissionReadResult Failure(string error) => new(null, error);
}
