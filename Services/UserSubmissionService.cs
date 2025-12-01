// Services/UserSubmissionService.cs
using SafeVault.Utils;

namespace SafeVault.Services;

public interface IUserSubmissionService
{
    SubmissionValidationResult Validate(UserSubmission submission);
}

public sealed class UserSubmissionService : IUserSubmissionService
{
    public SubmissionValidationResult Validate(UserSubmission submission)
    {
        // Sanitize incoming fields aggressively before checking basic rules.
        var sanitizedUsername = InputSanitizer.Sanitize(submission.Username);
        if (sanitizedUsername.Length < 3)
        {
            return SubmissionValidationResult.Invalid(
                "Username must be at least 3 characters and cannot include control characters or SQL keywords."
            );
        }

        var emailResult = InputSanitizer.SanitizeEmail(submission.Email);
        if (!emailResult.IsValid)
        {
            return SubmissionValidationResult.Invalid(
                "Provide a valid email address without scripts, whitespace, or SQL tokens."
            );
        }

        return SubmissionValidationResult.Valid(
            new SanitizedSubmission(sanitizedUsername, emailResult.Value)
        );
    }
}

public sealed record UserSubmission(string? Username, string? Email);

public sealed record SanitizedSubmission(string Username, string Email);

public sealed record SubmissionValidationResult
{
    private SubmissionValidationResult(
        bool isValid,
        string errorMessage,
        SanitizedSubmission? sanitized
    )
    {
        IsValid = isValid;
        ErrorMessage = errorMessage;
        Sanitized = sanitized;
    }

    public bool IsValid { get; }
    public string ErrorMessage { get; }
    public SanitizedSubmission? Sanitized { get; }

    public static SubmissionValidationResult Invalid(string errorMessage) =>
        new(false, errorMessage, null);

    public static SubmissionValidationResult Valid(SanitizedSubmission submission) =>
        new(true, string.Empty, submission);
}
