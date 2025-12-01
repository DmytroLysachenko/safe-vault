// Utils/InputSanitizer.cs
using System.Text;
using System.Text.RegularExpressions;

namespace SafeVault.Utils;

public static class InputSanitizer
{
    // Tight regex set strips control chars, markup delimiters, and common SQL/XSS tokens.
    private static readonly Regex ControlChars = new(
        @"[\u0000-\u001F\u007F]",
        RegexOptions.Compiled
    );
    private static readonly Regex TagDelimiters = new(@"[<>]", RegexOptions.Compiled);
    private static readonly Regex QuotesAndSeparators = new(
        @"[""'`;%(){}\[\]\|]",
        RegexOptions.Compiled
    );
    private static readonly Regex SqlMeta = new(@"(--|[#*\\/])", RegexOptions.Compiled);
    private static readonly Regex ReservedSqlKeywords = new(
        @"\b(SELECT|INSERT|DELETE|UPDATE|DROP|ALTER|EXEC|UNION|CREATE)\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled
    );
    private static readonly Regex MultiWhitespace = new(@"\s{2,}", RegexOptions.Compiled);
    private static readonly Regex EmailPattern = new(
        @"^[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled
    );
    private static readonly Regex SuspiciousEmailTokens = new(
        @"(script|onerror|alert|confirm|onload)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled
    );

    public static string Sanitize(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return string.Empty;
        }

        string normalized;
        try
        {
            normalized = input.Normalize(NormalizationForm.FormKC);
        }
        catch (ArgumentException)
        {
            return string.Empty;
        }

        var sanitized = normalized;
        sanitized = ControlChars.Replace(sanitized, string.Empty);
        sanitized = TagDelimiters.Replace(sanitized, string.Empty);
        sanitized = QuotesAndSeparators.Replace(sanitized, string.Empty);
        sanitized = SqlMeta.Replace(sanitized, string.Empty);
        sanitized = ReservedSqlKeywords.Replace(sanitized, string.Empty);
        sanitized = MultiWhitespace.Replace(sanitized, " ");

        return sanitized.Trim();
    }

    public static SanitizedEmailResult SanitizeEmail(string? input)
    {
        var sanitized = Sanitize(input).Replace(" ", string.Empty, StringComparison.Ordinal);
        var isValid =
            sanitized.Length > 0
            && EmailPattern.IsMatch(sanitized)
            && !SuspiciousEmailTokens.IsMatch(sanitized);

        return new SanitizedEmailResult(sanitized, isValid);
    }
}

public readonly record struct SanitizedEmailResult(string Value, bool IsValid);
