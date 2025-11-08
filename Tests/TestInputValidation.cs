// Tests/TestInputValidation.cs
using NUnit.Framework;
using SafeVault.Utils;

[TestFixture]
public class TestInputValidation
{
    [TestCase("Robert'); DROP TABLE Students;--", "Robert TABLE Students")]
    [TestCase("1; DELETE FROM Users WHERE '1'='1'", "1 FROM Users WHERE 1=1")]
    [TestCase("Jane'; EXEC xp_cmdshell('dir');--", "Jane xp_cmdshelldir")]
    public void TestForSqlInjectionVectors(string payload, string expected)
    {
        var sanitized = InputSanitizer.Sanitize(payload);

        Assert.AreEqual(expected, sanitized);
        Assert.False(sanitized.Contains("DROP"), "Reserved SQL keywords should be removed.");
        Assert.False(sanitized.Contains("DELETE"), "Data-destroying commands should be removed.");
        Assert.False(sanitized.Contains("EXEC"), "Execution keywords should be removed.");
        Assert.False(sanitized.Contains("--"), "Comment markers should be stripped.");
        Assert.False(sanitized.Contains("'"), "Quotes should be stripped.");
    }

    [TestCase("<script>alert('pwnd')</script>", "scriptalertpwndscript")]
    [TestCase("<<img src=x onerror=alert(1)>", "img src=x onerror=alert1")]
    [TestCase("\"><svg/onload=confirm(document.cookie)>", "svgonload=confirmdocument.cookie")]
    public void TestForXssVectors(string payload, string expected)
    {
        var sanitized = InputSanitizer.Sanitize(payload);

        Assert.AreEqual(expected, sanitized);
        Assert.False(sanitized.Contains("<"));
        Assert.False(sanitized.Contains(">"));
    }

    [TestCase(
        "test@example.com\"><script>alert('x')</script>",
        "test@example.comscriptalertxscript"
    )]
    [TestCase(" attacker@example.com ' OR '1'='1 ", "attacker@example.comOR1=1")]
    public void TestEmailSanitizationBlocksAttacks(string payload, string expectedValue)
    {
        var result = InputSanitizer.SanitizeEmail(payload);

        Assert.IsFalse(result.IsValid, "Email containing malicious payload must be rejected.");
        Assert.AreEqual(expectedValue, result.Value);
        Assert.False(result.Value.Contains("<"));
        Assert.False(result.Value.Contains(">"));
        Assert.False(result.Value.Contains("'"));
    }

    [Test]
    public void TestValidEmailPasses()
    {
        const string validEmail = "secure.user+demo@example.co.uk";
        var result = InputSanitizer.SanitizeEmail(validEmail);

        Assert.IsTrue(result.IsValid);
        Assert.AreEqual(validEmail, result.Value);
    }
}
