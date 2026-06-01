using System.Text.Json;
using Xunit;

namespace SecureEnvelopeKit.Tests;

internal static class TestSupport
{
    public static string ToHex(ReadOnlyMemory<byte> bytes) => Convert.ToHexString(bytes.Span).ToLowerInvariant();

    public static SecureEnvelopeException AssertEnvelopeError(SecureEnvelopeError expected, Action action)
    {
        var exception = Assert.Throws<SecureEnvelopeException>(action);
        Assert.Equal(expected, exception.Error);
        return exception;
    }
}

/// <summary>
/// Loads the shared cross-platform fixture. The repository-root fixture is
/// linked into the test output (see the test .csproj), so it is the single
/// source of truth shared with the Swift and Kotlin tests.
/// </summary>
internal sealed class SecureEnvelopeV1Fixture
{
    private readonly JsonElement _root;

    private SecureEnvelopeV1Fixture(JsonElement root) => _root = root;

    public static SecureEnvelopeV1Fixture Load()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "Fixtures", "secure-envelope-v1.json");
        if (!File.Exists(path))
        {
            throw new FileNotFoundException($"shared fixture not found at {path}");
        }
        using var document = JsonDocument.Parse(File.ReadAllText(path));
        return new SecureEnvelopeV1Fixture(document.RootElement.Clone());
    }

    public string Str(string key) => _root.GetProperty(key).GetString()!;

    public int Int(string key) => _root.GetProperty(key).GetInt32();

    public byte[] Hex(string key) => Convert.FromHexString(Str(key));
}
