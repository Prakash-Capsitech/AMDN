using System.Diagnostics;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using Xunit;

namespace AMDN.Harness.Tests;

// Disposable test browser only. It never attaches to a user's browser/profile,
// exports authenticator keys, disables Chrome's sandbox or trusts arbitrary TLS.
internal interface IEnrollmentBrowser : IAsyncDisposable
{
    Task<JsonElement> Call(string method, object? parameters = null);
    Task<JsonElement> Evaluate(string expression);
}

internal sealed class BrowserProbe : IEnrollmentBrowser
{
    private readonly string _profile = Path.Combine(Path.GetTempPath(), "amdn-browser-" + Guid.NewGuid().ToString("N"));
    private Process? _chrome;
    private readonly ClientWebSocket _socket = new();
    private readonly CancellationTokenSource _lifetime = new(TimeSpan.FromSeconds(70));
    private Task<string>? _errors;
    private Task<string>? _output;
    private int _id;

    public static async Task<BrowserProbe> Start(string certificatePin)
    {
        var probe = new BrowserProbe();
        try { await probe.Open(certificatePin); return probe; }
        catch { await probe.DisposeAsync(); throw; }
    }

    private async Task Open(string pin)
    {
        Directory.CreateDirectory(_profile);
        var start = new ProcessStartInfo(Environment.GetEnvironmentVariable("CHROME_BIN") ?? "google-chrome")
        { RedirectStandardError = true, RedirectStandardOutput = true, UseShellExecute = false };
        foreach (var argument in new[] { "--headless", "--disable-gpu", "--no-first-run", "--disable-background-networking", "--disable-extensions",
            "--remote-debugging-address=127.0.0.1", "--remote-debugging-port=0", "--user-data-dir=" + _profile,
            "--ignore-certificate-errors-spki-list=" + pin, "about:blank" }) start.ArgumentList.Add(argument);
        _chrome = Process.Start(start) ?? throw new InvalidOperationException("Could not start isolated Chrome.");
        _errors = _chrome.StandardError.ReadToEndAsync(); _output = _chrome.StandardOutput.ReadToEndAsync();
        var portFile = Path.Combine(_profile, "DevToolsActivePort");
        var deadline = DateTime.UtcNow.AddSeconds(15);
        while (!File.Exists(portFile))
        {
            if (_chrome.HasExited || DateTime.UtcNow >= deadline) throw new InvalidOperationException("Isolated Chrome did not start; its sandbox must remain enabled.");
            await Task.Delay(50, _lifetime.Token);
        }
        var lines = await File.ReadAllLinesAsync(portFile, _lifetime.Token);
        Assert.True(int.TryParse(lines[0], out var port) && port is > 0 and <= 65535);
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
        using var request = new HttpRequestMessage(HttpMethod.Put, $"http://127.0.0.1:{port}/json/new?about:blank");
        using var response = await http.SendAsync(request, _lifetime.Token);
        response.EnsureSuccessStatusCode();
        using var target = JsonDocument.Parse(await response.Content.ReadAsStringAsync(_lifetime.Token));
        await _socket.ConnectAsync(new Uri(target.RootElement.GetProperty("webSocketDebuggerUrl").GetString()!), _lifetime.Token);
        await Call("Page.enable"); await Call("WebAuthn.enable", new { enableUI = false });
    }

    public async Task<JsonElement> Call(string method, object? parameters = null)
    {
        var number = ++_id;
        var message = JsonSerializer.SerializeToUtf8Bytes(new { id = number, method, @params = parameters ?? new { } });
        await _socket.SendAsync(message.AsMemory(), WebSocketMessageType.Text, true, _lifetime.Token);
        var buffer = new byte[8192];
        while (true)
        {
            using var result = new MemoryStream();
            WebSocketReceiveResult received;
            do
            {
                received = await _socket.ReceiveAsync(buffer, _lifetime.Token);
                Assert.Equal(WebSocketMessageType.Text, received.MessageType);
                Assert.True(result.Length + received.Count <= 1048576, "Browser protocol response exceeded test bounds.");
                result.Write(buffer, 0, received.Count);
            } while (!received.EndOfMessage);
            using var json = JsonDocument.Parse(result.ToArray());
            var value = json.RootElement;
            if (!value.TryGetProperty("id", out var responseId) || responseId.GetInt32() != number) continue;
            Assert.False(value.TryGetProperty("error", out _), "Browser protocol command failed: " + method);
            return value.GetProperty("result").Clone();
        }
    }

    public async Task<JsonElement> Evaluate(string expression)
    {
        var result = await Call("Runtime.evaluate", new { expression, awaitPromise = true, returnByValue = true, userGesture = true });
        Assert.False(result.TryGetProperty("exceptionDetails", out _), "Browser fixture JavaScript failed.");
        return result.GetProperty("result").GetProperty("value").Clone();
    }

    public async ValueTask DisposeAsync()
    {
        _lifetime.Cancel(); _socket.Dispose();
        if (_chrome is not null)
        {
            if (!_chrome.HasExited) _chrome.Kill(entireProcessTree: true);
            await _chrome.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
            if (_errors is not null) await _errors; if (_output is not null) await _output;
            _chrome.Dispose();
        }
        if (Directory.Exists(_profile)) Directory.Delete(_profile, recursive: true);
        _lifetime.Dispose();
    }
}
