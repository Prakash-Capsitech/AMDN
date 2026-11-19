using System.Diagnostics;
using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Xunit;

namespace AMDN.Harness.Tests;

// A fresh WebDriver session, never a user's profile. Its NSS database trusts only
// the public test authority; acceptInsecureCerts stays false. No key exports.
internal sealed class FirefoxProbe : IEnrollmentBrowser
{
    private readonly string _profile = Path.Combine(Path.GetTempPath(), "amdn-firefox-" + Guid.NewGuid().ToString("N"));
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(25) };
    private readonly CancellationTokenSource _lifetime = new(TimeSpan.FromSeconds(70));
    private Process? _driver;
    private Task<string>? _errors;
    private Task<string>? _output;
    private string? _session;

    public static async Task<FirefoxProbe> Start(X509Certificate2 certificate)
    {
        var probe = new FirefoxProbe();
        try { await probe.Open(certificate); return probe; }
        catch { await probe.DisposeAsync(); throw; }
    }

    private async Task Open(X509Certificate2 certificate)
    {
        Directory.CreateDirectory(_profile);
        var certFile = Path.Combine(_profile, "fixture.cer");
        await File.WriteAllBytesAsync(certFile, certificate.Export(X509ContentType.Cert));
        var certutil = Environment.GetEnvironmentVariable("AMDN_CERTUTIL") ?? throw new InvalidOperationException("Local NSS test tools are required.");
        await Tool(certutil, "-N", "-d", "sql:" + _profile, "--empty-password");
        await Tool(certutil, "-A", "-d", "sql:" + _profile, "-n", "AMDN disposable fixture", "-t", "C,,", "-i", certFile);
        File.Delete(certFile);
        using var profileBytes = new MemoryStream();
        using (var zip = new ZipArchive(profileBytes, ZipArchiveMode.Create, leaveOpen: true))
            foreach (var file in Directory.GetFiles(_profile)) zip.CreateEntryFromFile(file, Path.GetFileName(file));
        using var portReservation = new TcpListener(IPAddress.Loopback, 0);
        portReservation.Start(); var port = ((IPEndPoint)portReservation.LocalEndpoint).Port; portReservation.Stop();
        _http.BaseAddress = new Uri($"http://127.0.0.1:{port}/");
        var start = new ProcessStartInfo(Environment.GetEnvironmentVariable("GECKODRIVER_BIN") ?? "geckodriver")
        { RedirectStandardError = true, RedirectStandardOutput = true, UseShellExecute = false };
        foreach (var argument in new[] { "--host", "127.0.0.1", "--port", port.ToString(System.Globalization.CultureInfo.InvariantCulture), "--log", "fatal" }) start.ArgumentList.Add(argument);
        _driver = Process.Start(start) ?? throw new InvalidOperationException("Could not start isolated Firefox driver.");
        _errors = _driver.StandardError.ReadToEndAsync(); _output = _driver.StandardOutput.ReadToEndAsync();
        var ready = false;
        for (var attempt = 0; attempt < 100 && !_driver.HasExited; attempt++)
        {
            try { using var response = await _http.GetAsync("status", _lifetime.Token); ready = response.IsSuccessStatusCode; }
            catch (HttpRequestException) { }
            if (ready) break;
            await Task.Delay(100, _lifetime.Token);
        }
        Assert.True(ready, "Isolated Firefox driver did not start.");
        var session = await Request(HttpMethod.Post, "session", new
        {
            capabilities = new
            {
                alwaysMatch = new Dictionary<string, object>
                {
                    ["browserName"] = "firefox",
                    ["acceptInsecureCerts"] = false,
                    ["webauthn:virtualAuthenticators"] = true,
                    ["moz:firefoxOptions"] = new
                    {
                        args = new[] { "-headless" },
                        profile = Convert.ToBase64String(profileBytes.ToArray()),
                        // Firefox's native test-token manager is selected explicitly;
                        // USB hardware is not present in this disposable fixture.
                        prefs = new Dictionary<string, bool>
                        {
                            ["security.webauth.webauthn_enable_softtoken"] = true,
                            ["security.webauth.webauthn_enable_usbtoken"] = false
                        }
                    }
                }
            }
        });
        _session = session.GetProperty("sessionId").GetString();
        Assert.False(session.GetProperty("capabilities").GetProperty("acceptInsecureCerts").GetBoolean());
        await Request(HttpMethod.Post, $"session/{_session}/timeouts", new { script = 20000, pageLoad = 20000 });
    }

    private static async Task Tool(string executable, params string[] arguments)
    {
        var start = new ProcessStartInfo(executable) { RedirectStandardError = true, RedirectStandardOutput = true, UseShellExecute = false };
        foreach (var argument in arguments) start.ArgumentList.Add(argument);
        using var process = Process.Start(start) ?? throw new InvalidOperationException("Could not prepare fixture certificate database.");
        var errors = process.StandardError.ReadToEndAsync(); var output = process.StandardOutput.ReadToEndAsync();
        try { await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10)); }
        finally { if (!process.HasExited) { process.Kill(entireProcessTree: true); await process.WaitForExitAsync(); } }
        await errors; await output;
        Assert.Equal(0, process.ExitCode);
    }

    private async Task<JsonElement> Request(HttpMethod method, string path, object? body = null)
    {
        using var request = new HttpRequestMessage(method, path);
        if (body is not null) request.Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");
        using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, _lifetime.Token);
        response.EnsureSuccessStatusCode();
        await using var stream = await response.Content.ReadAsStreamAsync(_lifetime.Token);
        using var bytes = new MemoryStream(); var buffer = new byte[8192]; int count;
        while ((count = await stream.ReadAsync(buffer, _lifetime.Token)) > 0)
        {
            Assert.True(bytes.Length + count <= 1048576, "Firefox protocol response exceeded test bounds.");
            bytes.Write(buffer, 0, count);
        }
        using var json = JsonDocument.Parse(bytes.ToArray());
        return json.RootElement.GetProperty("value").Clone();
    }

    public async Task<JsonElement> Call(string method, object? parameters = null)
    {
        var args = JsonSerializer.SerializeToElement(parameters);
        if (method == "Page.navigate") return await Request(HttpMethod.Post, $"session/{_session}/url", new { url = args.GetProperty("url").GetString() });
        Assert.Equal("WebAuthn.addVirtualAuthenticator", method);
        var value = await Request(HttpMethod.Post, $"session/{_session}/webauthn/authenticator", new
        { protocol = "ctap2", transport = "usb", hasResidentKey = false, hasUserVerification = true, isUserConsenting = true, isUserVerified = true });
        return JsonSerializer.SerializeToElement(new { authenticatorId = value.GetString() });
    }

    public async Task<JsonElement> Evaluate(string expression)
    {
        // The driver must never log scripts: this payload can contain fixture tokens.
        var result = await Request(HttpMethod.Post, $"session/{_session}/execute/async", new
        {
            script = "const done=arguments[arguments.length-1]; Promise.resolve().then(()=>eval(arguments[0])).then(value=>done({ok:true,value}),()=>done({ok:false}));",
            args = new[] { expression }
        });
        Assert.True(result.GetProperty("ok").GetBoolean(), "Firefox fixture JavaScript failed.");
        return result.GetProperty("value").Clone();
    }

    public async ValueTask DisposeAsync()
    {
        try { if (_session is not null) await Request(HttpMethod.Delete, $"session/{_session}"); }
        catch (HttpRequestException) { }
        catch (TaskCanceledException) { }
        finally
        {
            _lifetime.Cancel();
            if (_driver is not null)
            {
                if (!_driver.HasExited) _driver.Kill(entireProcessTree: true);
                await _driver.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
                if (_errors is not null) await _errors; if (_output is not null) await _output;
                _driver.Dispose();
            }
            _http.Dispose();
            _lifetime.Dispose();
            if (Directory.Exists(_profile)) Directory.Delete(_profile, recursive: true);
        }
    }
}
