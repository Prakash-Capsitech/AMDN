using System.Globalization;
using System.Security.Claims;
using AMDN.Identity.Membership;
using Microsoft.Extensions.Options;

namespace AMDN.Identity.Authentication;

public sealed class DeviceStepUpSettings
{
    public const string Section = "Authentication:DeviceStepUp";
    public bool Enabled { get; set; }
    public string[] AllowedAcrValues { get; set; } = [];
    public int MaximumAgeSeconds { get; set; }

    internal bool IsValid(bool oidcEnabled) => !Enabled
        ? AllowedAcrValues.Length == 0 && MaximumAgeSeconds == 0
        : oidcEnabled && MaximumAgeSeconds is >= 1 and <= 900
            && AllowedAcrValues.Length is >= 1 and <= 16
            && AllowedAcrValues.All(ValidAcr)
            && AllowedAcrValues.Distinct(StringComparer.Ordinal).Count() == AllowedAcrValues.Length;

    internal static bool ValidAcr(string value) => value.Length is >= 1 and <= 256
        && value.All(character => character is >= (char)0x21 and <= (char)0x7e);
}

// Authentication prerequisite only: this neither proves device-key possession
// nor resolves membership, checks a current grant, or authorizes enrollment.
public sealed class DeviceStepUp(IOptions<DeviceStepUpSettings> configured, TimeProvider clock)
{
    public const string Policy = "AmdnDeviceStepUpPrerequisite";

    public bool SatisfiedBy(ClaimsPrincipal principal)
    {
        var settings = configured.Value;
        if (!settings.Enabled || !IdentityScopes.Has(principal, "device.manage")) return false;
        var acr = principal.FindAll("acr").ToArray();
        var times = principal.FindAll("auth_time").ToArray();
        if (acr.Length != 1 || times.Length != 1
            || !settings.AllowedAcrValues.Contains(acr[0].Value, StringComparer.Ordinal)
            || !long.TryParse(times[0].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var authenticatedAt)) return false;
        var now = clock.GetUtcNow().ToUnixTimeSeconds();
        // No extra lifetime clock skew: token renewal must not refresh this age.
        return authenticatedAt >= 0 && authenticatedAt <= now
            && now - authenticatedAt <= settings.MaximumAgeSeconds;
    }
}
