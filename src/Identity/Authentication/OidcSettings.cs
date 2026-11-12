namespace AMDN.Identity.Authentication;

public sealed class OidcSettings
{
    public const string Section = "Authentication:Oidc";
    public bool Enabled { get; set; }
    public string Issuer { get; set; } = "";
    public string Audience { get; set; } = "";

    internal bool IsValid()
    {
        if (!Enabled) return Issuer.Length == 0 && Audience.Length == 0;
        return Issuer.Length <= 2048 && Issuer == Issuer.Trim() && !Issuer.Any(char.IsControl)
            && Uri.TryCreate(Issuer, UriKind.Absolute, out var uri)
            && uri.Scheme == Uri.UriSchemeHttps && uri.UserInfo.Length == 0
            && uri.Query.Length == 0 && uri.Fragment.Length == 0
            && Audience.Length is > 0 and <= 1024 && Audience == Audience.Trim()
            && !Audience.Any(char.IsControl);
    }
}
