using Microsoft.AspNetCore.Http;

namespace AMDN.Identity.Authentication;

public static class IdentityProblem
{
    private static readonly object RequestIdKey = new();

    public static string RequestId(HttpContext context)
    {
        if (context.Items.TryGetValue(RequestIdKey, out var existing)) return (string)existing!;
        var id = Guid.NewGuid().ToString("D");
        context.Items[RequestIdKey] = id;
        context.TraceIdentifier = id;
        return id;
    }

    public static IResult Create(HttpContext context, int status)
    {
        var code = status switch
        {
            400 => "invalid_request",
            401 => "unauthenticated",
            403 => "forbidden",
            404 => "not_found",
            409 => "conflict",
            413 => "payload_too_large",
            415 => "unsupported_media_type",
            429 => "rate_limited",
            503 => "unavailable",
            _ => throw new ArgumentOutOfRangeException(nameof(status))
        };
        if (status is 429 or 503) context.Response.Headers.RetryAfter = status == 429 ? "60" : "5";
        return Results.Problem(type: "about:blank", statusCode: status, title: code,
            extensions: new Dictionary<string, object?> { ["code"] = code, ["request_id"] = RequestId(context) });
    }
}
