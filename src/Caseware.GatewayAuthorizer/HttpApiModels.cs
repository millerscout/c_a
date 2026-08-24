using System.Text.Json.Serialization;
using Caseware.Authz;

namespace Caseware.GatewayAuthorizer;

public sealed class AuthorizerRequest
{
    [JsonPropertyName("headers")]
    public Dictionary<string, string>? Headers { get; set; }

    public string AuthorizationHeader()
    {
        if (Headers is null)
        {
            return "";
        }

        foreach (var pair in Headers)
        {
            if (pair.Key.Equals("authorization", StringComparison.OrdinalIgnoreCase))
            {
                return pair.Value;
            }
        }

        return "";
    }
}

public sealed class AuthorizerResponse
{
    [JsonPropertyName("isAuthorized")]
    public bool IsAuthorized { get; init; }

    [JsonPropertyName("context")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Dictionary<string, string>? Context { get; init; }

    public static AuthorizerResponse From(in AuthzDecision decision)
    {
        if (!decision.IsAuthorized)
        {
            return new AuthorizerResponse { IsAuthorized = false };
        }

        return new AuthorizerResponse
        {
            IsAuthorized = true,
            Context = new Dictionary<string, string>(3)
            {
                ["sub"] = decision.Sub ?? "",
                ["azp"] = decision.Azp ?? "",
                ["roles"] = decision.Roles ?? ""
            }
        };
    }
}

public static class IntegrationMapping
{
    public static bool ShouldForward(in AuthzDecision decision) => decision.IsAuthorized;
}
