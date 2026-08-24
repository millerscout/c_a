using System.Text.Json;

namespace Caseware.Authz;

public sealed class AuthorizerOptions
{
    public const string DenySentinelValue = "__deny__";
    public const string RedisKeyPrefix = "authz:";

    public string RedisEndpoint { get; init; } = "localhost:6379";
    public bool RedisUseTls { get; init; }
    public string CognitoIssuer { get; init; } = "";
    public string JwksUrl { get; init; } = "";
    public string AvpPolicyStoreId { get; init; } = "";
    public string[] RoleCatalog { get; init; } = [];
    public string AvpRoleBindings { get; init; } = "";

    public static AuthorizerOptions FromEnvironmentAndFile(string? appsettingsPath = null)
    {
        var file = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var path = appsettingsPath ?? Path.Combine(AppContext.BaseDirectory, "appsettings.json");
        if (File.Exists(path))
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            foreach (var prop in doc.RootElement.EnumerateObject())
            {
                if (prop.Value.ValueKind == JsonValueKind.String)
                {
                    file[prop.Name] = prop.Value.GetString() ?? "";
                }
            }
        }

        string Get(params string[] keys)
        {
            foreach (var key in keys)
            {
                var env = Environment.GetEnvironmentVariable(key);
                if (!string.IsNullOrWhiteSpace(env))
                {
                    return env;
                }

                if (file.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value))
                {
                    return value;
                }
            }

            return "";
        }

        var catalog = Get("ROLE_CATALOG");
        var tls = Get("REDIS_USE_TLS");
        return new AuthorizerOptions
        {
            RedisEndpoint = Get("REDIS_ENDPOINT") is { Length: > 0 } r ? r : "localhost:6379",
            RedisUseTls = tls is "1" or "true" or "TRUE" or "yes" or "YES",
            CognitoIssuer = Get("COGNITO_ISSUER"),
            JwksUrl = Get("COGNITO_JWKS_URL"),
            AvpPolicyStoreId = Get("AVP_POLICY_STORE_ID"),
            RoleCatalog = catalog.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries),
            AvpRoleBindings = Get("AVP_ROLE_BINDINGS")
        };
    }
}
