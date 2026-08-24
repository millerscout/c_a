using Caseware.Authz;
using Caseware.Authz.Cache;

namespace Caseware.Authz.Tests;

public sealed class ConfigurationTests
{
    [Fact]
    public void Loads_redis_and_cognito_settings_from_appsettings()
    {
        var path = Path.Combine(Path.GetTempPath(), "authz-settings-" + Guid.NewGuid().ToString("N") + ".json");
        File.WriteAllText(path,
            "{" +
            "\"REDIS_ENDPOINT\":\"localhost:6379\"," +
            $"\"COGNITO_ISSUER\":\"{JwtTokenFactory.Issuer}\"," +
            "\"COGNITO_JWKS_URL\":\"https://example/.well-known/jwks.json\"," +
            "\"AVP_POLICY_STORE_ID\":\"ps-1\"," +
            "\"ROLE_CATALOG\":\"firm_admin,workspace_contributor\"" +
            "}");
        try
        {
            var options = AuthorizerOptions.FromEnvironmentAndFile(path);
            Assert.Equal("localhost:6379", options.RedisEndpoint);
            Assert.Equal(JwtTokenFactory.Issuer, options.CognitoIssuer);
            Assert.Equal("ps-1", options.AvpPolicyStoreId);
            Assert.Equal(["firm_admin", "workspace_contributor"], options.RoleCatalog);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Loads_compose_endpoint_from_shipped_appsettings()
    {
        var path = FindRepoFile(Path.Combine("src", "Caseware.GatewayAuthorizer", "appsettings.json"));
        var options = AuthorizerOptions.FromEnvironmentAndFile(path);
        Assert.Equal("localhost:6379", options.RedisEndpoint);
        Assert.False(options.RedisUseTls);
        Assert.Contains("cognito-idp", options.CognitoIssuer);
        Assert.True(options.RoleCatalog.Length >= 1);
    }

    private static string FindRepoFile(string relative)
    {
        var dir = AppContext.BaseDirectory;
        for (var i = 0; i < 10; i++)
        {
            var candidate = Path.Combine(dir, relative);
            if (File.Exists(candidate))
            {
                return candidate;
            }

            dir = Directory.GetParent(dir)?.FullName ?? dir;
        }

        throw new FileNotFoundException(relative);
    }
}

public sealed class RedisCacheTests
{
    [Fact]
    public async Task Round_trip_allow_snapshot_against_local_redis()
    {
        await using var cache = RedisAuthzCache.Connect("localhost:6379");
        var pong = await cache.PingAsync(CancellationToken.None);
        Assert.Equal("PONG", pong);
        var jti = "itest-" + Guid.NewGuid().ToString("N");
        await cache.SetAllowAsync(jti, "firm_admin", TimeSpan.FromSeconds(30), CancellationToken.None);
        var hit = await cache.GetAsync(jti, CancellationToken.None);
        Assert.Equal(CacheOutcome.Allow, hit.Outcome);
        Assert.Equal("firm_admin", hit.Roles);
        var ttl = await cache.PttlMillisecondsAsync(jti, CancellationToken.None);
        Assert.InRange(ttl, 25_000, 30_000);
        await cache.DeleteAsync(jti, CancellationToken.None);
        var miss = await cache.GetAsync(jti, CancellationToken.None);
        Assert.Equal(CacheOutcome.Miss, miss.Outcome);
    }
}
