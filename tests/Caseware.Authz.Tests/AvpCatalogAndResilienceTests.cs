using System.Security.Cryptography;
using Caseware.Authz.Avp;
using Caseware.Authz.Cache;
using Caseware.Authz.Jwt;

namespace Caseware.Authz.Tests;

public sealed class AvpCatalogAndResilienceTests
{
    [Fact]
    public async Task Catalog_snapshot_grants_only_bound_roles_in_catalog()
    {
        using var rsa = JwtTokenFactory.CreateRsa();
        var jwks = new JwksKeyCache(new ScriptJwksClient());
        jwks.Load(JwtTokenFactory.JwksJson(rsa, "k1"));
        var verifier = new JwtVerifier(jwks, JwtTokenFactory.Issuer);
        var cache = new InMemoryAuthzCache();
        var avp = new CatalogAvpSnapshotClient(
            ["firm_admin", "workspace_contributor", "unused_role"],
            BindingAvpRoleEvaluator.Parse("user-1|client-app|firm_admin;user-1|client-app|workspace_contributor"));
        var pipeline = new AuthorizerPipeline(verifier, cache, avp, new RecordingAuditSink());
        var jwt = JwtTokenFactory.Token(rsa, "k1", jti: "cat-1");

        var decision = await pipeline.AuthorizeAsync("Bearer " + jwt, CancellationToken.None);

        Assert.True(decision.IsAuthorized);
        Assert.Equal("firm_admin,workspace_contributor", decision.Roles);
        Assert.True(cache.HasAllow("cat-1"));
        Assert.Equal(1, avp.InvocationCount);
    }

    [Fact]
    public async Task Catalog_snapshot_denies_when_no_bindings_match()
    {
        using var rsa = JwtTokenFactory.CreateRsa();
        var jwks = new JwksKeyCache(new ScriptJwksClient());
        jwks.Load(JwtTokenFactory.JwksJson(rsa, "k1"));
        var verifier = new JwtVerifier(jwks, JwtTokenFactory.Issuer);
        var cache = new InMemoryAuthzCache();
        var avp = new CatalogAvpSnapshotClient(
            ["firm_admin"],
            BindingAvpRoleEvaluator.Parse(""));
        var pipeline = new AuthorizerPipeline(verifier, cache, avp, new RecordingAuditSink());
        var jwt = JwtTokenFactory.Token(rsa, "k1", jti: "cat-deny");

        var decision = await pipeline.AuthorizeAsync("Bearer " + jwt, CancellationToken.None);

        Assert.False(decision.IsAuthorized);
        Assert.False(cache.HasAllow("cat-deny"));
        Assert.Equal(1, avp.InvocationCount);
    }

    [Fact]
    public async Task Redis_outage_fails_closed_without_avp()
    {
        using var rsa = JwtTokenFactory.CreateRsa();
        var jwks = new JwksKeyCache(new ScriptJwksClient());
        jwks.Load(JwtTokenFactory.JwksJson(rsa, "k1"));
        var verifier = new JwtVerifier(jwks, JwtTokenFactory.Issuer);
        var cache = new ThrowingAuthzCache();
        var avp = new RecordingAvpClient((_, _) => new AvpSnapshot(true, "firm_admin"));
        var audit = new RecordingAuditSink();
        var pipeline = new AuthorizerPipeline(verifier, cache, avp, audit);
        var jwt = JwtTokenFactory.Token(rsa, "k1", jti: "down-1");

        var decision = await pipeline.AuthorizeAsync("Bearer " + jwt, CancellationToken.None);

        Assert.False(decision.IsAuthorized);
        Assert.Equal(0, avp.InvocationCount);
        Assert.Equal(1, cache.GetCalls);
        Assert.Contains(audit.Records, r => !r.Allowed && r.Sub == "user-1");
    }

    [Fact]
    public async Task Unknown_issuer_never_calls_redis_or_avp()
    {
        using var rsa = JwtTokenFactory.CreateRsa();
        var jwks = new JwksKeyCache(new ScriptJwksClient());
        jwks.Load(JwtTokenFactory.JwksJson(rsa, "k1"));
        var verifier = new JwtVerifier(jwks, JwtTokenFactory.Issuer);
        var cache = new InMemoryAuthzCache();
        var avp = new RecordingAvpClient();
        var pipeline = new AuthorizerPipeline(verifier, cache, avp, new RecordingAuditSink());
        var jwt = JwtTokenFactory.Token(rsa, "k1", jti: "iss-1", iss: "https://evil.example");

        var decision = await pipeline.AuthorizeAsync("Bearer " + jwt, CancellationToken.None);

        Assert.False(decision.IsAuthorized);
        Assert.Equal(0, cache.GetCalls);
        Assert.Equal(0, avp.InvocationCount);
    }
}

file sealed class ThrowingAuthzCache : IAuthzCache
{
    public int GetCalls { get; private set; }
    public int SetCalls { get; private set; }
    public int DeleteCalls { get; private set; }

    public ValueTask<CacheLookup> GetAsync(string jti, CancellationToken cancellationToken)
    {
        GetCalls++;
        throw new IOException("redis unavailable");
    }

    public ValueTask SetAllowAsync(string jti, string roles, TimeSpan ttl, CancellationToken cancellationToken)
    {
        SetCalls++;
        return ValueTask.CompletedTask;
    }

    public ValueTask SetDenySentinelAsync(string jti, TimeSpan ttl, CancellationToken cancellationToken)
    {
        SetCalls++;
        return ValueTask.CompletedTask;
    }

    public ValueTask DeleteAsync(string jti, CancellationToken cancellationToken)
    {
        DeleteCalls++;
        return ValueTask.CompletedTask;
    }
}
