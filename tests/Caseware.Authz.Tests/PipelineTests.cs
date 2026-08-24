using System.Security.Cryptography;
using Caseware.Authz.Avp;
using Caseware.Authz.Cache;
using Caseware.Authz.Jwt;
using Caseware.Authz.Roles;
using Caseware.GatewayAuthorizer;

namespace Caseware.Authz.Tests;

public sealed class AuthorizerPipelineTests
{
    private static (AuthorizerPipeline Pipeline, InMemoryAuthzCache Cache, RecordingAvpClient Avp, RecordingAuditSink Audit)
        Create(RSA rsa, string kid = "k1", Func<string, string, AvpSnapshot>? avp = null)
    {
        var jwks = new JwksKeyCache(new ScriptJwksClient());
        jwks.Load(JwtTokenFactory.JwksJson(rsa, kid));
        var verifier = new JwtVerifier(jwks, JwtTokenFactory.Issuer);
        var cache = new InMemoryAuthzCache();
        var avpClient = new RecordingAvpClient(avp);
        var audit = new RecordingAuditSink();
        var pipeline = new AuthorizerPipeline(verifier, cache, avpClient, audit);
        return (pipeline, cache, avpClient, audit);
    }

    [Fact]
    public async Task Cache_hit_injects_roles_without_calling_avp()
    {
        using var rsa = JwtTokenFactory.CreateRsa();
        var (pipeline, cache, avp, _) = Create(rsa);
        var jwt = JwtTokenFactory.Token(rsa, "k1", jti: "hit-1");
        await cache.SetAllowAsync("hit-1", "firm_admin,workspace_contributor", TimeSpan.FromMinutes(5), CancellationToken.None);

        var decision = await pipeline.AuthorizeAsync("Bearer " + jwt, CancellationToken.None);

        Assert.True(decision.IsAuthorized);
        Assert.Equal("firm_admin,workspace_contributor", decision.Roles);
        Assert.Equal("user-1", decision.Sub);
        Assert.Equal("client-app", decision.Azp);
        Assert.Equal(0, avp.InvocationCount);
        Assert.Equal(1, cache.GetCalls);
    }

    [Fact]
    public async Task Cache_miss_allow_writes_snapshot_and_returns_roles()
    {
        using var rsa = JwtTokenFactory.CreateRsa();
        var (pipeline, cache, avp, _) = Create(rsa, avp: (_, _) => new AvpSnapshot(true, "firm_admin"));
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var jwt = JwtTokenFactory.Token(rsa, "k1", jti: "miss-1", exp: now + 90);

        var decision = await pipeline.AuthorizeAsync("Bearer " + jwt, CancellationToken.None);

        Assert.True(decision.IsAuthorized);
        Assert.Equal("firm_admin", decision.Roles);
        Assert.Equal(1, avp.InvocationCount);
        Assert.True(cache.HasAllow("miss-1"));
        var ttl = cache.RemainingTtl("miss-1");
        Assert.NotNull(ttl);
        Assert.InRange(ttl!.Value.TotalSeconds, 89, 91);
    }

    [Fact]
    public async Task Avp_deny_does_not_cache_allow()
    {
        using var rsa = JwtTokenFactory.CreateRsa();
        var (pipeline, cache, _, _) = Create(rsa, avp: (_, _) => new AvpSnapshot(false, ""));
        var jwt = JwtTokenFactory.Token(rsa, "k1", jti: "deny-1");

        var decision = await pipeline.AuthorizeAsync("Bearer " + jwt, CancellationToken.None);

        Assert.False(decision.IsAuthorized);
        Assert.False(cache.HasAllow("deny-1"));
    }

    [Fact]
    public async Task Deny_sentinel_blocks_without_avp()
    {
        using var rsa = JwtTokenFactory.CreateRsa();
        var (pipeline, _, avp, _) = Create(rsa);
        var jwt = JwtTokenFactory.Token(rsa, "k1", jti: "revoked-1");
        await pipeline.RevokeWithSentinelAsync("revoked-1", TimeSpan.FromMinutes(5), CancellationToken.None);

        var decision = await pipeline.AuthorizeAsync("Bearer " + jwt, CancellationToken.None);

        Assert.False(decision.IsAuthorized);
        Assert.Equal(0, avp.InvocationCount);
        Assert.False(IntegrationMapping.ShouldForward(decision));
    }

    [Fact]
    public async Task Delete_without_sentinel_would_rehydrate_from_avp()
    {
        using var rsa = JwtTokenFactory.CreateRsa();
        var (pipeline, cache, avp, _) = Create(rsa, avp: (_, _) => new AvpSnapshot(true, "stale_admin"));
        var jwt = JwtTokenFactory.Token(rsa, "k1", jti: "del-1");
        await cache.SetAllowAsync("del-1", "old_role", TimeSpan.FromMinutes(5), CancellationToken.None);
        await cache.DeleteAsync("del-1", CancellationToken.None);

        var decision = await pipeline.AuthorizeAsync("Bearer " + jwt, CancellationToken.None);

        Assert.True(decision.IsAuthorized);
        Assert.Equal("stale_admin", decision.Roles);
        Assert.Equal(1, avp.InvocationCount);
    }

    [Fact]
    public async Task Jwt_failure_never_calls_redis_or_avp()
    {
        using var rsa = JwtTokenFactory.CreateRsa();
        var (pipeline, cache, avp, audit) = Create(rsa);
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var jwt = JwtTokenFactory.Token(rsa, "k1", exp: now - 40, nbf: now - 200);

        var decision = await pipeline.AuthorizeAsync("Bearer " + jwt, CancellationToken.None);

        Assert.False(decision.IsAuthorized);
        Assert.Equal(0, cache.GetCalls);
        Assert.Equal(0, avp.InvocationCount);
        Assert.Contains(audit.Records, r => !r.Allowed && r.Sub == "user-1");
        var response = AuthorizerResponse.From(decision);
        Assert.False(response.IsAuthorized);
        Assert.Null(response.Context);
    }

    [Fact]
    public async Task End_to_end_hit_miss_deny_expired_and_revoked()
    {
        using var rsa = JwtTokenFactory.CreateRsa();
        var (pipeline, _, _, _) = Create(rsa, avp: (_, _) => new AvpSnapshot(true, "workspace_contributor"));
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        var miss = await pipeline.AuthorizeAsync("Bearer " + JwtTokenFactory.Token(rsa, "k1", jti: "e2e-miss"), CancellationToken.None);
        Assert.True(miss.IsAuthorized);

        var hit = await pipeline.AuthorizeAsync("Bearer " + JwtTokenFactory.Token(rsa, "k1", jti: "e2e-miss"), CancellationToken.None);
        Assert.True(hit.IsAuthorized);
        Assert.Equal("workspace_contributor", hit.Roles);

        var denyPipe = Create(rsa, avp: (_, _) => new AvpSnapshot(false, "")).Pipeline;
        var denied = await denyPipe.AuthorizeAsync("Bearer " + JwtTokenFactory.Token(rsa, "k1", jti: "e2e-deny"), CancellationToken.None);
        Assert.False(denied.IsAuthorized);

        var expired = await pipeline.AuthorizeAsync(
            "Bearer " + JwtTokenFactory.Token(rsa, "k1", jti: "e2e-exp", exp: now - 20, nbf: now - 100),
            CancellationToken.None);
        Assert.False(expired.IsAuthorized);

        await pipeline.RevokeWithSentinelAsync("e2e-rev", TimeSpan.FromMinutes(1), CancellationToken.None);
        var revoked = await pipeline.AuthorizeAsync("Bearer " + JwtTokenFactory.Token(rsa, "k1", jti: "e2e-rev"), CancellationToken.None);
        Assert.False(revoked.IsAuthorized);
        Assert.False(IntegrationMapping.ShouldForward(revoked));
        Assert.True(IntegrationMapping.ShouldForward(hit));
    }

    [Fact]
    public async Task Update_roles_writes_avp_before_redis_delete()
    {
        var cache = new InMemoryAuthzCache();
        await cache.SetAllowAsync("jti-a", "old", TimeSpan.FromMinutes(5), CancellationToken.None);
        var writer = new OrderTrackingAvpWriter(cache);
        var service = new UpdateRolesService(writer, cache);

        await service.ApplyAsync(new RoleChangeRequest { AffectedJtis = ["jti-a"] }, CancellationToken.None);

        Assert.Equal(1, writer.ApplyCalls);
        Assert.Equal(["avp"], writer.Events);
        var after = await cache.GetAsync("jti-a", CancellationToken.None);
        Assert.Equal(CacheOutcome.Miss, after.Outcome);
    }

    [Fact]
    public async Task After_update_roles_next_request_hydrates_new_roles()
    {
        using var rsa = JwtTokenFactory.CreateRsa();
        var roles = "old_role";
        var (pipeline, cache, _, _) = Create(rsa, avp: (_, _) => new AvpSnapshot(true, roles));
        var jwt = JwtTokenFactory.Token(rsa, "k1", jti: "rotate-1");
        await pipeline.AuthorizeAsync("Bearer " + jwt, CancellationToken.None);
        Assert.True(cache.HasAllow("rotate-1"));

        roles = "new_role";
        var writer = new CountingAvpWriter();
        var updater = new UpdateRolesService(writer, cache);
        await updater.ApplyAsync(new RoleChangeRequest { AffectedJtis = ["rotate-1"] }, CancellationToken.None);

        var started = DateTime.UtcNow;
        var again = await pipeline.AuthorizeAsync("Bearer " + jwt, CancellationToken.None);
        Assert.True(DateTime.UtcNow - started < TimeSpan.FromSeconds(1));
        Assert.Equal("new_role", again.Roles);
        Assert.Equal(1, writer.ApplyCalls);
    }
}

file sealed class CountingAvpWriter : IAvpPolicyWriter
{
    public int ApplyCalls { get; private set; }

    public ValueTask ApplyRoleChangesAsync(RoleChangeRequest request, CancellationToken cancellationToken)
    {
        ApplyCalls++;
        return ValueTask.CompletedTask;
    }
}
