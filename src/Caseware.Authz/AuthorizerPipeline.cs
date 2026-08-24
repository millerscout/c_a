using Caseware.Authz.Avp;
using Caseware.Authz.Cache;
using Caseware.Authz.Jwt;

namespace Caseware.Authz;

public readonly struct AuthzDecision
{
    public AuthzDecision(bool isAuthorized, string? sub, string? azp, string? roles, JwtVerifyStatus jwtStatus)
    {
        IsAuthorized = isAuthorized;
        Sub = sub;
        Azp = azp;
        Roles = roles;
        JwtStatus = jwtStatus;
    }

    public bool IsAuthorized { get; }
    public string? Sub { get; }
    public string? Azp { get; }
    public string? Roles { get; }
    public JwtVerifyStatus JwtStatus { get; }
}

public readonly struct AuditRecord
{
    public AuditRecord(bool allowed, string? sub, string? azp)
    {
        Allowed = allowed;
        Sub = sub;
        Azp = azp;
    }

    public bool Allowed { get; }
    public string? Sub { get; }
    public string? Azp { get; }
}

public interface IAuditSink
{
    void Write(in AuditRecord record);
}

public sealed class RecordingAuditSink : IAuditSink
{
    private readonly List<AuditRecord> _records = [];

    public IReadOnlyList<AuditRecord> Records => _records;

    public void Write(in AuditRecord record) => _records.Add(record);
}

public sealed class AuthorizerPipeline
{
    private readonly JwtVerifier _verifier;
    private readonly IAuthzCache _cache;
    private readonly IAvpSnapshotClient _avp;
    private readonly IAuditSink _audit;
    private readonly TimeProvider _clock;

    public AuthorizerPipeline(
        JwtVerifier verifier,
        IAuthzCache cache,
        IAvpSnapshotClient avp,
        IAuditSink audit,
        TimeProvider? clock = null)
    {
        _verifier = verifier;
        _cache = cache;
        _avp = avp;
        _audit = audit;
        _clock = clock ?? TimeProvider.System;
    }

    public async ValueTask<AuthzDecision> AuthorizeAsync(string authorization, CancellationToken cancellationToken)
    {
        var jwt = await _verifier.VerifyAsync(authorization, cancellationToken).ConfigureAwait(false);
        if (!jwt.IsOk)
        {
            var parsedSub = string.IsNullOrEmpty(jwt.Claims.Sub) ? null : jwt.Claims.Sub;
            var parsedAzp = string.IsNullOrEmpty(jwt.Claims.Azp) ? null : jwt.Claims.Azp;
            _audit.Write(new AuditRecord(false, parsedSub, parsedAzp));
            return new AuthzDecision(false, parsedSub, parsedAzp, null, jwt.Status);
        }

        var claims = jwt.Claims;
        CacheLookup lookup;
        try
        {
            lookup = await _cache.GetAsync(claims.Jti, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception)
        {
            _audit.Write(new AuditRecord(false, claims.Sub, claims.Azp));
            return new AuthzDecision(false, claims.Sub, claims.Azp, null, JwtVerifyStatus.Ok);
        }

        if (lookup.Outcome == CacheOutcome.Allow)
        {
            _audit.Write(new AuditRecord(true, claims.Sub, claims.Azp));
            return new AuthzDecision(true, claims.Sub, claims.Azp, lookup.Roles, JwtVerifyStatus.Ok);
        }

        if (lookup.Outcome == CacheOutcome.DenySentinel)
        {
            _audit.Write(new AuditRecord(false, claims.Sub, claims.Azp));
            return new AuthzDecision(false, claims.Sub, claims.Azp, null, JwtVerifyStatus.Ok);
        }

        var snapshot = await _avp.GetSnapshotAsync(claims.Sub, claims.Azp, cancellationToken).ConfigureAwait(false);
        var ttl = Ttl(claims.Exp);
        if (!snapshot.Allowed)
        {
            _audit.Write(new AuditRecord(false, claims.Sub, claims.Azp));
            return new AuthzDecision(false, claims.Sub, claims.Azp, null, JwtVerifyStatus.Ok);
        }

        await _cache.SetAllowAsync(claims.Jti, snapshot.Roles, ttl, cancellationToken).ConfigureAwait(false);
        _audit.Write(new AuditRecord(true, claims.Sub, claims.Azp));
        return new AuthzDecision(true, claims.Sub, claims.Azp, snapshot.Roles, JwtVerifyStatus.Ok);
    }

    public async ValueTask RevokeWithSentinelAsync(string jti, TimeSpan ttl, CancellationToken cancellationToken)
        => await _cache.SetDenySentinelAsync(jti, ttl, cancellationToken).ConfigureAwait(false);

    private TimeSpan Ttl(long exp)
    {
        var remaining = exp - _clock.GetUtcNow().ToUnixTimeSeconds();
        return remaining < 1 ? TimeSpan.FromSeconds(1) : TimeSpan.FromSeconds(remaining);
    }
}
