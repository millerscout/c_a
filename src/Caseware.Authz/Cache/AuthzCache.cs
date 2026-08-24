namespace Caseware.Authz.Cache;

public enum CacheOutcome : byte
{
    Miss = 0,
    Allow = 1,
    DenySentinel = 2
}

public readonly struct CacheLookup
{
    public CacheLookup(CacheOutcome outcome, string? roles = null)
    {
        Outcome = outcome;
        Roles = roles;
    }

    public CacheOutcome Outcome { get; }
    public string? Roles { get; }
}

public interface IAuthzCache
{
    int GetCalls { get; }
    int SetCalls { get; }
    int DeleteCalls { get; }

    ValueTask<CacheLookup> GetAsync(string jti, CancellationToken cancellationToken);
    ValueTask SetAllowAsync(string jti, string roles, TimeSpan ttl, CancellationToken cancellationToken);
    ValueTask SetDenySentinelAsync(string jti, TimeSpan ttl, CancellationToken cancellationToken);
    ValueTask DeleteAsync(string jti, CancellationToken cancellationToken);
}

public sealed class InMemoryAuthzCache : IAuthzCache
{
    private readonly Dictionary<string, (string Value, DateTimeOffset Expires)> _store = new(StringComparer.Ordinal);
    private readonly TimeProvider _clock;

    public InMemoryAuthzCache(TimeProvider? clock = null)
    {
        _clock = clock ?? TimeProvider.System;
    }

    public int GetCalls { get; private set; }
    public int SetCalls { get; private set; }
    public int DeleteCalls { get; private set; }

    public ValueTask<CacheLookup> GetAsync(string jti, CancellationToken cancellationToken)
    {
        GetCalls++;
        if (!_store.TryGetValue(jti, out var entry) || entry.Expires <= _clock.GetUtcNow())
        {
            _store.Remove(jti);
            return ValueTask.FromResult(new CacheLookup(CacheOutcome.Miss));
        }

        if (entry.Value == AuthorizerOptions.DenySentinelValue)
        {
            return ValueTask.FromResult(new CacheLookup(CacheOutcome.DenySentinel));
        }

        return ValueTask.FromResult(new CacheLookup(CacheOutcome.Allow, entry.Value));
    }

    public ValueTask SetAllowAsync(string jti, string roles, TimeSpan ttl, CancellationToken cancellationToken)
    {
        SetCalls++;
        _store[jti] = (roles, _clock.GetUtcNow() + ttl);
        return ValueTask.CompletedTask;
    }

    public ValueTask SetDenySentinelAsync(string jti, TimeSpan ttl, CancellationToken cancellationToken)
    {
        SetCalls++;
        _store[jti] = (AuthorizerOptions.DenySentinelValue, _clock.GetUtcNow() + ttl);
        return ValueTask.CompletedTask;
    }

    public ValueTask DeleteAsync(string jti, CancellationToken cancellationToken)
    {
        DeleteCalls++;
        _store.Remove(jti);
        return ValueTask.CompletedTask;
    }

    public TimeSpan? RemainingTtl(string jti)
    {
        if (!_store.TryGetValue(jti, out var entry))
        {
            return null;
        }

        var left = entry.Expires - _clock.GetUtcNow();
        return left < TimeSpan.Zero ? TimeSpan.Zero : left;
    }

    public bool HasAllow(string jti)
        => _store.TryGetValue(jti, out var e)
           && e.Expires > _clock.GetUtcNow()
           && e.Value != AuthorizerOptions.DenySentinelValue;
}
