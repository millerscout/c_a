using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.Json;

namespace Caseware.Authz.Jwt;

public interface IJwksClient
{
    Task<string> GetJwksJsonAsync(CancellationToken cancellationToken);
}

public sealed class HttpJwksClient : IJwksClient
{
    private readonly HttpClient _http;
    private readonly string _url;

    public HttpJwksClient(HttpClient http, string url)
    {
        _http = http;
        _url = url;
    }

    public Task<string> GetJwksJsonAsync(CancellationToken cancellationToken)
        => _http.GetStringAsync(_url, cancellationToken);
}

public sealed class JwksKeyCache
{
    private readonly ConcurrentDictionary<string, RSA> _keys = new(StringComparer.Ordinal);
    private readonly IJwksClient _client;
    private readonly SemaphoreSlim _refresh = new(1, 1);

    public JwksKeyCache(IJwksClient client)
    {
        _client = client;
    }

    public int Count => _keys.Count;

    public bool TryGet(string kid, out RSA rsa) => _keys.TryGetValue(kid, out rsa!);

    public async Task RefreshAsync(CancellationToken cancellationToken)
    {
        await _refresh.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var json = await _client.GetJwksJsonAsync(cancellationToken).ConfigureAwait(false);
            Load(json);
        }
        finally
        {
            _refresh.Release();
        }
    }

    public void Load(string jwksJson)
    {
        using var doc = JsonDocument.Parse(jwksJson);
        if (!doc.RootElement.TryGetProperty("keys", out var keys) || keys.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        foreach (var key in keys.EnumerateArray())
        {
            if (!key.TryGetProperty("kty", out var kty) || kty.GetString() != "RSA")
            {
                continue;
            }

            var kid = key.TryGetProperty("kid", out var kidEl) ? kidEl.GetString() : null;
            var n = key.TryGetProperty("n", out var nEl) ? nEl.GetString() : null;
            var e = key.TryGetProperty("e", out var eEl) ? eEl.GetString() : null;
            if (string.IsNullOrEmpty(kid) || string.IsNullOrEmpty(n) || string.IsNullOrEmpty(e))
            {
                continue;
            }

            var rsa = RSA.Create();
            rsa.ImportParameters(new RSAParameters
            {
                Modulus = Base64Url.Decode(n),
                Exponent = Base64Url.Decode(e)
            });
            _keys.AddOrUpdate(kid, rsa, (_, old) =>
            {
                old.Dispose();
                return rsa;
            });
        }
    }
}

public enum JwtVerifyStatus : byte
{
    Ok = 0,
    Malformed = 1,
    MissingBearer = 2,
    Expired = 3,
    NotYetValid = 4,
    BadSignature = 5,
    UnknownIssuer = 6,
    UnknownKid = 7,
    MissingClaims = 8
}

public readonly struct JwtVerifyResult
{
    public JwtVerifyResult(JwtVerifyStatus status, JwtClaims claims = default)
    {
        Status = status;
        Claims = claims;
    }

    public JwtVerifyStatus Status { get; }
    public JwtClaims Claims { get; }
    public bool IsOk => Status == JwtVerifyStatus.Ok;
}

public sealed class JwtVerifier
{
    private readonly JwksKeyCache _cache;
    private readonly string _issuer;
    private readonly TimeProvider _clock;
    private readonly int _clockSkewSeconds;

    public JwtVerifier(JwksKeyCache cache, string issuer, TimeProvider? clock = null, int clockSkewSeconds = 5)
    {
        _cache = cache;
        _issuer = issuer;
        _clock = clock ?? TimeProvider.System;
        _clockSkewSeconds = clockSkewSeconds;
    }

    public async ValueTask<JwtVerifyResult> VerifyAsync(string authorization, CancellationToken cancellationToken)
    {
        if (!Bearer.TryGetToken(authorization, out var tokenSpan))
        {
            return new JwtVerifyResult(JwtVerifyStatus.MissingBearer);
        }

        var token = tokenSpan.ToString();
        if (!JwtParser.TryParseUnverified(token, out var claims, out var signedLength, out var signatureStart))
        {
            return new JwtVerifyResult(JwtVerifyStatus.Malformed);
        }

        if (string.IsNullOrEmpty(claims.Kid) || string.IsNullOrEmpty(claims.Sub) || string.IsNullOrEmpty(claims.Jti))
        {
            return new JwtVerifyResult(JwtVerifyStatus.MissingClaims, claims);
        }

        if (!string.IsNullOrEmpty(_issuer) && !string.Equals(claims.Iss, _issuer, StringComparison.Ordinal))
        {
            return new JwtVerifyResult(JwtVerifyStatus.UnknownIssuer, claims);
        }

        var now = _clock.GetUtcNow().ToUnixTimeSeconds();
        if (claims.Nbf > 0 && now + _clockSkewSeconds < claims.Nbf)
        {
            return new JwtVerifyResult(JwtVerifyStatus.NotYetValid, claims);
        }

        if (now - _clockSkewSeconds >= claims.Exp)
        {
            return new JwtVerifyResult(JwtVerifyStatus.Expired, claims);
        }

        if (!_cache.TryGet(claims.Kid, out _))
        {
            await _cache.RefreshAsync(cancellationToken).ConfigureAwait(false);
        }

        if (!_cache.TryGet(claims.Kid, out var rsa))
        {
            return new JwtVerifyResult(JwtVerifyStatus.UnknownKid, claims);
        }

        var signature = Base64Url.Decode(token.AsSpan(signatureStart));
        if (signature.Length == 0)
        {
            return new JwtVerifyResult(JwtVerifyStatus.BadSignature, claims);
        }

        var signedSpan = token.AsSpan(0, signedLength);
        var signedBytes = new byte[signedSpan.Length];
        System.Text.Encoding.ASCII.GetBytes(signedSpan, signedBytes);
        if (!rsa.VerifyData(signedBytes, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
        {
            return new JwtVerifyResult(JwtVerifyStatus.BadSignature, claims);
        }

        return new JwtVerifyResult(JwtVerifyStatus.Ok, claims);
    }
}
