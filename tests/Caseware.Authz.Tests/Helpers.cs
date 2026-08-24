using System.Security.Cryptography;
using System.Text;
using Caseware.Authz.Cache;
using Caseware.Authz.Jwt;
using Caseware.Authz.Roles;

namespace Caseware.Authz.Tests;

internal static class JwtTokenFactory
{
    public const string Issuer = "https://cognito-idp.us-east-1.amazonaws.com/local_pool";

    public static RSA CreateRsa() => RSA.Create(2048);

    public static string JwksJson(RSA rsa, string kid)
    {
        var p = rsa.ExportParameters(false);
        var n = Base64Url.Encode(p.Modulus!);
        var e = Base64Url.Encode(p.Exponent!);
        return $"{{\"keys\":[{{\"kty\":\"RSA\",\"kid\":\"{kid}\",\"n\":\"{n}\",\"e\":\"{e}\"}}]}}";
    }

    public static string Token(
        RSA rsa,
        string kid,
        string sub = "user-1",
        string azp = "client-app",
        string jti = "jti-1",
        long? nbf = null,
        long? exp = null,
        string? iss = Issuer,
        bool useAzp = true,
        bool tamperPayload = false)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        nbf ??= now - 10;
        exp ??= now + 3600;
        var header = Base64Url.EncodeUtf8($"{{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"{kid}\"}}");
        var party = useAzp ? $"\"azp\":\"{azp}\"" : $"\"client_id\":\"{azp}\"";
        var payloadJson =
            $"{{\"sub\":\"{sub}\",{party},\"jti\":\"{jti}\",\"nbf\":{nbf},\"exp\":{exp},\"iss\":\"{iss}\"}}";
        var payload = Base64Url.EncodeUtf8(payloadJson);
        if (tamperPayload)
        {
            payload = Base64Url.EncodeUtf8(payloadJson.Replace(sub, sub + "x", StringComparison.Ordinal));
        }

        var signed = header + "." + payload;
        var sig = rsa.SignData(Encoding.ASCII.GetBytes(signed), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return signed + "." + Base64Url.Encode(sig);
    }
}

internal sealed class ScriptJwksClient : IJwksClient
{
    private readonly Queue<string> _payloads = new();
    public int FetchCount { get; private set; }

    public ScriptJwksClient(params string[] payloads)
    {
        foreach (var p in payloads)
        {
            _payloads.Enqueue(p);
        }
    }

    public Task<string> GetJwksJsonAsync(CancellationToken cancellationToken)
    {
        FetchCount++;
        if (_payloads.Count == 0)
        {
            return Task.FromResult("{\"keys\":[]}");
        }

        return Task.FromResult(_payloads.Dequeue());
    }
}

internal sealed class MutableClock : TimeProvider
{
    public DateTimeOffset Utc { get; set; } = DateTimeOffset.UtcNow;

    public override DateTimeOffset GetUtcNow() => Utc;
}

internal sealed class OrderTrackingAvpWriter : IAvpPolicyWriter
{
    private readonly IAuthzCache _cache;
    public List<string> Events { get; } = [];
    public int ApplyCalls { get; private set; }

    public OrderTrackingAvpWriter(IAuthzCache cache)
    {
        _cache = cache;
    }

    public async ValueTask ApplyRoleChangesAsync(RoleChangeRequest request, CancellationToken cancellationToken)
    {
        ApplyCalls++;
        foreach (var jti in request.AffectedJtis)
        {
            var lookup = await _cache.GetAsync(jti, cancellationToken).ConfigureAwait(false);
            if (lookup.Outcome == CacheOutcome.Miss)
            {
                throw new InvalidOperationException("Redis deleted before AVP apply");
            }
        }

        Events.Add("avp");
    }
}
