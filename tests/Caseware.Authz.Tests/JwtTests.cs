using Caseware.Authz.Jwt;

namespace Caseware.Authz.Tests;

public sealed class JwtParserTests
{
    [Fact]
    public void Missing_authorization_header_is_not_a_bearer_token()
    {
        Assert.False(Bearer.TryGetToken("", out _));
        Assert.False(Bearer.TryGetToken("Basic abc", out _));
    }

    [Fact]
    public void Malformed_jwt_does_not_parse()
    {
        Assert.False(JwtParser.TryParseUnverified("not-a-jwt", out _, out _, out _));
        Assert.False(JwtParser.TryParseUnverified("a.b", out _, out _, out _));
    }

    [Fact]
    public void Extracts_claims_including_azp()
    {
        using var rsa = JwtTokenFactory.CreateRsa();
        var jwt = JwtTokenFactory.Token(rsa, "k1", sub: "usr_1", azp: "app_3", jti: "tok_9");
        Assert.True(JwtParser.TryParseUnverified(jwt, out var claims, out _, out _));
        Assert.Equal("k1", claims.Kid);
        Assert.Equal("usr_1", claims.Sub);
        Assert.Equal("app_3", claims.Azp);
        Assert.Equal("tok_9", claims.Jti);
        Assert.Equal(JwtTokenFactory.Issuer, claims.Iss);
    }

    [Fact]
    public void Azp_falls_back_to_client_id()
    {
        using var rsa = JwtTokenFactory.CreateRsa();
        var jwt = JwtTokenFactory.Token(rsa, "k1", azp: "from-client-id", useAzp: false);
        Assert.True(JwtParser.TryParseUnverified(jwt, out var claims, out _, out _));
        Assert.Equal("from-client-id", claims.Azp);
    }
}

public sealed class JwtVerifierTests
{
    [Fact]
    public async Task Expired_token_is_denied_without_jwks_fetch_when_key_cached()
    {
        using var rsa = JwtTokenFactory.CreateRsa();
        var jwks = new JwksKeyCache(new ScriptJwksClient(JwtTokenFactory.JwksJson(rsa, "k1")));
        jwks.Load(JwtTokenFactory.JwksJson(rsa, "k1"));
        var verifier = new JwtVerifier(jwks, JwtTokenFactory.Issuer);
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var jwt = JwtTokenFactory.Token(rsa, "k1", exp: now - 30, nbf: now - 120);

        var result = await verifier.VerifyAsync("Bearer " + jwt, CancellationToken.None);

        Assert.Equal(JwtVerifyStatus.Expired, result.Status);
        Assert.Equal("user-1", result.Claims.Sub);
    }

    [Fact]
    public async Task Not_yet_valid_token_is_denied()
    {
        using var rsa = JwtTokenFactory.CreateRsa();
        var jwks = new JwksKeyCache(new ScriptJwksClient());
        jwks.Load(JwtTokenFactory.JwksJson(rsa, "k1"));
        var verifier = new JwtVerifier(jwks, JwtTokenFactory.Issuer);
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var jwt = JwtTokenFactory.Token(rsa, "k1", nbf: now + 600, exp: now + 1200);

        var result = await verifier.VerifyAsync("Bearer " + jwt, CancellationToken.None);

        Assert.Equal(JwtVerifyStatus.NotYetValid, result.Status);
    }

    [Fact]
    public async Task Bad_signature_is_denied()
    {
        using var rsa = JwtTokenFactory.CreateRsa();
        using var other = JwtTokenFactory.CreateRsa();
        var jwks = new JwksKeyCache(new ScriptJwksClient());
        jwks.Load(JwtTokenFactory.JwksJson(rsa, "k1"));
        var verifier = new JwtVerifier(jwks, JwtTokenFactory.Issuer);
        var jwt = JwtTokenFactory.Token(other, "k1");

        var result = await verifier.VerifyAsync("Bearer " + jwt, CancellationToken.None);

        Assert.Equal(JwtVerifyStatus.BadSignature, result.Status);
    }

    [Fact]
    public async Task Unknown_issuer_is_denied()
    {
        using var rsa = JwtTokenFactory.CreateRsa();
        var jwks = new JwksKeyCache(new ScriptJwksClient());
        jwks.Load(JwtTokenFactory.JwksJson(rsa, "k1"));
        var verifier = new JwtVerifier(jwks, JwtTokenFactory.Issuer);
        var jwt = JwtTokenFactory.Token(rsa, "k1", iss: "https://evil.example");

        var result = await verifier.VerifyAsync("Bearer " + jwt, CancellationToken.None);

        Assert.Equal(JwtVerifyStatus.UnknownIssuer, result.Status);
    }

    [Fact]
    public async Task Unknown_kid_fetches_jwks_then_accepts()
    {
        using var rsa = JwtTokenFactory.CreateRsa();
        var client = new ScriptJwksClient(JwtTokenFactory.JwksJson(rsa, "rotated"));
        var jwks = new JwksKeyCache(client);
        var verifier = new JwtVerifier(jwks, JwtTokenFactory.Issuer);
        var jwt = JwtTokenFactory.Token(rsa, "rotated");

        var result = await verifier.VerifyAsync("Bearer " + jwt, CancellationToken.None);

        Assert.Equal(JwtVerifyStatus.Ok, result.Status);
        Assert.Equal(1, client.FetchCount);
        Assert.Equal("user-1", result.Claims.Sub);
    }
}
