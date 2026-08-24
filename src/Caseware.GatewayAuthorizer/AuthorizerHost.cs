using Caseware.Authz;
using Caseware.Authz.Avp;
using Caseware.Authz.Cache;
using Caseware.Authz.Jwt;

namespace Caseware.GatewayAuthorizer;

public static class AuthorizerHost
{
    public static AuthorizerPipeline CreatePipeline(AuthorizerOptions options)
    {
        var http = new HttpClient { Timeout = TimeSpan.FromSeconds(3) };
        var jwks = new JwksKeyCache(new HttpJwksClient(http, options.JwksUrl));
        var verifier = new JwtVerifier(jwks, options.CognitoIssuer);
        var cache = RedisAuthzCache.Shared(options.RedisEndpoint, options.RedisUseTls);
        IAvpSnapshotClient avp = new CatalogAvpSnapshotClient(
            options.RoleCatalog,
            BindingAvpRoleEvaluator.Parse(options.AvpRoleBindings));
        return new AuthorizerPipeline(verifier, cache, avp, new LambdaAuditSink());
    }
}

internal sealed class LambdaAuditSink : IAuditSink
{
    public void Write(in AuditRecord record) => _ = record;
}
