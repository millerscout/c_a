using Caseware.Authz;

namespace Caseware.GatewayAuthorizer;

public sealed class Function
{
    private readonly AuthorizerPipeline _pipeline;

    public Function() : this(AuthorizerHost.CreatePipeline(LoadOptions()))
    {
    }

    public Function(AuthorizerPipeline pipeline)
    {
        _pipeline = pipeline;
    }

    public async Task<AuthorizerResponse> FunctionHandler(AuthorizerRequest request, ILambdaContext context)
    {
        var decision = await _pipeline.AuthorizeAsync(request.AuthorizationHeader(), CancellationToken.None)
            .ConfigureAwait(false);
        context.Logger.Log(
            $"authz decision={(decision.IsAuthorized ? "allow" : "deny")} sub={decision.Sub} azp={decision.Azp}");
        return AuthorizerResponse.From(decision);
    }

    public static AuthorizerOptions LoadOptions()
        => AuthorizerOptions.FromEnvironmentAndFile();
}
