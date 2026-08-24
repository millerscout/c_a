namespace Caseware.GatewayAuthorizer;

public interface ILambdaLogger
{
    void Log(string message);
}

public interface ILambdaContext
{
    ILambdaLogger Logger { get; }
}

public sealed class NullLambdaContext : ILambdaContext
{
    public ILambdaLogger Logger { get; } = new NullLogger();

    private sealed class NullLogger : ILambdaLogger
    {
        public void Log(string message)
        {
        }
    }
}
