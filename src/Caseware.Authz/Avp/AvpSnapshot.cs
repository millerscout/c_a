namespace Caseware.Authz.Avp;

public readonly struct AvpSnapshot
{
    public AvpSnapshot(bool allowed, string roles)
    {
        Allowed = allowed;
        Roles = roles;
    }

    public bool Allowed { get; }
    public string Roles { get; }
}

public interface IAvpSnapshotClient
{
    int InvocationCount { get; }
    ValueTask<AvpSnapshot> GetSnapshotAsync(string sub, string azp, CancellationToken cancellationToken);
}

public sealed class RecordingAvpClient : IAvpSnapshotClient
{
    private readonly Func<string, string, AvpSnapshot> _handler;

    public RecordingAvpClient(Func<string, string, AvpSnapshot>? handler = null)
    {
        _handler = handler ?? ((_, _) => new AvpSnapshot(true, "workspace_contributor"));
    }

    public int InvocationCount { get; private set; }

    public ValueTask<AvpSnapshot> GetSnapshotAsync(string sub, string azp, CancellationToken cancellationToken)
    {
        InvocationCount++;
        return ValueTask.FromResult(_handler(sub, azp));
    }
}
