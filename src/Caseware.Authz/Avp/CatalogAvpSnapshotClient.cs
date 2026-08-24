namespace Caseware.Authz.Avp;

public interface IAvpRoleEvaluator
{
    ValueTask<bool> HasRoleAsync(string sub, string azp, string role, CancellationToken cancellationToken);
}

public sealed class BindingAvpRoleEvaluator : IAvpRoleEvaluator
{
    private readonly HashSet<(string Sub, string Azp, string Role)> _grants;

    public BindingAvpRoleEvaluator(IEnumerable<(string Sub, string Azp, string Role)> grants)
    {
        _grants = [.. grants];
    }

    public static BindingAvpRoleEvaluator Parse(string? bindings)
    {
        var grants = new List<(string, string, string)>();
        if (string.IsNullOrWhiteSpace(bindings))
        {
            return new BindingAvpRoleEvaluator(grants);
        }

        foreach (var entry in bindings.Split([';', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var parts = entry.Split('|', StringSplitOptions.TrimEntries);
            if (parts.Length != 3 || parts[0].Length == 0 || parts[1].Length == 0 || parts[2].Length == 0)
            {
                continue;
            }

            grants.Add((parts[0], parts[1], parts[2]));
        }

        return new BindingAvpRoleEvaluator(grants);
    }

    public ValueTask<bool> HasRoleAsync(string sub, string azp, string role, CancellationToken cancellationToken)
        => ValueTask.FromResult(_grants.Contains((sub, azp, role)));
}

public sealed class CatalogAvpSnapshotClient : IAvpSnapshotClient
{
    private readonly string[] _catalog;
    private readonly IAvpRoleEvaluator _evaluator;

    public CatalogAvpSnapshotClient(IReadOnlyList<string> catalog, IAvpRoleEvaluator evaluator)
    {
        _catalog = [.. catalog];
        _evaluator = evaluator;
    }

    public int InvocationCount { get; private set; }

    public async ValueTask<AvpSnapshot> GetSnapshotAsync(string sub, string azp, CancellationToken cancellationToken)
    {
        InvocationCount++;
        var granted = new List<string>(_catalog.Length);
        foreach (var role in _catalog)
        {
            if (await _evaluator.HasRoleAsync(sub, azp, role, cancellationToken).ConfigureAwait(false))
            {
                granted.Add(role);
            }
        }

        if (granted.Count == 0)
        {
            return new AvpSnapshot(false, "");
        }

        return new AvpSnapshot(true, string.Join(',', granted));
    }
}
