using Caseware.Authz.Cache;
using Caseware.Authz.Roles;

namespace Caseware.UpdateRoles;

public sealed class UpdateRolesRequest
{
    public string[] AffectedJtis { get; set; } = [];
}

public sealed class Function
{
    private readonly UpdateRolesService _service;

    public Function() : this(CreateDefault())
    {
    }

    public Function(UpdateRolesService service)
    {
        _service = service;
    }

    public Task FunctionHandler(UpdateRolesRequest request)
        => _service.ApplyAsync(
            new RoleChangeRequest { AffectedJtis = request.AffectedJtis },
            CancellationToken.None);

    internal static UpdateRolesService CreateDefault()
    {
        var options = GatewayAuthorizer.Function.LoadOptions();
        var cache = RedisAuthzCache.Connect(options.RedisEndpoint);
        return new UpdateRolesService(new NoOpAvpWriter(), cache);
    }
}

file sealed class NoOpAvpWriter : IAvpPolicyWriter
{
    public int ApplyCalls { get; private set; }

    public ValueTask ApplyRoleChangesAsync(RoleChangeRequest request, CancellationToken cancellationToken)
    {
        ApplyCalls++;
        return ValueTask.CompletedTask;
    }
}
