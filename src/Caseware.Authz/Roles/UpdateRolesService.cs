using Caseware.Authz.Cache;

namespace Caseware.Authz.Roles;

public sealed class RoleChangeRequest
{
    public required IReadOnlyList<string> AffectedJtis { get; init; }
}

public interface IAvpPolicyWriter
{
    int ApplyCalls { get; }
    ValueTask ApplyRoleChangesAsync(RoleChangeRequest request, CancellationToken cancellationToken);
}

/// <summary>
/// Admin role updates write Cedar first, then DEL authz:{jti}.
/// Logout / forced disconnect MUST NOT use this path: DEL + miss would rehydrate Allow.
/// Use <see cref="IAuthzCache.SetDenySentinelAsync"/> (D5) instead.
/// </summary>
public sealed class UpdateRolesService
{
    private readonly IAvpPolicyWriter _avp;
    private readonly IAuthzCache _cache;

    public UpdateRolesService(IAvpPolicyWriter avp, IAuthzCache cache)
    {
        _avp = avp;
        _cache = cache;
    }

    public async Task ApplyAsync(RoleChangeRequest request, CancellationToken cancellationToken)
    {
        await _avp.ApplyRoleChangesAsync(request, cancellationToken).ConfigureAwait(false);
        foreach (var jti in request.AffectedJtis)
        {
            await _cache.DeleteAsync(jti, cancellationToken).ConfigureAwait(false);
        }
    }
}
