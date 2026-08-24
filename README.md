# Caseware gateway authorizer

Custom **API Gateway HTTP API** authorizer for Caseware Collaborate. One Lambda owns Cognito JWT verification and role lookup so Gateway does not have to chain a JWT authorizer with a second custom authorizer (it cannot).

On the hot path the authorizer verifies the Bearer token against Cognito JWKS in process memory, then reads Redis `authz:{jti}`. A hit returns roles without calling Amazon Verified Permissions (AVP). A miss evaluates a finite role catalog, caches the snapshot until the token expires, and returns the same HTTP API v2 simple response. Workspace still owns document-level checks.

| Budget | Target |
| --- | --- |
| Redis hit ratio (active sessions) | > 99.5% |
| p99 latency on cache hit | < 10 ms |
| Role-change visibility | < 1 s (AVP write, then Redis `DEL`) |

## Request flow

```
Client
  │  Authorization: Bearer <cognito jwt>
  ▼
API Gateway HTTP API (CUSTOM, payload 2.0, result TTL 0)
  ▼
Authorizer Lambda
  1. Parse JWT (kid, sub, azp|client_id, jti, nbf, exp)
  2. Verify signature + issuer via in-memory JWKS  ← no Redis/AVP before this
  3. GET authz:{jti}
       hit allow     → isAuthorized true + context
       deny sentinel → isAuthorized false (logout while JWT still unexpired)
       miss          → catalog snapshot; SET with TTL = exp − now
  ▼
On Allow: VPC Lattice / Cloud Map → Workspace
           headers x-sub, x-azp, x-roles
```

Allow response:

```json
{
  "isAuthorized": true,
  "context": {
    "sub": "…",
    "azp": "…",
    "roles": "firm_admin,workspace_contributor"
  }
}
```

Deny is `{ "isAuthorized": false }` with no context. Gateway does not invoke Workspace.

`context.azp` comes from JWT `azp`, or Cognito `client_id` when `azp` is absent. Roles never come from the token.

## Repository

| Path | Role |
| --- | --- |
| `src/Caseware.Authz` | JWT verify, Redis cache, catalog snapshot, Update Roles service |
| `src/Caseware.GatewayAuthorizer` | HTTP API v2 Lambda handler |
| `src/Caseware.UpdateRoles` | Admin role-change Lambda (Cedar first, then `DEL`) |
| `tests/Caseware.Authz.Tests` | JWT, pipeline, Redis, template contract tests |
| `infra/template.yaml` | SAM: HTTP API, authorizer TTL 0, Lattice / Cloud Map, header mapping |
| `docker-compose.yml` | Local Redis 7 (no persist, `allkeys-lru`, port 6379) |
| `openspec/changes/spec-001-gateway-custom-authorizer` | Spec, design, tasks (ADR 001) |

Solution file: `Caseware.slnx`. Target framework: `net10.0`.

## Prerequisites

- .NET 10 SDK
- Docker or Podman (local Redis)
- Optional: AWS SAM CLI to deploy `infra/template.yaml`

`nuget.config` points at `./nupkgs` and **disables nuget.org**. Production libraries have no package references. Test packages (xunit, VSTest) live in `nupkgs/` (gitignored). If restore fails, copy those nupkgs in or temporarily re-enable nuget.org.

## Local Redis

```bash
podman compose up -d    # or: docker compose up -d
podman compose exec -T redis redis-cli PING
# PONG
```

No AOF/RDB. `allkeys-lru` with a 64 MB cap. This is the local stand-in for ElastiCache.

## Build and test

```bash
dotnet build
dotnet run --project tests/Caseware.Authz.Tests
```

The test project is an executable with a small `[Fact]` runner. Use `dotnet run` (not `dotnet test`): the VSTest host is unreliable in this environment.

Redis round-trip tests expect `localhost:6379`. Bring compose up first.

## Configuration

Env vars override `src/Caseware.GatewayAuthorizer/appsettings.json`.

| Key | Meaning |
| --- | --- |
| `REDIS_ENDPOINT` | `host:port` (default `localhost:6379`) |
| `REDIS_USE_TLS` | `true` / `1` for ElastiCache in-transit encryption |
| `COGNITO_ISSUER` | Expected JWT `iss` |
| `COGNITO_JWKS_URL` | JWKS URL; fetched only on unknown `kid` |
| `AVP_POLICY_STORE_ID` | Policy store id (wired for deploy; SDK client not in this slice) |
| `ROLE_CATALOG` | Comma-separated roles the miss path may grant |
| `AVP_ROLE_BINDINGS` | `sub\|azp\|role` entries, separated by `;` or newlines |

Empty bindings **fail closed** on cache miss (no roles → deny). Local example:

```text
user-1|client-app|firm_admin;user-1|client-app|workspace_contributor
```

## Revocation

- **Admin role change:** Update Roles writes Cedar/AVP first, then `DEL authz:{jti}`. The next request misses and hydrates the new snapshot. Do not delete Redis first.
- **Logout / forced disconnect** while the JWT is still inside `exp`: set deny sentinel `authz:{jti} = __deny__` with remaining TTL. A plain `DEL` would miss and AVP would Allow again.

Gateway authorizer result cache is **TTL 0** so the next request always re-enters Lambda and sees Redis.

Redis errors after a valid JWT **fail closed** (deny, no AVP stampede).

## Infrastructure

`infra/template.yaml` defines:

- Authorizer + Update Roles functions (`dotnet8` runtime in SAM; projects compile as `net10.0`)
- HTTP API with `payloadFormatVersion: "2.0"`, simple responses, identity source `Authorization`, result TTL `0`
- VPC Lattice service, Cloud Map namespace `caseware.internal` / service `workspace`
- Header mapping: `x-sub`, `x-azp`, `x-roles` from `$context.authorizer.*`

The authorizer does not call Cloud Map. Lattice/Cloud Map run only after Allow.

## Out of scope (later ADR phases)

Cognito Hosted UI / per-firm federation and PKCE; RFC 8693 OBO issuance and downstream `aud` checks; DynamoDB/DAX L2; Envoy + in-process Cedar. This Lambda still treats those tokens as Cognito JWTs (`sub`, `azp`, `jti`, `exp`).

## Implementation notes

- JWT parse/verify is span-oriented; no IdentityModel on the hot path. RS256 + in-memory JWKS.
- Redis is a small RESP client with a process-wide `RedisAuthzCache.Shared` connection (StackExchange.Redis is not referenced while nuget.org is off).
- Miss-path AVP is a catalog evaluator (`CatalogAvpSnapshotClient`), not the AWS AVP SDK. Swap the `IAvpSnapshotClient` when the SDK feed is available.
- Update Roles uses the same Cedar-then-`DEL` order; the deployed writer is a no-op until the AVP SDK is wired.
