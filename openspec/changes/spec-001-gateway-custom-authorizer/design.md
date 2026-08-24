## Context

See proposal.md (ADR 001). Greenfield authorizer Lambda. Constraints: one Gateway authorizer slot; HTTP API v2 simple responses; JWT is identity only (`sub`, `azp`, `jti`, validity — no roles); crypto before Redis/AVP; ElastiCache in deployed envs, compose Redis locally; AVP has no GetRoles API (miss = role/tenant snapshot); after Allow, **VPC Lattice + Cloud Map** (not a Cloud Map client inside the Lambda). Traffic assumption: &lt; 1B requests/month; hit-path p99 &lt; 10 ms; Redis hit ratio &gt; 99.5%.

**Claim mapping:** inject `context.azp`. Read JWT `azp` when present, else Cognito access-token `client_id`.

## Goals / Non-Goals

**Goals:**

- Single custom request authorizer: parse JWT (spans) → verify Cognito JWKS → `GET authz:{jti}` → AVP snapshot on miss → `{ isAuthorized, context }`.
- Allocation-light hit path: reused buffers, structs, static `ConnectionMultiplexer`, static JWKS/keys.
- Revocation: Cedar first, Redis `DEL` second; logout/forced disconnect cannot rehydrate Allow; Gateway result TTL 0.
- Emit `sub` / `azp` / decision for audit; optional X-Ray / OTel context through the authorizer (pass-through, not a new tracing product).

**Non-Goals:**

- IAM policy documents / REST authorizer 1.0.
- Per-route or document-level Cedar in this Lambda (Workspace).
- Lattice/Cloud Map clients inside the authorizer; Cognito Hosted UI / per-firm federation (Phase 1).
- RFC 8693 OBO issuance and downstream `aud` enforcement (Phase 4 / pen-test). Those tokens still look like Cognito JWTs to this authorizer (`sub`, `azp`, `jti`, `exp`).
- DynamoDB DAX L2; self-hosted Envoy + Cedar Rust (ADR 2.0).
- Cedar policy authoring UX.

## Decisions

### D1 — HTTP API v2 simple response (`payloadFormatVersion: "2.0"`)

Return `{ "isAuthorized": true|false, "context": { "sub", "azp", "roles" } }`. Context values are strings; `roles` is comma-separated.

**Why:** HTTP API + Lattice/Cloud Map private integration. Simple responses avoid IAM JSON and match the coarse gate. REST `authorizationType` / HTTP `AuthorizationType` are a single enum; this Lambda is the one `CUSTOM` slot.

**Alternative considered:** REST IAM `policyDocument` — rejected.

### D2 — Coarse gate + role injection

Allow = valid session + role snapshot. Workspace applies document-level rules using `context.roles`.

**Why:** Stable `authz:{jti}` keys, high hit ratio. Fine-grained keys would thrash AVP.

### D3 — Redis key `authz:{jti}`, TTL = `exp - now`

**Why:** Per-token revoke; `azp` still goes to context. Gateway authorizer cache TTL **0** so Redis `DEL`/sentinel is visible on the next request.

**Value:** packed UTF-8 role blob, not JSON on the hit path.

### D4 — Miss path is an AVP role/policy snapshot

Cedar evaluates base roles and tenant permissions against a finite catalog; `SET authz:{jti} EX {exp-now}`. Entities not in the JWT MUST be supplied from the policy store/entity payload. `IsAuthorizedWithToken` cannot invent groups the JWT does not carry.

### D5 — Revocation integrity

**Admin role change (ADR):** Update Roles writes AVP first, then `DEL authz:{jti}`. Next miss hydrates the new snapshot.

**Logout / forced disconnect (JWT still in `exp`):** `DEL` then miss would **rehydrate Allow**. MUST deny without an AVP allow snapshot: deny-sentinel `SET authz:{jti}` with remaining TTL, or `authz:revoked:{jti}` checked before miss→AVP.

### D6 — Untrusted first (no Redis/AVP before verify)

Span-parse Bearer → `kid`/`exp`/`nbf`/`jti` → signature + issuer via in-memory JWKS; unknown `kid` fetches `jwks.json` then retries. Only then Redis.

**Why:** Forged tokens must not hit Redis or AVP (quota + confused deputy). Tradeoff: Lambda CPU on garbage tokens (Gateway cannot verify in this topology).

**Libraries:** No IdentityModel on the hot path. Cached `RSA`/`ECDsa` per `kid`. StackExchange.Redis static multiplexer. AVP only on miss.

### D7 — Gateway authorizer cache off

Identity source: `Authorization`. Result TTL = 0.

### D8 — Runtime and Redis topology

.NET Lambda. Local: compose Redis, no persistence, `allkeys-lru`. Dev/prod: ElastiCache TLS, same multiplexer. First slice: standalone / configuration endpoint, not cluster-mode.

**Redis outage (ADR §6):** fail closed or degrade to AVP is a product choice; **do not** silently fail open. DAX/L2 and tenant-sharded Redis are ADR 2.0 / ops mitigations, not this change.

### D9 — Handler shape

HTTP API request authorizer event 2.0: `headers.authorization` only. `readonly struct` result → canned JSON true/false.

### D10 — OBO / confused deputy (adjacent)

External OBO: RFC 8693 token exchange at Cognito. Internal: exchange token with `sub`, `azp`, `aud`. **This authorizer** still verifies Cognito signature and session roles. **Downstream** services MUST reject `aud` mismatch (403). Not implemented in this Lambda.

### D11 — Observability

Pass X-Ray/OTel if Gateway provides it. Audit line: decision, `sub`, `azp`, workspace/target when present. Hit-path logging must not allocate per-field graphs; structured fields on deny/miss are enough.

## Risks / Trade-offs

- [Logout vs DEL rehydrate] → Deny sentinel (D5).
- [Redis down → AVP stampede] → Fail closed or bounded AVP; L2/sharding later (ADR §6).
- [Malformed JWT Lambda cost] → Verify is mandatory; JWKS in memory; no Redis until sig OK.
- [JWKS fetch fail on unknown `kid`] → Deny.
- [Lambda in VPC for ElastiCache] → Endpoints/NAT for Cognito JWKS + AVP.
- [Coarse Allow] → Workspace MUST enforce documents.
- [Gateway context size] → Compact role names.
- [NativeAOT + StackExchange.Redis] → Trim-test or isolate AVP helper.

## Migration Plan

Aligned to ADR 001 phases; **this change is Phase 3 authorizer + Update Roles + Redis/AVP wiring**. Federation (Phase 1), Cedar schema authorship (Phase 2 content), Lattice target groups + Cloud Map self-register + `aud` (Phase 4) are prerequisites or follow-ons.

1. Compose Redis + stub AVP; unit-test JWT and hit/miss.
2. Deploy authorizer + HTTP API `CUSTOM`, cache TTL 0; prove Allow/Deny without Lattice.
3. Update Roles Lambda (AVP then `DEL`); e2e revocation &lt; 1 s.
4. Attach Lattice / Cloud Map integration; map `sub` / `azp` / `roles`.
5. Rollback: detach authorizer (unauthorized) or deny-all; do not attach Cognito JWT authorizer expecting roles.

**ADR 2.0:** Revisit Envoy + in-process Cedar / Ory when platform ops capacity exists and ~$2k/1B vs ~$200–300/1B ROI justifies it.

## Open Questions

- Cedar snapshot catalog (role/permission identifiers) when the AVP store is created; does not change miss/hit.
- JWKS algorithm is whatever the pool publishes (`RS256` typical).
- Redis-unavailable behavior: fail closed vs bounded AVP (pick at apply time; default **fail closed**).
