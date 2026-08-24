## Why

Caseware Collaborate needs a high-throughput authorization edge for internal staff and external clients. The legacy authorizer is at capacity (target: current traffic under 1 billion requests/month). API Gateway allows **exactly one** authorizer per HTTP API route (`JWT` | `CUSTOM` | `AWS_IAM`) and per REST method (`COGNITO_USER_POOLS` | `CUSTOM` | `AWS_IAM` | `NONE`). Cognito JWT verification and role resolution therefore cannot be chained at the Gateway; they MUST live in a single custom Lambda authorizer. Calling Amazon Verified Permissions on every request misses the hit-path latency budget (p99 under 10 ms).

This change implements **ADR 001** (Proposed, 23 Aug 2026): consolidated custom authorizer, Redis session keyed by `jti`, Cedar snapshot on miss, coarse `context.roles` injection. Workspace keeps document-level enforcement. After Allow, Gateway forwards via VPC Lattice and Cloud Map.

## What Changes

- Attach a custom Lambda authorizer as the **only** authorizer on HTTP API routes (`payloadFormatVersion: "2.0"`, Gateway authorizer result TTL **0**).
- Verify the Bearer JWT (identity: `sub`, `azp`, `jti`, `nbf`/`exp`) against Cognito JWKS in container memory **before** any Redis or AVP I/O; refresh JWKS only on unknown `kid`.
- `GET authz:{jti}` on ElastiCache Redis (docker-compose Redis locally). Hit: `isAuthorized: true` + `context.roles`. Miss: Cedar snapshot in AVP → `SET authz:{jti}` TTL = `exp - now` → same v2 body. No IAM policy JSON.
- Coarse perimeter: session gate + role injector. Workspace enforces resource/document overrides.
- **Update Roles Lambda:** write Cedar in AVP first, then `DEL authz:{jti}` so a miss cannot rehydrate stale roles.
- After Allow: API Gateway → VPC link / **VPC Lattice** → **Cloud Map** → Workspace (integration, not authorizer logic).
- Inject `context.sub`, `context.azp`, `context.roles` for Workspace and audit (`sub` actor, `azp` delegate).

**Out of this change (ADR 001 later phases / ADR 2.0):** Cognito per-firm OIDC/SAML + PKCE setup; RFC 8693 OBO token exchange and downstream `aud` enforcement (confused-deputy tests); DynamoDB/DAX L2 cache; Envoy + embedded Cedar / Ory-Keycloak cost-down path.

## Capabilities

### New Capabilities

- `gateway-custom-authorizer`: HTTP API v2 request authorizer that verifies Cognito JWTs (crypto before cache), resolves roles from Redis `authz:{jti}` or an AVP Cedar snapshot, injects `context.roles` / `sub` / `azp`, returns simple `isAuthorized` responses, and relies on Update Roles (AVP then Redis `DEL`) plus a deny-sentinel for logout while the JWT is still in `exp`.

### Modified Capabilities

- None (greenfield; no existing spec requirements).

## Impact

- .NET authorizer Lambda (span parse, static JWKS, Redis multiplexer); Update Roles Lambda; ElastiCache (dev/prod) and compose Redis (local); AVP on miss; Cognito as IdP/JWKS only.
- HTTP API: `CUSTOM` authorizer, payload 2.0 simple responses, result cache TTL 0, VPC Lattice target groups + Cloud Map service discovery for Workspace.
- SLAs that constrain the hot path: Redis hit ratio above 99.5% for active sessions; p99 auth latency under 10 ms on hit; revocation propagation under 1 s (AVP write then Redis `DEL`).
- Workspace, Lattice auth policies, Cloud Map self-registration CI/CD, and OBO/`aud` checks consume `context` but are not implemented here.
- Dependencies: Cognito user pool, ElastiCache, AVP policy store, HTTP API, Lattice/Cloud Map (wiring after Allow is proven).
