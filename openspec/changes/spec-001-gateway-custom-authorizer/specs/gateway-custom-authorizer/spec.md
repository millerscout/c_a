## Purpose

Authenticates API Gateway HTTP API requests with a Cognito JWT (crypto before any cache or policy I/O) and injects an AVP-derived role snapshot from Redis so Workspace receives identity and roles through a single custom authorizer slot.

## ADDED Requirements

### Requirement: HTTP API v2 simple authorizer contract

The authorizer MUST attach to an API Gateway HTTP API as a request authorizer using payload format version `2.0` and MUST return a simple response body. On success it MUST return `isAuthorized` true and a `context` object containing `sub`, `azp`, and `roles` (comma-separated role names). On rejection it MUST return `isAuthorized` false. The authorizer MUST NOT return an IAM policy document. API Gateway authorizer result caching MUST be disabled (TTL 0).

#### Scenario: Authorized request includes identity and roles

- **WHEN** a request presents a valid Cognito JWT and an active role snapshot is available
- **THEN** the authorizer returns `isAuthorized` true and `context.sub`, `context.azp`, and `context.roles` populated from the token and the snapshot

#### Scenario: Rejected request omits context

- **WHEN** the authorizer denies the request
- **THEN** the response is `{ "isAuthorized": false }` and API Gateway MUST NOT invoke Workspace

### Requirement: JWT verification before cache or AVP

The authorizer MUST verify the Bearer JWT against the configured Cognito user pool before reading Redis or calling AVP. Verification MUST include signature validation using the JWKS key identified by `kid`, issuer checks, and `nbf`/`exp`. JWKS MUST be served from process memory after first load and MUST be refreshed only when the token `kid` is unknown. The JWT MUST be treated as identity only (`sub`, authorized party, `jti`, validity); it MUST NOT be treated as a source of roles. Authorized party in `context.azp` MUST come from claim `azp` when present, otherwise `client_id`.

#### Scenario: Expired or not-yet-valid token is denied

- **WHEN** the JWT `exp` is in the past or `nbf` is in the future
- **THEN** the authorizer returns `isAuthorized` false without reading Redis or calling AVP

#### Scenario: Invalid signature or unknown issuer is denied

- **WHEN** the JWT signature does not match the Cognito JWKS key or the issuer is not the configured user pool
- **THEN** the authorizer returns `isAuthorized` false without reading Redis or calling AVP

#### Scenario: Unknown kid refreshes JWKS then verifies

- **WHEN** the JWT `kid` is not in the in-memory JWKS
- **THEN** the authorizer fetches Cognito JWKS, updates memory, and retries verification with the new keys

#### Scenario: Forged token does not touch Redis or AVP

- **WHEN** the Bearer token fails cryptographic validation
- **THEN** Redis is not read or written and AVP is not called

### Requirement: Redis session key by jti

After a JWT verifies, the authorizer MUST look up `authz:{jti}`. On a hit it MUST use the stored role snapshot and MUST NOT call AVP. Cache TTL for a hydrated allow snapshot MUST equal remaining token lifetime (`exp - now`).

#### Scenario: Cache hit injects roles without AVP

- **WHEN** `GET authz:{jti}` returns a role snapshot
- **THEN** the authorizer returns `isAuthorized` true with those roles in `context.roles` and does not call AVP

#### Scenario: Cache miss hydrates from AVP

- **WHEN** `GET authz:{jti}` misses and AVP returns an allow snapshot of base roles and tenant permissions
- **THEN** the authorizer stores that snapshot at `authz:{jti}` with TTL equal to remaining `exp` and returns `isAuthorized` true with those roles

### Requirement: Coarse gate only

A verified session with an allow snapshot MUST authorize invocation of the HTTP API (coarse perimeter). The authorizer MUST NOT evaluate Workspace document-level or resource-instance rules. Workspace MUST enforce those using `context.roles` and its own domain data.

#### Scenario: Authorizer allows API invoke regardless of document

- **WHEN** the JWT is valid and the role snapshot allows the session
- **THEN** the authorizer returns `isAuthorized` true even if Workspace would later deny a specific document

### Requirement: AVP deny and revocation

On a Redis miss, if AVP denies the session the authorizer MUST return `isAuthorized` false and MUST NOT write an allow snapshot. Role changes MUST update Cedar in AVP first, then delete `authz:{jti}` so a later miss cannot rehydrate stale roles. Logout or forced disconnect MUST prevent reuse of that `jti` while the JWT is still within `exp`.

#### Scenario: AVP deny does not cache an allow snapshot

- **WHEN** Redis misses and AVP returns deny
- **THEN** the authorizer returns `isAuthorized` false and Redis does not contain an allow snapshot for that `jti`

#### Scenario: Role update invalidates Redis after AVP

- **WHEN** an admin role change is applied
- **THEN** Cedar in AVP is updated first and `authz:{jti}` is deleted second

#### Scenario: Revoked jti cannot proceed to Workspace

- **WHEN** the JWT is still cryptographically valid but the `jti` has been revoked
- **THEN** the authorizer returns `isAuthorized` false and Workspace is not invoked
