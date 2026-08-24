## 1. Project and local Redis

- [x] 1.1 Create the .NET Lambda authorizer project (handler placeholder returning HTTP API v2 `{ isAuthorized: false }`) and verify `dotnet build` succeeds
- [x] 1.2 Add `docker-compose` Redis (no persistence, `allkeys-lru`, port published) and verify `redis-cli PING` returns `PONG`
- [x] 1.3 Add configuration for Redis endpoint, Cognito pool/issuer, and AVP policy store (env/settings) and verify local compose endpoint loads in the process

## 2. JWT verification

- [x] 2.1 Implement span-based Bearer extraction and JWT header/payload read (`kid`, `sub`, `azp` or `client_id`, `jti`, `nbf`, `exp`) and verify unit tests cover missing header, malformed JWT, claim extraction, and `azp` fallback to `client_id`
- [x] 2.2 Implement in-memory JWKS cache with refresh on unknown `kid` and signature + issuer + `nbf`/`exp` checks and verify tests deny expired, not-yet-valid, bad signature, and unknown issuer without calling Redis or AVP
- [x] 2.3 Verify unknown `kid` fetches JWKS, updates memory, and then accepts a valid token signed with the new key

## 3. Redis session cache

- [x] 3.1 Wire a static `ConnectionMultiplexer` (async) and `GET`/`SET`/`DEL` on `authz:{jti}` using structs/`RedisValue` and reused key buffers, and verify a round-trip against compose Redis
- [x] 3.2 Implement hit path: valid JWT + stored role blob → `{ isAuthorized: true, context: { sub, azp, roles } }` with no AVP call, and verify with a test double that AVP is not invoked
- [x] 3.3 Implement `SET` with TTL = `exp - now` for allow snapshots and verify TTL is within one second of remaining lifetime
- [x] 3.4 Implement deny-sentinel (or `authz:revoked:{jti}`) for logout/forced disconnect so a still-valid JWT returns `isAuthorized: false` without AVP, and verify `DEL` of an allow key without sentinel would rehydrate (negative test) while sentinel does not

## 4. AVP miss path

- [x] 4.1 Implement AVP role/policy snapshot on Redis miss (finite catalog of base roles and tenant permissions) and verify miss + AVP allow writes `authz:{jti}` and returns `isAuthorized: true` with those roles
- [x] 4.2 On AVP deny, return `isAuthorized: false` and verify Redis has no allow snapshot for that `jti`
- [x] 4.3 Verify JWT failure paths never call Redis or AVP (test double / invocation count)

## 5. Authorizer handler

- [x] 5.1 Compose the hot path: verify JWT → `GET authz:{jti}` → hit/miss/sentinel → canned v2 JSON, using a `readonly struct` result, and verify end-to-end tests for hit, miss-allow, miss-deny, expired JWT, and revoked `jti`
- [x] 5.2 Ensure Gateway authorizer cache TTL 0 in IaC and verify the HTTP API authorizer resource sets result TTL to 0
- [x] 5.3 Add audit fields (decision, `sub`, `azp`) on allow/deny without per-request object graphs on the hit path, and verify a deny log contains `sub` when the JWT parsed

## 6. Update Roles Lambda

- [x] 6.1 Implement Update Roles: apply Cedar in AVP first, then `DEL authz:{jti}` for affected tokens, and verify order with a test that fails if Redis is deleted while AVP still returns the old snapshot
- [x] 6.2 Document that logout uses deny-sentinel (D5), not `DEL` + miss, and verify logout test matches 3.4
- [x] 6.3 Add an integration test that an allow snapshot is replaced within 1 second after Update Roles (AVP then `DEL`) and the next request hydrates new roles

## 7. Gateway and Lattice / Cloud Map (wiring)

- [x] 7.1 Define HTTP API custom request authorizer (`payloadFormatVersion: "2.0"`, simple responses, identity source `Authorization`) and verify deploy/template includes those settings
- [x] 7.2 After Allow is proven, attach VPC Lattice / Cloud Map private integration and parameter mapping for `sub` / `azp` / `roles`, and verify an allowed request is forwarded and a denied request is not
