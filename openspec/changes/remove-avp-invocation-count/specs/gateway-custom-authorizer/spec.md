## ADDED Requirements

### Requirement: AVP snapshot port is retrieval-only

The production AVP snapshot port MUST expose only snapshot retrieval for a verified identity (`sub`, authorized party). It MUST NOT expose invocation counters or other test-only call telemetry. Proof that AVP was or was not invoked MUST be provided by test doubles or other test-side instrumentation, not by the production port.

#### Scenario: Cache hit does not require a production call counter

- **WHEN** a verified JWT hits an allow snapshot in Redis
- **THEN** the authorizer returns `isAuthorized` true with those roles and does not call AVP, and the production snapshot port has no call-count field to consult

#### Scenario: Invalid JWT does not require a production call counter

- **WHEN** the Bearer token fails verification
- **THEN** AVP is not called, and the production snapshot port has no call-count field to consult
