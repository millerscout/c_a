## Why

`InvocationCount` sits on the production AVP snapshot port (`IAvpSnapshotClient`) and on `CatalogAvpSnapshotClient`. That is test instrumentation in the live authorizer surface: it mutates on every miss, is unused in Lambda, and makes “did we call AVP?” look like a product API. Tests still need to prove JWT failure and cache hits never touch AVP; that proof belongs on a test double, not on the production contract.

## What Changes

- **BREAKING** (internal): remove `InvocationCount` from `IAvpSnapshotClient`.
- Remove the incrementing counter from `CatalogAvpSnapshotClient` (production catalog/miss client).
- Keep call counting only on test types (`RecordingAvpClient` and/or a test-only decorator wrapping the catalog client).
- Update pipeline and catalog tests so “AVP not called” / “AVP called once” assertions use those test types.

## Capabilities

### New Capabilities

- None.

### Modified Capabilities

- `gateway-custom-authorizer`: the AVP snapshot port is snapshot retrieval only; call-count telemetry is not part of the production contract. Authorizer HTTP behavior (crypto first, hit skips AVP, miss hydrates) is unchanged.

## Impact

- `src/Caseware.Authz/Avp/` (`IAvpSnapshotClient`, `CatalogAvpSnapshotClient`, `RecordingAvpClient`).
- Tests in `tests/Caseware.Authz.Tests/` that read `InvocationCount` (`PipelineTests`, `AvpCatalogAndResilienceTests`).
- No change to Redis keys, JWT verify, HTTP API v2 body, SAM, or Gateway TTL.
- Out of scope: `IAuthzCache.GetCalls` / `SetCalls` / `DeleteCalls` (same smell, separate change).
