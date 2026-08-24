## 1. Production port

- [ ] 1.1 Remove `InvocationCount` from `IAvpSnapshotClient` and from `CatalogAvpSnapshotClient` (property and increment) and verify `src/` has no remaining `InvocationCount` references
- [ ] 1.2 Confirm `AuthorizerHost` still constructs `CatalogAvpSnapshotClient` against the slimmer interface and verify `dotnet build src/Caseware.GatewayAuthorizer` succeeds

## 2. Test doubles

- [ ] 2.1 Move `RecordingAvpClient` into `tests/Caseware.Authz.Tests` (or leave it in `src/` only if still referenced there) with `InvocationCount` on the **class**, not the interface, and verify pipeline tests compile against the class property
- [ ] 2.2 Add a test-only `CountingAvpClient` decorator that wraps `IAvpSnapshotClient`, increments a class-level count, then delegates, and verify catalog tests can wrap `CatalogAvpSnapshotClient`

## 3. Tests

- [ ] 3.1 Update `PipelineTests` so hit / JWT-failure / sentinel “AVP not called” and miss “called once” assertions use `RecordingAvpClient.InvocationCount` (not the interface) and verify those facts still pass
- [ ] 3.2 Update `AvpCatalogAndResilienceTests` catalog facts to wrap with `CountingAvpClient` (or drop the count assert if roles + Redis already prove the path) and verify JWT-failure / Redis-outage facts still assert `RecordingAvpClient.InvocationCount == 0`
- [ ] 3.3 Run `dotnet run --project tests/Caseware.Authz.Tests` and verify all tests pass with no `InvocationCount` on production AVP types
