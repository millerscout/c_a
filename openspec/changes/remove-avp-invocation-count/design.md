## Context

See proposal.md. Today `IAvpSnapshotClient` requires `InvocationCount`; both `CatalogAvpSnapshotClient` (wired in the Lambda host) and `RecordingAvpClient` implement it. Tests in `PipelineTests` and `AvpCatalogAndResilienceTests` assert 0 vs 1 against that property. Authorizer control flow already skips AVP on JWT failure, cache hit, and deny-sentinel; the counter is not used at runtime.

## Goals / Non-Goals

**Goals:**

- Production AVP port is `GetSnapshotAsync` only.
- Tests still assert “not called” / “called once” without mutating production types.
- Catalog client stays allocation-light on the miss path (no unused increment).

**Non-Goals:**

- Stripping `GetCalls` / `SetCalls` / `DeleteCalls` from `IAuthzCache`.
- Replacing the catalog client with AWSSDK.VerifiedPermissions.
- Changing hit/miss/sentinel semantics.

## Decisions

### D1 — Drop `InvocationCount` from `IAvpSnapshotClient`

The port is a collaborator for the miss path, not a metrics API. CloudWatch/audit already cover operational visibility.

**Alternative:** keep the property but `[Obsolete]` it — still ships test state in Lambda.

### D2 — Count only in the test assembly

- Keep `RecordingAvpClient` as a test double with its own `InvocationCount` (or `CallCount`) **on the class**, not the interface. Prefer moving it from `src/Caseware.Authz` into `tests/Caseware.Authz.Tests` if nothing in `src/` constructs it.
- For catalog tests that need both real catalog behavior and a call count, wrap `CatalogAvpSnapshotClient` with a test-only decorator (`CountingAvpClient`) that increments then delegates.

**Alternative:** `CallbackAvpClient` / mock library — heavier than a 10-line decorator; this repo already uses hand-rolled doubles.

### D3 — Do not add metrics on the production client “for later”

If miss-path volume is needed in Lambda, emit an existing audit/log field on miss, not a public integer on the interface. Out of this change.

## Risks / Trade-offs

- [Tests compile-break until assertions move] → same PR updates tests; run `dotnet run --project tests/Caseware.Authz.Tests`.
- [Someone uses `IAvpSnapshotClient.InvocationCount` outside this repo] → internal library; no published package.
- [Decorator forgotten on a catalog test] → catalog allow/deny tests still assert roles and Redis; call-count tests that need a wrapper are explicit.

## Migration Plan

In-tree only. Remove the interface member, stop incrementing in `CatalogAvpSnapshotClient`, relocate/keep counting on test types, run the existing 27 tests. No deploy flag. Rollback is revert of the PR.

## Open Questions

None.
