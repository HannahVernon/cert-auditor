# Contributing to CertAuditor

Thanks for your interest in contributing.

## Prerequisites

- Windows Server 2016+ or Windows 10+ (CertAuditor uses the CAPI2 ETW provider, which is Windows-only)
- .NET Framework 4.8 SDK / Visual Studio 2022 (or `dotnet` CLI with the .NET Framework targeting pack)
- Administrator privileges are required to run `capture` locally, since ETW session creation is a privileged operation

## Branch Model

- `main` - release branch, protected
- `dev` - integration branch, protected
- `feature/xxx` / `fix/xxx` - work branches off `dev`

Open pull requests against `dev`, not `main`.

## Building

```
dotnet build CertAuditor.sln --configuration Release
```

## Testing

```
dotnet test CertAuditor.Tests\CertAuditor.Tests.csproj
```

All existing tests must continue to pass. Add tests for new behavior, especially around:

- `DurationParser` - duration string parsing edge cases
- `CertUsageEvent` - log line serialization/parsing round-trips
- `LogParser` - summary aggregation
- `EtwCaptureSession` - event filtering and XML parsing (mock ETW payloads where possible; avoid tests that require an elevated live CAPI2 session)

## Coding Standards

- Match the existing style (4-space indentation, braces on new lines, `PascalCase` for public members)
- Keep the `--events` allow-list (`EtwCaptureSession.AllowedEventIds`) as the single source of truth for supported CAPI2 event IDs
- Avoid catch-all `catch (Exception)` blocks except at top-level command boundaries; catch specific exception types
- New NuGet dependencies must be pinned to an exact version (`Version="[x.y.z]"`), and must be MIT/Apache-2.0 licensed unless discussed first. Update `THIRD-PARTY-NOTICES.md` when adding one.

## Pull Requests

- Keep PRs focused - one logical change per PR
- Fill out the PR template completely, including how you tested the change
- Update `README.md` / `ARCHITECTURE.md` if the change affects user-facing behavior or project structure
- CI must pass (`dotnet build`, `dotnet test`) before requesting review

## Reporting Bugs / Requesting Features

Use the issue templates provided in `.github/ISSUE_TEMPLATE/`. Security vulnerabilities should **not** be filed as public issues - see [SECURITY.md](SECURITY.md).
