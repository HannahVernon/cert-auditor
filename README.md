# CertAuditor

A Windows command-line tool that audits certificate usage by capturing real-time events from the CAPI2 ETW provider. It answers the question: **"Can I safely remove this certificate from the store?"**

By monitoring which certificates are actively accessed by applications and services, CertAuditor identifies unused certificates that can be safely removed — and flags those still in use.

## Requirements

- Windows Server 2016+ or Windows 10+ with .NET Framework 4.8
- **Administrator privileges** (required to create ETW trace sessions)

## Quick Start

### Capture certificate usage for 1 hour

```
CertAuditor.exe capture --log C:\logs\cert-audit.log --duration 1h
```

### Capture only a specific certificate

```
CertAuditor.exe capture --log C:\logs\cert-audit.log --thumbprint AB12CD34EF56 --duration 7d
```

### Allowed Event IDs

```
CertAuditor.exe capture --log audit.log --events 11,30,41,90 --duration 1h
```

### View a summary of captured events

```
CertAuditor.exe summarize --log C:\logs\cert-audit.log
```

### Export summary as CSV (tab-delimited)

```
CertAuditor.exe summarize --log C:\logs\cert-audit.log --format csv
```

## Commands

### `capture`

Starts a real-time ETW session subscribed to the CAPI2 provider. Writes one event per line to the log file in append mode. Runs until Ctrl+C is pressed or the optional `--duration` elapses.

Option | Description
-------|------------
`--log <path>` | **Required.** Path to the output log file (append mode).
`--duration <value>` | Auto-stop after the specified duration. Format: `<number><unit>` where unit is `s` (seconds), `m` (minutes), `h` (hours), or `d` (days). Examples: `30s`, `10m`, `1h`, `2d`.
`--store <name>` | Filter to a specific certificate store. Examples: `LocalMachine\My`, `CurrentUser\Root`.
`--thumbprint <list>` | Filter to specific certificate thumbprint(s). Comma-separated, case-insensitive.
`--events <list>` | Comma-separated list of CAPI2 event IDs to capture. Default: `11,30`.

### `summarize`

Parses a captured log file and displays a per-certificate usage summary including total event count, first/last seen timestamps, and which processes accessed each certificate.

Option | Description
-------|------------
`--log <path>` | **Required.** Path to the log file to summarize.
`--format <type>` | Output format: `table` (default) or `csv`.

## Allowed Event IDs

ID | Name | Description
---|------|------------
11 | BuildChain | Certificate chain validation — most detailed, includes full chain
30 | VerifyChainPolicy | Chain policy verification (Authenticode, Microsoft Root, etc.)
41 | VerifyRevocation | Revocation check result (CRL/OCSP) — includes cert and issuer
81 | VerifyTrust | Code signing trust verification
90 | X509Objects | Certificate objects loaded from store — full cert metadata

Event IDs 11 and 30 are the defaults and are the most reliable indicators that a certificate is being actively used for TLS, code signing, or other cryptographic operations.

## Log File Format

The log file is tab-delimited text with a header row:

```
Timestamp	EventId	Thumbprint	Subject	Issuer	StoreName	ProcessId	ProcessName	Result
```

Tab-delimited was chosen over CSV because certificate subjects can contain commas. The file is append-only, so multiple capture sessions accumulate in the same log file.

## Typical Workflow

1. **Identify candidates** — List certificates in `LocalMachine\My` that may be unused (expired, unknown purpose, etc.)
2. **Capture** — Run CertAuditor for a representative period (e.g., 7 days) to capture all certificate usage
3. **Summarize** — Review the summary to see which certificates were accessed and by which processes
4. **Decide** — Certificates that appear in the log are in active use. Certificates absent from the log for the entire capture period are candidates for removal.

### Recommended capture duration

Duration | Good for
---------|----------
1h | Quick smoke test — are any certs being used right now?
1d | Catches daily scheduled tasks and services
7d | Catches weekly jobs, backups, and periodic renewals
30d | Comprehensive audit before certificate store cleanup

## Security Considerations

- CertAuditor requires administrator privileges because ETW session creation is a privileged operation.
- The log file may contain certificate subjects, issuers, and thumbprints. While these are not secrets, they may reveal infrastructure details. Store log files with appropriate access controls.
- The ETW session name is `CertAuditor-CAPI2`. Only one instance of CertAuditor can run at a time.

## Dependencies

Package | Version | License
--------|---------|--------
Microsoft.Diagnostics.Tracing.TraceEvent | 3.1.16 (pinned) | MIT

## Building

```
dotnet build CertAuditor.sln --configuration Release
```

Output: `CertAuditor\bin\Release\net48\CertAuditor.exe`

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for build/test instructions, branch model, and coding standards. Please review the [Code of Conduct](CODE_OF_CONDUCT.md) before participating.

## Reporting Security Issues

See [SECURITY.md](SECURITY.md) for how to privately report a vulnerability.

## License

MIT - see [LICENSE](LICENSE). Third-party dependency licenses are listed in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
