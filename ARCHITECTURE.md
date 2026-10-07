# Architecture

## Overview

CertAuditor is a .NET Framework 4.8 console application that subscribes to Windows CAPI2 ETW events in real time to audit certificate usage. It has two modes: **capture** (live ETW monitoring) and **summarize** (log file analysis).

## File Tree

```
C:\Dev\cert-auditor\
├── CertAuditor.sln - Visual Studio solution file
├── README.md - User-facing documentation
├── ARCHITECTURE.md - This file
└── CertAuditor\
    ├── CertAuditor.csproj - SDK-style project targeting net48
    ├── Program.cs - Entry point, CLI parsing, verb dispatch
    ├── EtwCaptureSession.cs - CAPI2 ETW subscription and event parsing
    ├── LogParser.cs - Log file reader and summary aggregation
    ├── CertUsageEvent.cs - POCO for a single certificate-usage event
    ├── SeenCertificate.cs - POCO for a certificate seen during a capture run (thumbprint/subject/count)
    ├── CertificateStoreLookup.cs - Looks up a certificate's validity period from the Windows certificate stores by thumbprint
    ├── SeenCertificateReport.cs - Prints the end-of-run "certificates seen" table
    ├── DurationParser.cs - Parses shorthand durations (10m, 1h, 2d)
    └── ConsoleHelpers.cs - Ctrl+C handling, elevation check, console output
```

## Component Responsibilities

### Program.cs

Entry point. Parses command-line arguments into a verb (`capture` or `summarize`) and a dictionary of options. Validates required arguments, enforces the allowed event ID whitelist, and dispatches to the appropriate handler. Prints usage/help text.

### EtwCaptureSession.cs

Core capture logic. Creates a `TraceEventSession` (from the `Microsoft.Diagnostics.Tracing.TraceEvent` library) subscribed to the CAPI2 ETW provider by GUID (`5BBCA4A8-B209-48DC-A8C7-B23D3E5216FB`).

Responsibilities:
- Creates and manages the ETW session lifecycle
- Filters events by event ID, store name, and thumbprint
- Parses event payloads (XML fragments) to extract certificate details
- Writes `CertUsageEvent` records to the log file in append mode
- Tracks a running tally of distinct certificates seen (by thumbprint), for the end-of-run summary
- Handles graceful shutdown via cancellation token
- After the run ends (Ctrl+C or `--duration` elapses), prints a "certificates seen" table via `SeenCertificateReport`

### CertUsageEvent.cs

Data transfer object representing one captured event. Provides:
- `ToLogLine()` - serializes to tab-delimited format
- `Parse(string)` - deserializes from tab-delimited format
- `SanitizeField(string)` - strips tabs/newlines from field values to prevent log corruption

### SeenCertificate.cs

Lightweight POCO tracked in memory during a capture run: `Thumbprint`, `Subject`, and `Count` (how many matching events were seen for that thumbprint). Distinct from `LogParser.CertSummary`, which is derived later from the saved log file and carries richer fields (issuer, first/last seen, processes).

### CertificateStoreLookup.cs

Looks up a certificate's validity period (`NotBefore`/`NotAfter`) by thumbprint. CAPI2 ETW events don't carry validity dates in their payload, so this re-reads the actual certificate from wherever it's installed. Checks the `--store` filter first (if one was given), then falls back to a list of commonly used stores (`LocalMachine\My`, `LocalMachine\Root`, etc.). Returns `null` if the certificate can no longer be found in any store searched (e.g., it was removed after being observed).

### SeenCertificateReport.cs

Prints the table of certificates seen during a capture run (thumbprint, subject, valid from/to, count), ordered by count descending. The validity lookup is an injectable delegate (defaulting to `CertificateStoreLookup.TryGetValidity`) so the table-formatting logic can be unit tested without depending on real certificate stores.

### LogParser.cs

Reads a tab-delimited log file produced by capture mode. Aggregates events by certificate thumbprint into `CertSummary` records (count, first/last seen, distinct processes). Outputs as either an aligned console table or tab-delimited CSV.

### DurationParser.cs

Converts human-friendly duration strings (`30s`, `10m`, `1h`, `2d`) into `TimeSpan` values using a compiled regex. Only single-unit values are supported (no `1h30m` combinations).

### ConsoleHelpers.cs

Utility class providing:
- Ctrl+C handler that triggers a `CancellationToken`
- Administrator privilege check via `WindowsPrincipal.IsInRole`
- Standardized error/info output to `stderr`

## Data Flow

### Capture Mode

```
CAPI2 ETW Provider (crypt32.dll)
        │
        ▼
TraceEventSession (real-time subscription)
        │
        ▼
EtwCaptureSession.OnEvent()
  ├── Filter by event ID whitelist
  ├── Parse XML payload → CertUsageEvent
  ├── Filter by --store (if specified)
  ├── Filter by --thumbprint (if specified)
  ├── Write CertUsageEvent.ToLogLine() → log file
  └── Tally into in-memory SeenCertificate dictionary (by thumbprint)
        │
        ▼  (on Ctrl+C or --duration elapsed)
SeenCertificateReport.WriteTable()
  ├── CertificateStoreLookup.TryGetValidity() per thumbprint
  └── Print thumbprint/subject/valid-from/valid-to/count table → stdout
```

### Summarize Mode

```
Log file (tab-delimited)
        │
        ▼
LogParser.Summarize()
  ├── Read each line → CertUsageEvent.Parse()
  ├── Aggregate by thumbprint → CertSummary
  └── Output table or CSV → stdout
```

## ETW Details

- **Provider:** Microsoft-Windows-CAPI2 (`{5BBCA4A8-B209-48DC-A8C7-B23D3E5216FB}`)
- **Provider type:** Manifest-based (confirmed - supports up to 8 concurrent ETW sessions)
- **Session name:** `CertAuditor-CAPI2`
- **Manifest location:** `%SystemRoot%\System32\crypt32.dll`

### Event Payload Parsing

CAPI2 events use a single payload field called `EventWriteData` containing an XML string. The XML structure varies by event ID but follows common patterns:

- **Thumbprint**: `fileRef` attribute on `<Certificate>` elements (format: `THUMBPRINT.cer`)
- **Subject**: `subjectName` attribute on `<Certificate>` elements
- **Issuer**: `<Issuer><CN>...</CN></Issuer>` child elements, or `<IssuerCertificate subjectName="..."/>` elements
- **Process**: `<EventAuxInfo ProcessName="..."/>` attribute
- **Result**: `<Result value="..."/>` attribute

The parser extracts the first `<Certificate>` element found (the leaf/end-entity cert) from the XML payload.

## Dependencies

Package | Version | Purpose
--------|---------|--------
Microsoft.Diagnostics.Tracing.TraceEvent | 3.1.16 (pinned) | ETW session management and event consumption

The version is pinned in the `.csproj` via `Version="[3.1.16]"` to prevent silent upgrades and ensure reproducible builds.
