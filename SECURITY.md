# Security Policy

## Supported Versions

CertAuditor does not yet have tagged releases.  Security fixes are applied to the `main` branch and, where applicable, backported to `dev`.

## Reporting a Vulnerability

If you discover a security vulnerability in CertAuditor, please report it privately rather than opening a public issue.

**Preferred:** Use [GitHub's private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability) feature on this repository (Security tab -> Report a vulnerability).

**Alternative:** Email **vuln@mvct.com** with:

- A description of the vulnerability and its potential impact
- Steps to reproduce, including any proof-of-concept code
- The affected version or commit

## What to Expect

- We will acknowledge your report as soon as reasonably possible.
- We will investigate and keep you informed of progress toward a fix.
- We will credit reporters in the release notes unless you prefer to remain anonymous.

## Scope

CertAuditor requires administrator privileges to create ETW trace sessions and writes certificate metadata (thumbprints, subjects, issuers, process names) to a log file.  Security reports involving log file access control, ETW session handling, or XML parsing of CAPI2 event payloads are all in scope.
