# Security Policy

Logatory is a local-first log analysis tool. By default no log data leaves the
machine it runs on, and personally identifiable information is redacted
directly after parsing.

## Supported versions

Logatory is in early development (`0.1.x`, alpha). Security fixes are applied to
the latest state of `master`.

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅        |
| < 0.1   | ❌        |

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, use GitHub's private vulnerability reporting:

1. Open the [Security tab](https://github.com/T0nd3/logatory/security) of the
   repository.
2. Click **Report a vulnerability**.
3. Include a description, steps to reproduce, and the affected version.

You will get an acknowledgement as soon as possible (best effort — Logatory is
currently maintained by a single developer). Please allow reasonable time for a
fix before any public disclosure.

## Scope

Security-relevant areas include, but are not limited to:

- **PII redaction bypasses** — log data that should have been redacted reaching
  storage, the LLM layer, or API responses.
- **REST API authentication bypasses.**
- **Path traversal or injection** via log file paths, rule files, or plugins.
- Unexpected behaviour in the plugin loader.

Note that the plugin system **executes Python files** from the configured
plugin directory by design — only point it at directories you trust. This is
expected behaviour, not a vulnerability.
