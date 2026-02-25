---
name: x402-linter
description: Validate and lint x402 protocol artifacts (v1 and v2), including PAYMENT-REQUIRED / PAYMENT-SIGNATURE / PAYMENT-RESPONSE headers, route configs, and complete 402→payment→200 flows. Use when debugging x402 integration failures, auditing Coinbase/CDP-style payment handshakes, or verifying fixtures before deploying paid endpoints.
---

# x402-linter

Validate x402 payloads and route configs with deterministic local checks.

## Quick Start

```bash
node {baseDir}/scripts/x402-linter.mjs x402_validate {baseDir}/scripts/fixtures/valid-v2-required.headers.json
node {baseDir}/scripts/x402-linter.mjs x402_lint {baseDir}/scripts/fixtures/valid-config.routes.json
node {baseDir}/scripts/x402-linter.mjs x402_test
```

## Commands

### 1) Validate headers, payloads, or full flows

```bash
node {baseDir}/scripts/x402-linter.mjs x402_validate <url-or-file> [--kind auto|payment-required|payment-signature|payment-response|flow] [--timeout 5000] [--max-bytes 262144] [--json]
```

Notes:
- `--kind auto` detects payload type automatically.
- URL mode enforces SSRF guards (no localhost/private IPs).
- JSON output mode is recommended for agent pipelines.

### 2) Lint route configuration

```bash
node {baseDir}/scripts/x402-linter.mjs x402_lint <config.json> [--json]
```

Checks route key format, `accepts[]` completeness, and common UX metadata (`description`, `mimeType`).

### 3) Run fixture regression tests

```bash
node {baseDir}/scripts/x402-linter.mjs x402_test [--json]
```

Runs a fixed suite with valid + invalid fixtures, including a realistic Coinbase-style weather payment flow.

## Fixtures + References

- Fixtures: `{baseDir}/scripts/fixtures/`
- Test suite: `{baseDir}/scripts/tests/x402-linter.test.mjs`
- Spec checklist: `{baseDir}/references/spec-checklist.md`
