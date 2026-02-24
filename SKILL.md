---
name: x402-linter
description: Lint and validate x402 payment headers/configs for APIs. Use for x402 compliance checks, header validation, and quick mock testing with safe defaults.
metadata: {"openclaw":{"emoji":"💸","requires":{"bins":["node"]}}}
---

# x402-linter

Validate and lint x402 payment metadata with safe defaults for agent use.

## Install

```bash
clawhub install x402-linter
```

or locally:

```bash
cd {baseDir}
npm install
```

## Commands

### `x402_validate`
Validate URL response headers or local header files.

**Usage**
```bash
node {baseDir}/cli.js x402_validate <url-or-file> [--json] [--timeout 5000] [--max-bytes 262144]
```

**Examples**
```bash
node {baseDir}/cli.js x402_validate https://api.example.com/protected
node {baseDir}/cli.js x402_validate ./examples/sample-headers.json --json
```

### `x402_lint`
Lint x402 config/spec JSON for required fields and value sanity.

**Usage**
```bash
node {baseDir}/cli.js x402_lint <config.json> [--json]
```

**Examples**
```bash
node {baseDir}/cli.js x402_lint ./examples/sample-config.json
node {baseDir}/cli.js x402_lint ./examples/sample-config.json --json
```

### `x402_test`
Run mock internal test cases to verify the validator/linter behavior.

**Usage**
```bash
node {baseDir}/cli.js x402_test [--mock] [--json]
```

## Safety Notes

- SSRF protections block localhost, loopback, and private RFC1918 ranges by default.
- Sensitive headers (`Authorization`, `X-Payment-Token`, cookies, API keys) are redacted from output.
- HTTP requests use a 5s default timeout and response-size limits.
- Prefer `--json` for agent pipelines and machine-readable checks.
