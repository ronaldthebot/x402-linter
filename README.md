# x402-linter

OpenClaw skill for linting and validating x402 payment headers.

## What it does

`x402-linter` provides three commands:

1. `x402_validate` — validate URL/local headers against x402-oriented checks
2. `x402_lint` — lint a config/spec JSON for required fields and value validity
3. `x402_test` — run a built-in mock test suite for fast sanity checks

## Features

- SSRF protections for URL checks (blocks localhost + private network ranges)
- Sensitive header redaction by default
- JSON output mode (`--json`) for agent/tooling consumption
- Human-readable output by default
- HTTP timeout (default 5s) and response-size limits

## Install

```bash
npm install
```

## Usage

```bash
node cli.js x402_validate ./examples/sample-headers.json
node cli.js x402_validate https://api.example.com/protected --json
node cli.js x402_lint ./examples/sample-config.json
node cli.js x402_test --mock --json
```

## Example files

- `examples/sample-headers.json`
- `examples/sample-config.json`

## License

MIT
