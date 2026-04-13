# x402-linter

A CLI tool and OpenClaw skill for validating [x402](https://x402.org) payment protocol artifacts — headers, payloads, route configs, and complete 402→payment→200 flows.

x402 is the HTTP payment standard pioneered by Coinbase/CDP. It lets APIs require USDC payment before returning a response. If you're building or debugging an x402-enabled endpoint, this tool tells you exactly what's wrong with your headers and why.

## What it validates

- **`PAYMENT-REQUIRED` headers** — 402 responses from the server (v1 and v2 formats)
- **`PAYMENT-SIGNATURE` headers** — signed payment requests from the client
- **`PAYMENT-RESPONSE` headers** — confirmation headers on the 200 response
- **Route configs** — server-side x402 route definitions (`payTo`, `amount`, `asset`, `network`, `scheme`)
- **Full flows** — end-to-end 402→payment→200 sequences in one shot

## Install

```bash
git clone https://github.com/ronaldthebot/x402-linter.git
cd x402-linter
```

No dependencies. Node 20+ only.

## Quick start

```bash
# Validate a PAYMENT-REQUIRED header from a file
node scripts/x402-linter.mjs x402_validate scripts/fixtures/valid-v2-required.headers.json

# Validate a live endpoint
node scripts/x402-linter.mjs x402_validate https://api.example.com/protected

# Validate a full 402→payment→200 flow
node scripts/x402-linter.mjs x402_validate scripts/fixtures/coinbase-weather-flow.json --kind flow

# Lint a route config for missing or invalid fields
node scripts/x402-linter.mjs x402_lint scripts/fixtures/valid-config.routes.json

# Run the built-in test suite
node scripts/x402-linter.mjs x402_test
```

## Commands

### `x402_validate <file-or-url> [options]`

Validates a header payload or full flow against the x402 spec.

| Option | Default | Description |
|--------|---------|-------------|
| `--kind` | `auto` | `payment-required`, `payment-signature`, `payment-response`, `flow`, or `auto` |
| `--timeout` | `5000` | HTTP timeout in ms (URL mode) |
| `--max-bytes` | `262144` | Max response size in bytes |
| `--json` | off | Machine-readable JSON output |

Auto-detection reads the structure of the payload and picks the right validator. Use `--kind flow` for full end-to-end fixture files.

### `x402_lint <routes-file> [options]`

Lints a route config JSON. Checks `payTo`, `amount`, `asset`, `network`, `scheme`, `maxTimeoutSeconds`, and `accepts` arrays for correctness.

| Option | Default | Description |
|--------|---------|-------------|
| `--json` | off | Machine-readable JSON output |

### `x402_test`

Runs the built-in fixture test suite. Useful for sanity-checking the tool itself or as a CI step.

## Output

Human-readable by default:

```
✓ x402Version: 2
✓ error field present
✓ resource.url valid
✓ accepts[0].scheme: exact
✓ accepts[0].network: eip155:84532
✓ accepts[0].amount: 1000
✓ accepts[0].asset: valid EVM address
✓ accepts[0].payTo: valid EVM address
Result: VALID
```

JSON mode (`--json`) returns structured results for agent/pipeline consumption:

```json
{
  "valid": true,
  "kind": "payment-required",
  "version": 2,
  "issues": []
}
```

## Security

- SSRF protection: blocks `localhost`, `127.x`, `0.0.0.0`, `169.254.x`, and all RFC-1918 ranges when validating URLs
- Sensitive headers (`authorization`, `x-api-key`, `x-payment-token`, `cookie`) are redacted from output

## OpenClaw skill

This repo doubles as an OpenClaw agent skill. Install it via [ClawHub](https://clawhub.com) or drop the directory into your OpenClaw workspace.

```bash
clawhub install x402-linter
```

Once installed, your OpenClaw agent can call `x402_validate`, `x402_lint`, and `x402_test` directly.

## Fixtures

Test fixtures live in `scripts/fixtures/`. All wallet addresses and contract addresses in fixtures are placeholders (`0x1111...`, `0x2222...`) or public testnet contracts — no real credentials.

## License

MIT


Short aliases also work:

```bash
node scripts/x402-linter.mjs validate scripts/fixtures/valid-v2-required.headers.json
node scripts/x402-linter.mjs lint scripts/fixtures/valid-config.routes.json
node scripts/x402-linter.mjs test
```


Reviewer note: docs-only changes should stay small and explicit.
