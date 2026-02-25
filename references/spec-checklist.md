# x402 Lint Checklist (v1 + v2)

Use this checklist when extending or auditing the linter.

## Protocol surface covered

1. **`PAYMENT-REQUIRED` challenge**
   - Decodes base64 JSON header (v2)
   - Validates body-style object fallback (v1)
   - Checks `x402Version`, `accepts[]`, amount/maxAmountRequired, network format, payTo format, and resource metadata

2. **`PAYMENT-SIGNATURE` payload**
   - Decodes base64 JSON payload
   - Checks v2 (`resource`, `accepted`, `payload`) and v1 (`scheme`, `network`, `payload`) shapes

3. **`PAYMENT-RESPONSE` settlement**
   - Decodes base64 JSON payload
   - Checks `success`, `transaction`, and `network`

4. **Route config linting**
   - Checks route key shape (`METHOD /path`)
   - Ensures each route has non-empty `accepts[]`
   - Checks payment option fields (`scheme`, `network`, `payTo`, `price|amount`)
   - Emits UX warnings for missing `description` and `mimeType`

5. **End-to-end flow coherence**
   - Verifies accepted option in `PAYMENT-SIGNATURE` is present in `PAYMENT-REQUIRED`
   - Verifies settlement network matches accepted network

## Security checks

- SSRF protections on URL validation:
  - blocks localhost/loopback literals
  - blocks private RFC1918 IPv4 ranges
  - blocks DNS-resolved private/loopback targets
- Response timeout and byte cap for remote fetch mode
- Sensitive header redaction in output

## Out of scope (current)

- Cryptographic signature verification
- Facilitator API round-trip verification
- Chain state / on-chain settlement confirmation
- Formal JSON Schema compatibility tests against every upstream SDK release
