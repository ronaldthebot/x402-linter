import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  runValidate,
  runLint,
  validatePaymentRequiredObject,
  validateFlowObject,
} from "../x402-linter.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const fixturesDir = path.join(__dirname, "..", "fixtures");

const fixture = name => path.join(fixturesDir, name);

test("valid v2 PAYMENT-REQUIRED fixture passes", async () => {
  const result = await runValidate(fixture("valid-v2-required.headers.json"), {
    kind: "payment-required",
  });
  assert.equal(result.result.ok, true);
  assert.equal(result.result.errors, 0);
});

test("invalid PAYMENT-REQUIRED fixture fails with ACCEPTS_MISSING", async () => {
  const result = await runValidate(fixture("invalid-required-missing-accepts.headers.json"), {
    kind: "payment-required",
  });
  assert.equal(result.result.ok, false);
  assert.ok(result.result.issues.some(issue => issue.code === "ACCEPTS_MISSING"));
});

test("valid v1 body fixture passes", async () => {
  const result = await runValidate(fixture("valid-v1-required.body.json"), {
    kind: "payment-required",
  });
  assert.equal(result.result.ok, true);
});

test("coinbase realistic flow fixture passes", async () => {
  const result = await runValidate(fixture("coinbase-weather-flow.json"), {
    kind: "flow",
  });
  assert.equal(result.result.ok, true);
});

test("price-only route config fixture passes", async () => {
  const result = await runLint(fixture("valid-config-price-only.routes.json"));
  assert.equal(result.result.ok, true);
});

test("invalid route config fixture fails", async () => {
  const result = await runLint(fixture("invalid-config.routes.json"));
  assert.equal(result.result.ok, false);
  assert.ok(result.result.issues.some(issue => issue.code === "PAYTO_MISSING"));
});

test("edge-case: malformed CAIP-2 network is rejected", () => {
  const result = validatePaymentRequiredObject({
    x402Version: 2,
    resource: {
      url: "https://api.example.com/paid",
      description: "Paid endpoint",
      mimeType: "application/json",
    },
    accepts: [
      {
        scheme: "exact",
        network: "base-mainnet",
        amount: "1000",
        asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
        payTo: "0x1111111111111111111111111111111111111111",
        maxTimeoutSeconds: 300,
      },
    ],
  });

  assert.equal(result.ok, false);
  assert.ok(result.issues.some(issue => issue.code === "NETWORK_INVALID"));
});

test("edge-case: flow network mismatch is caught", () => {
  const required = {
    x402Version: 2,
    resource: {
      url: "https://api.example.com/paid",
      description: "Paid endpoint",
      mimeType: "application/json",
    },
    accepts: [
      {
        scheme: "exact",
        network: "eip155:84532",
        amount: "1000",
        asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
        payTo: "0x1111111111111111111111111111111111111111",
        maxTimeoutSeconds: 300,
      },
    ],
  };

  const signature = {
    x402Version: 2,
    resource: required.resource,
    accepted: required.accepts[0],
    payload: { method: "eip3009", signature: "0xabc" },
  };

  const settle = {
    success: true,
    transaction: "0x1234",
    network: "eip155:8453"
  };

  const flow = {
    initialResponse: {
      status: 402,
      headers: {
        "PAYMENT-REQUIRED": Buffer.from(JSON.stringify(required)).toString("base64"),
      },
    },
    retryRequest: {
      headers: {
        "PAYMENT-SIGNATURE": Buffer.from(JSON.stringify(signature)).toString("base64"),
      },
    },
    finalResponse: {
      status: 200,
      headers: {
        "PAYMENT-RESPONSE": Buffer.from(JSON.stringify(settle)).toString("base64"),
      },
    },
  };

  const result = validateFlowObject(flow);
  assert.equal(result.ok, false);
  assert.ok(result.issues.some(issue => issue.code === "FLOW_NETWORK_MISMATCH"));
});
