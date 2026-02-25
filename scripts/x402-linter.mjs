#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import net from "node:net";
import dns from "node:dns/promises";
import process from "node:process";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const DEFAULT_TIMEOUT_MS = 5000;
const DEFAULT_MAX_BYTES = 256 * 1024;

const STRICT_BASE64_REGEX = /^[A-Za-z0-9+/]+={0,2}$/;
const RELAXED_BASE64_REGEX = /^[A-Za-z0-9+/_-]+={0,2}$/;
const CAIP2_REGEX = /^[a-z0-9]+:[A-Za-z0-9._-]+$/;
const MIME_REGEX = /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/i;
const EVM_ADDRESS_REGEX = /^0x[a-fA-F0-9]{40}$/;
const SOLANA_ADDRESS_REGEX = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;

const SENSITIVE_HEADERS = new Set([
  "authorization",
  "proxy-authorization",
  "x-api-key",
  "x-payment-token",
  "cookie",
  "set-cookie",
]);

const COMMAND_ALIASES = new Map([
  ["validate", "x402_validate"],
  ["lint", "x402_lint"],
  ["test", "x402_test"],
]);

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token.startsWith("--")) {
      args._.push(token);
      continue;
    }
    const raw = token.slice(2);
    if (raw.includes("=")) {
      const [key, value] = raw.split(/=(.*)/s, 2);
      args[key] = value;
      continue;
    }
    const next = argv[i + 1];
    if (next && !next.startsWith("--")) {
      args[raw] = next;
      i += 1;
    } else {
      args[raw] = true;
    }
  }
  return args;
}

function normalizeCommand(command) {
  if (!command) return command;
  return COMMAND_ALIASES.get(command) || command;
}

function mkIssue(level, code, message, where = "") {
  return { level, code, message, where };
}

function summarizeIssues(issues) {
  const errors = issues.filter(issue => issue.level === "error").length;
  const warnings = issues.filter(issue => issue.level === "warning").length;
  return { errors, warnings, ok: errors === 0 };
}

function isObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function toInt(value) {
  if (typeof value === "number" && Number.isInteger(value)) return value;
  if (typeof value === "string" && /^\d+$/.test(value)) return Number(value);
  return Number.NaN;
}

function parseMaybeJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function parseHeaderLines(raw) {
  const headers = {};
  const lines = raw.split(/\r?\n/);
  for (const line of lines) {
    const idx = line.indexOf(":");
    if (idx <= 0) continue;
    const key = line.slice(0, idx).trim();
    const value = line.slice(idx + 1).trim();
    headers[key] = value;
  }
  return headers;
}

function normalizeHeaders(headerMap = {}) {
  const normalized = {};
  for (const [key, value] of Object.entries(headerMap)) {
    normalized[String(key).toLowerCase()] = String(value);
  }
  return normalized;
}

function redactHeaders(headerMap = {}) {
  const redacted = {};
  for (const [key, value] of Object.entries(headerMap)) {
    redacted[key] = SENSITIVE_HEADERS.has(key.toLowerCase()) ? "[REDACTED]" : value;
  }
  return redacted;
}

function isPrivateIPv4(ip) {
  const octets = ip.split(".").map(Number);
  if (octets.length !== 4 || octets.some(Number.isNaN)) return false;
  if (octets[0] === 10) return true;
  if (octets[0] === 127) return true;
  if (octets[0] === 192 && octets[1] === 168) return true;
  if (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) return true;
  if (octets[0] === 169 && octets[1] === 254) return true;
  return false;
}

function isPrivateIPv6(ip) {
  const normalized = String(ip || "").toLowerCase().split("%")[0];
  if (normalized === "::1") return true; // loopback

  // IPv4-mapped IPv6, e.g. ::ffff:127.0.0.1
  const mapped = normalized.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  if (mapped && isPrivateIPv4(mapped[1])) return true;

  // Unique local addresses (fc00::/7)
  if (/^fc[0-9a-f]|^fd[0-9a-f]/i.test(normalized)) return true;

  // Link-local (fe80::/10)
  if (/^fe[89ab][0-9a-f]:/i.test(normalized)) return true;

  return false;
}

function isBlockedHostLiteral(hostname) {
  const host = String(hostname || "").toLowerCase();
  const unwrapped = host.replace(/^\[/, "").replace(/\]$/, "");
  if (unwrapped === "localhost") return true;
  if (net.isIP(unwrapped) === 4) return isPrivateIPv4(unwrapped);
  if (net.isIP(unwrapped) === 6) return isPrivateIPv6(unwrapped);
  return false;
}

async function assertSafeUrl(rawUrl) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error(`Invalid URL: ${rawUrl}`);
  }
  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("Only http/https URLs are allowed.");
  }
  if (isBlockedHostLiteral(parsed.hostname)) {
    throw new Error(`Blocked by SSRF policy: ${parsed.hostname}`);
  }
  const records = await dns.lookup(parsed.hostname, { all: true });
  for (const record of records) {
    if (record.family === 4 && isPrivateIPv4(record.address)) {
      throw new Error(
        `Blocked by SSRF policy (resolved private IPv4): ${parsed.hostname} -> ${record.address}`,
      );
    }
    if (record.family === 6 && isPrivateIPv6(record.address)) {
      throw new Error(
        `Blocked by SSRF policy (resolved private/loopback IPv6): ${parsed.hostname} -> ${record.address}`,
      );
    }
  }
  return parsed;
}

function decodeBase64Json(headerName, value, issues, where) {
  if (typeof value !== "string" || value.trim() === "") {
    issues.push(mkIssue("error", "MISSING_HEADER_VALUE", `${headerName} is missing or empty`, where));
    return null;
  }

  const trimmed = value.trim();
  if (!RELAXED_BASE64_REGEX.test(trimmed)) {
    issues.push(mkIssue("error", "INVALID_BASE64", `${headerName} is not valid base64`, where));
    return null;
  }

  let normalized = trimmed;
  if (!STRICT_BASE64_REGEX.test(trimmed)) {
    issues.push(
      mkIssue(
        "warning",
        "BASE64URL_VARIANT",
        `${headerName} uses URL-safe base64 characters (-/_); normalized before decode`,
        where,
      ),
    );
    normalized = normalized.replace(/-/g, "+").replace(/_/g, "/");
  }

  let decoded;
  try {
    decoded = Buffer.from(normalized, "base64").toString("utf8");
  } catch {
    issues.push(mkIssue("error", "BASE64_DECODE_FAILED", `${headerName} could not be base64-decoded`, where));
    return null;
  }

  const parsed = parseMaybeJson(decoded);
  if (!isObject(parsed)) {
    issues.push(mkIssue("error", "DECODED_JSON_INVALID", `${headerName} did not decode to a JSON object`, where));
    return null;
  }

  return parsed;
}

function validateResource(resource, issues, where) {
  if (!isObject(resource)) {
    issues.push(mkIssue("error", "RESOURCE_MISSING", "resource must be an object", where));
    return;
  }

  if (typeof resource.url !== "string" || resource.url.trim() === "") {
    issues.push(mkIssue("error", "RESOURCE_URL_MISSING", "resource.url is required", `${where}.url`));
  } else {
    try {
      const parsed = new URL(resource.url);
      if (!["http:", "https:"].includes(parsed.protocol)) {
        issues.push(
          mkIssue(
            "warning",
            "RESOURCE_URL_PROTOCOL",
            "resource.url is non-http(s); some clients may reject it",
            `${where}.url`,
          ),
        );
      }
    } catch {
      issues.push(mkIssue("error", "RESOURCE_URL_INVALID", "resource.url is not a valid URL", `${where}.url`));
    }
  }

  if (typeof resource.description !== "string" || resource.description.trim() === "") {
    issues.push(
      mkIssue(
        "warning",
        "RESOURCE_DESCRIPTION_MISSING",
        "resource.description is missing (recommended for marketplace/discovery UX)",
        `${where}.description`,
      ),
    );
  }

  if (typeof resource.mimeType !== "string" || resource.mimeType.trim() === "") {
    issues.push(
      mkIssue(
        "warning",
        "RESOURCE_MIMETYPE_MISSING",
        "resource.mimeType is missing (recommended)",
        `${where}.mimeType`,
      ),
    );
  } else if (!MIME_REGEX.test(resource.mimeType)) {
    issues.push(
      mkIssue(
        "warning",
        "RESOURCE_MIMETYPE_INVALID",
        `resource.mimeType looks invalid: ${resource.mimeType}`,
        `${where}.mimeType`,
      ),
    );
  }
}

function validateRequirement(requirement, issues, where, version = 2, options = {}) {
  const { requireAmount = true } = options;
  if (!isObject(requirement)) {
    issues.push(mkIssue("error", "ACCEPT_INVALID", "accept entry must be an object", where));
    return;
  }

  if (typeof requirement.scheme !== "string" || requirement.scheme.trim() === "") {
    issues.push(mkIssue("error", "SCHEME_MISSING", "scheme is required", `${where}.scheme`));
  } else if (!["exact", "upto"].includes(requirement.scheme)) {
    issues.push(
      mkIssue(
        "warning",
        "SCHEME_UNCOMMON",
        `scheme '${requirement.scheme}' is not one of commonly-seen values (exact, upto)`,
        `${where}.scheme`,
      ),
    );
  }

  const network = requirement.network;
  if (typeof network !== "string" || network.trim() === "") {
    issues.push(mkIssue("error", "NETWORK_MISSING", "network is required", `${where}.network`));
  } else if (!CAIP2_REGEX.test(network)) {
    issues.push(
      mkIssue(
        "error",
        "NETWORK_INVALID",
        `network must look like CAIP-2 (<namespace>:<reference>), got: ${network}`,
        `${where}.network`,
      ),
    );
  }

  if (version === 2) {
    const amountIsPresent = requirement.amount !== undefined && requirement.amount !== null;
    if (requireAmount && !amountIsPresent) {
      issues.push(
        mkIssue(
          "error",
          "AMOUNT_MISSING",
          "amount is required for this payload and must be an atomic-unit integer string",
          `${where}.amount`,
        ),
      );
    }
    if (amountIsPresent) {
      if (typeof requirement.amount !== "string" || !/^\d+$/.test(requirement.amount)) {
        issues.push(
          mkIssue(
            "error",
            "AMOUNT_INVALID",
            "amount must be a positive integer string (atomic units)",
            `${where}.amount`,
          ),
        );
      } else if (Number(requirement.amount) <= 0) {
        issues.push(mkIssue("error", "AMOUNT_NON_POSITIVE", "amount must be > 0", `${where}.amount`));
      }
    }
  } else {
    if (typeof requirement.maxAmountRequired !== "string" || !/^\d+$/.test(requirement.maxAmountRequired)) {
      issues.push(
        mkIssue(
          "error",
          "MAX_AMOUNT_INVALID",
          "maxAmountRequired must be a positive integer string (v1)",
          `${where}.maxAmountRequired`,
        ),
      );
    } else if (Number(requirement.maxAmountRequired) <= 0) {
      issues.push(
        mkIssue("error", "MAX_AMOUNT_NON_POSITIVE", "maxAmountRequired must be > 0", `${where}.maxAmountRequired`),
      );
    }
  }

  if (typeof requirement.asset !== "string" || requirement.asset.trim() === "") {
    issues.push(mkIssue("warning", "ASSET_MISSING", "asset is missing", `${where}.asset`));
  }

  if (typeof requirement.payTo !== "string" || requirement.payTo.trim() === "") {
    issues.push(mkIssue("error", "PAYTO_MISSING", "payTo is required", `${where}.payTo`));
  } else if (typeof network === "string") {
    if (network.startsWith("eip155:") && !EVM_ADDRESS_REGEX.test(requirement.payTo)) {
      issues.push(
        mkIssue(
          "warning",
          "PAYTO_EVM_FORMAT",
          "payTo does not look like an EVM address for an eip155 network",
          `${where}.payTo`,
        ),
      );
    }
    if (network.startsWith("solana:") && !SOLANA_ADDRESS_REGEX.test(requirement.payTo)) {
      issues.push(
        mkIssue(
          "warning",
          "PAYTO_SOLANA_FORMAT",
          "payTo does not look like a Solana base58 address for a solana network",
          `${where}.payTo`,
        ),
      );
    }
  }

  if (requirement.maxTimeoutSeconds !== undefined) {
    const timeout = toInt(requirement.maxTimeoutSeconds);
    if (!Number.isInteger(timeout) || timeout <= 0) {
      issues.push(
        mkIssue(
          "warning",
          "TIMEOUT_INVALID",
          "maxTimeoutSeconds should be a positive integer",
          `${where}.maxTimeoutSeconds`,
        ),
      );
    }
  }

  if (version === 1) {
    if (typeof requirement.resource !== "string" || requirement.resource.trim() === "") {
      issues.push(
        mkIssue(
          "warning",
          "V1_RESOURCE_MISSING",
          "v1 requirement should include resource URL",
          `${where}.resource`,
        ),
      );
    }
    if (typeof requirement.mimeType !== "string" || requirement.mimeType.trim() === "") {
      issues.push(
        mkIssue(
          "warning",
          "V1_MIMETYPE_MISSING",
          "v1 requirement should include mimeType",
          `${where}.mimeType`,
        ),
      );
    }
  }
}

export function validatePaymentRequiredObject(input) {
  const issues = [];

  if (!isObject(input)) {
    issues.push(mkIssue("error", "REQUIRED_NOT_OBJECT", "payment-required payload must be an object"));
    return { ...summarizeIssues(issues), issues, kind: "payment-required" };
  }

  const version = toInt(input.x402Version);
  if (!Number.isInteger(version)) {
    issues.push(mkIssue("error", "VERSION_MISSING", "x402Version is required and must be an integer", "x402Version"));
  } else if (![1, 2].includes(version)) {
    issues.push(mkIssue("error", "VERSION_UNSUPPORTED", `Unsupported x402Version: ${input.x402Version}`, "x402Version"));
  }

  if (!Array.isArray(input.accepts) || input.accepts.length === 0) {
    issues.push(mkIssue("error", "ACCEPTS_MISSING", "accepts must be a non-empty array", "accepts"));
  } else {
    const v = Number.isInteger(version) ? version : 2;
    input.accepts.forEach((entry, index) => {
      validateRequirement(entry, issues, `accepts[${index}]`, v);
    });
  }

  if (version === 2) {
    validateResource(input.resource, issues, "resource");
  }

  if (version === 1 && input.resource !== undefined) {
    issues.push(
      mkIssue(
        "warning",
        "V1_TOP_LEVEL_RESOURCE",
        "v1 payload usually carries resource info inside each requirement, not top-level",
        "resource",
      ),
    );
  }

  return { ...summarizeIssues(issues), issues, kind: "payment-required", x402Version: version };
}

export function validatePaymentSignatureObject(input) {
  const issues = [];

  if (!isObject(input)) {
    issues.push(mkIssue("error", "SIGNATURE_NOT_OBJECT", "payment-signature payload must be an object"));
    return { ...summarizeIssues(issues), issues, kind: "payment-signature" };
  }

  const version = toInt(input.x402Version);
  if (!Number.isInteger(version)) {
    issues.push(mkIssue("error", "VERSION_MISSING", "x402Version is required and must be an integer", "x402Version"));
  }

  if (version === 2) {
    validateResource(input.resource, issues, "resource");
    validateRequirement(input.accepted, issues, "accepted", 2);
    if (!isObject(input.payload)) {
      issues.push(mkIssue("error", "PAYLOAD_MISSING", "payload must be an object", "payload"));
    }
  } else if (version === 1) {
    if (typeof input.scheme !== "string" || input.scheme.trim() === "") {
      issues.push(mkIssue("error", "SCHEME_MISSING", "v1 payment payload requires scheme", "scheme"));
    }
    if (typeof input.network !== "string" || !CAIP2_REGEX.test(input.network)) {
      issues.push(mkIssue("error", "NETWORK_INVALID", "v1 payment payload requires CAIP-2 network", "network"));
    }
    if (!isObject(input.payload)) {
      issues.push(mkIssue("error", "PAYLOAD_MISSING", "payload must be an object", "payload"));
    }
  } else if (Number.isInteger(version)) {
    issues.push(mkIssue("error", "VERSION_UNSUPPORTED", `Unsupported x402Version: ${input.x402Version}`, "x402Version"));
  }

  return { ...summarizeIssues(issues), issues, kind: "payment-signature", x402Version: version };
}

export function validatePaymentResponseObject(input) {
  const issues = [];

  if (!isObject(input)) {
    issues.push(mkIssue("error", "RESPONSE_NOT_OBJECT", "payment-response payload must be an object"));
    return { ...summarizeIssues(issues), issues, kind: "payment-response" };
  }

  if (typeof input.success !== "boolean") {
    issues.push(mkIssue("error", "SUCCESS_MISSING", "success must be a boolean", "success"));
  }

  if (typeof input.transaction !== "string" || input.transaction.trim() === "") {
    issues.push(mkIssue("error", "TRANSACTION_MISSING", "transaction is required", "transaction"));
  }

  if (typeof input.network !== "string" || !CAIP2_REGEX.test(input.network)) {
    issues.push(mkIssue("error", "NETWORK_INVALID", "network must be CAIP-2 format", "network"));
  }

  if (input.success === false && !input.errorReason) {
    issues.push(
      mkIssue(
        "warning",
        "ERROR_REASON_MISSING",
        "success=false without errorReason makes incident triage harder",
        "errorReason",
      ),
    );
  }

  return { ...summarizeIssues(issues), issues, kind: "payment-response" };
}

function requirementIdentity(requirement) {
  if (!isObject(requirement)) return "";
  const major = {
    scheme: requirement.scheme,
    network: requirement.network,
    asset: requirement.asset,
    payTo: requirement.payTo,
    amount: requirement.amount,
    maxAmountRequired: requirement.maxAmountRequired,
  };
  return JSON.stringify(major);
}

export function validateFlowObject(input) {
  const issues = [];

  if (!isObject(input)) {
    issues.push(mkIssue("error", "FLOW_NOT_OBJECT", "flow payload must be an object"));
    return { ...summarizeIssues(issues), issues, kind: "flow" };
  }

  const initialHeaders = normalizeHeaders(input.initialResponse?.headers || {});
  const retryHeaders = normalizeHeaders(input.retryRequest?.headers || {});
  const finalHeaders = normalizeHeaders(input.finalResponse?.headers || {});

  const requiredObj = decodeBase64Json(
    "PAYMENT-REQUIRED",
    initialHeaders["payment-required"],
    issues,
    "initialResponse.headers.PAYMENT-REQUIRED",
  );
  const signatureObj = decodeBase64Json(
    "PAYMENT-SIGNATURE",
    retryHeaders["payment-signature"] || retryHeaders["x-payment"],
    issues,
    "retryRequest.headers.PAYMENT-SIGNATURE",
  );
  const responseObj = decodeBase64Json(
    "PAYMENT-RESPONSE",
    finalHeaders["payment-response"] || finalHeaders["x-payment-response"],
    issues,
    "finalResponse.headers.PAYMENT-RESPONSE",
  );

  const requiredResult = requiredObj ? validatePaymentRequiredObject(requiredObj) : null;
  const signatureResult = signatureObj ? validatePaymentSignatureObject(signatureObj) : null;
  const responseResult = responseObj ? validatePaymentResponseObject(responseObj) : null;

  if (requiredResult) issues.push(...requiredResult.issues);
  if (signatureResult) issues.push(...signatureResult.issues);
  if (responseResult) issues.push(...responseResult.issues);

  if (
    requiredObj &&
    signatureObj &&
    Array.isArray(requiredObj.accepts) &&
    isObject(signatureObj.accepted)
  ) {
    const allowed = new Set(requiredObj.accepts.map(requirementIdentity));
    const selected = requirementIdentity(signatureObj.accepted);
    if (!allowed.has(selected)) {
      issues.push(
        mkIssue(
          "error",
          "FLOW_ACCEPTED_MISMATCH",
          "PAYMENT-SIGNATURE accepted requirement does not match any PAYMENT-REQUIRED option",
          "retryRequest.headers.PAYMENT-SIGNATURE",
        ),
      );
    }
  }

  if (signatureObj?.accepted?.network && responseObj?.network) {
    if (signatureObj.accepted.network !== responseObj.network) {
      issues.push(
        mkIssue(
          "error",
          "FLOW_NETWORK_MISMATCH",
          "PAYMENT-RESPONSE network does not match the accepted payment network",
          "finalResponse.headers.PAYMENT-RESPONSE",
        ),
      );
    }
  }

  const initialStatus = input.initialResponse?.status;
  if (initialStatus !== undefined && Number(initialStatus) !== 402) {
    issues.push(
      mkIssue(
        "warning",
        "FLOW_INITIAL_STATUS",
        `initialResponse.status is ${initialStatus}; expected 402 for payment challenge`,
        "initialResponse.status",
      ),
    );
  }

  const finalStatus = input.finalResponse?.status;
  if (finalStatus !== undefined && (Number(finalStatus) < 200 || Number(finalStatus) >= 300)) {
    issues.push(
      mkIssue(
        "warning",
        "FLOW_FINAL_STATUS",
        `finalResponse.status is ${finalStatus}; expected 2xx after successful payment`,
        "finalResponse.status",
      ),
    );
  }

  return { ...summarizeIssues(issues), issues, kind: "flow" };
}

export function lintRouteConfig(input) {
  const issues = [];
  let routes;

  if (!isObject(input)) {
    issues.push(mkIssue("error", "CONFIG_NOT_OBJECT", "route config must be a JSON object"));
    return { ...summarizeIssues(issues), issues, kind: "route-config" };
  }

  if (Array.isArray(input.accepts) || input.scheme || input.network || input.price) {
    routes = { "INLINE_ROUTE": input };
    issues.push(
      mkIssue(
        "warning",
        "INLINE_ROUTE",
        "config appears to be a single route object; wrapping as INLINE_ROUTE for linting",
        "",
      ),
    );
  } else {
    routes = input;
  }

  for (const [routeKey, routeConfig] of Object.entries(routes)) {
    const routePath = `routes.${routeKey}`;

    if (routeKey !== "INLINE_ROUTE" && !/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+\/.+/.test(routeKey)) {
      issues.push(
        mkIssue(
          "warning",
          "ROUTE_KEY_FORMAT",
          `Route key should look like 'METHOD /path', got: ${routeKey}`,
          routePath,
        ),
      );
    }

    if (!isObject(routeConfig)) {
      issues.push(mkIssue("error", "ROUTE_CONFIG_INVALID", "route config must be an object", routePath));
      continue;
    }

    if (!Array.isArray(routeConfig.accepts) || routeConfig.accepts.length === 0) {
      issues.push(mkIssue("error", "ROUTE_ACCEPTS_MISSING", "accepts must be a non-empty array", `${routePath}.accepts`));
      continue;
    }

    routeConfig.accepts.forEach((accept, index) => {
      const base = `${routePath}.accepts[${index}]`;
      validateRequirement(accept, issues, base, 2, { requireAmount: false });

      const hasPrice = typeof accept.price === "string" || typeof accept.price === "number";
      const hasAmount = typeof accept.amount === "string";

      if (!hasPrice && !hasAmount) {
        issues.push(
          mkIssue(
            "error",
            "PRICE_OR_AMOUNT_REQUIRED",
            "each accept entry should include price (dollars) or amount (atomic units)",
            base,
          ),
        );
      }

      if (hasPrice) {
        const priceText = String(accept.price).trim();
        if (!/^\$?\d+(\.\d+)?$/.test(priceText)) {
          issues.push(
            mkIssue(
              "warning",
              "PRICE_FORMAT",
              `price should look like $0.001 or 0.001, got: ${String(accept.price)}`,
              `${base}.price`,
            ),
          );
        }
      }
    });

    if (typeof routeConfig.description !== "string" || routeConfig.description.trim() === "") {
      issues.push(
        mkIssue(
          "warning",
          "ROUTE_DESCRIPTION_MISSING",
          "description is recommended to improve buyer/agent UX",
          `${routePath}.description`,
        ),
      );
    }

    if (typeof routeConfig.mimeType !== "string" || routeConfig.mimeType.trim() === "") {
      issues.push(
        mkIssue(
          "warning",
          "ROUTE_MIMETYPE_MISSING",
          "mimeType is recommended",
          `${routePath}.mimeType`,
        ),
      );
    } else if (!MIME_REGEX.test(routeConfig.mimeType)) {
      issues.push(
        mkIssue(
          "warning",
          "ROUTE_MIMETYPE_INVALID",
          `mimeType looks invalid: ${routeConfig.mimeType}`,
          `${routePath}.mimeType`,
        ),
      );
    }
  }

  return { ...summarizeIssues(issues), issues, kind: "route-config" };
}

async function fetchWithLimits(url, timeoutMs, maxBytes) {
  await assertSafeUrl(url);

  const controller = new AbortController();
  const timeout = setTimeout(() => {
    controller.abort(new Error(`Request timed out after ${timeoutMs}ms`));
  }, timeoutMs);

  try {
    const response = await fetch(url, {
      method: "GET",
      redirect: "manual",
      signal: controller.signal,
    });

    const headers = {};
    response.headers.forEach((value, key) => {
      headers[key] = value;
    });

    let bytesRead = 0;
    const chunks = [];
    const reader = response.body?.getReader?.();

    if (reader) {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        bytesRead += value.byteLength;
        if (bytesRead > maxBytes) {
          throw new Error(`Response exceeded max bytes (${maxBytes})`);
        }
        chunks.push(value);
      }
    }

    const body = Buffer.concat(chunks.map(chunk => Buffer.from(chunk))).toString("utf8");

    return {
      status: response.status,
      headers,
      body,
      bytesRead,
    };
  } finally {
    clearTimeout(timeout);
  }
}

function readLocalTarget(target) {
  const fullPath = path.resolve(process.cwd(), target);
  const raw = fs.readFileSync(fullPath, "utf8");
  const trimmed = raw.trim();

  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    const parsed = JSON.parse(trimmed);
    if (isObject(parsed) && isObject(parsed.headers)) {
      return {
        source: target,
        mode: "file",
        status: parsed.status,
        headers: parsed.headers,
        body: typeof parsed.body === "string" ? parsed.body : "",
        payload: parsed,
      };
    }

    if (isObject(parsed)) {
      const keys = Object.keys(parsed);
      const maybeHeaderMap = keys.some(key => key.includes("-"));
      return {
        source: target,
        mode: "file",
        headers: maybeHeaderMap ? parsed : undefined,
        payload: parsed,
        body: "",
      };
    }

    return {
      source: target,
      mode: "file",
      payload: parsed,
      body: "",
    };
  }

  return {
    source: target,
    mode: "file",
    headers: parseHeaderLines(raw),
    body: "",
  };
}

async function loadTarget(target, { timeoutMs, maxBytes }) {
  if (/^https?:\/\//i.test(target)) {
    const fetched = await fetchWithLimits(target, timeoutMs, maxBytes);
    return {
      source: target,
      mode: "url",
      status: fetched.status,
      headers: fetched.headers,
      body: fetched.body,
      bytesRead: fetched.bytesRead,
    };
  }

  return readLocalTarget(target);
}

function detectValidationKind(data, explicitKind) {
  if (explicitKind && explicitKind !== "auto") return explicitKind;

  const headers = normalizeHeaders(data.headers || {});
  const payload = data.payload;

  if (isObject(payload) && payload.initialResponse && payload.retryRequest && payload.finalResponse) {
    return "flow";
  }

  if (headers["payment-required"] || headers["x-payment-required"]) return "payment-required";
  if (headers["payment-signature"] || headers["x-payment"]) return "payment-signature";
  if (headers["payment-response"] || headers["x-payment-response"]) return "payment-response";

  if (isObject(payload) && Array.isArray(payload.accepts) && payload.x402Version !== undefined) {
    return "payment-required";
  }

  if (isObject(payload) && payload.payload && (payload.accepted || payload.scheme) && payload.x402Version !== undefined) {
    return "payment-signature";
  }

  if (isObject(payload) && typeof payload.success === "boolean" && payload.transaction) {
    return "payment-response";
  }

  if (data.status === 402 && data.body) {
    const parsed = parseMaybeJson(data.body);
    if (isObject(parsed) && Array.isArray(parsed.accepts) && parsed.x402Version !== undefined) {
      return "payment-required";
    }
  }

  return "unknown";
}

function buildValidationPayload(data, kind, issues) {
  const headers = normalizeHeaders(data.headers || {});

  if (kind === "payment-required") {
    if (headers["payment-required"] || headers["x-payment-required"]) {
      return decodeBase64Json(
        "PAYMENT-REQUIRED",
        headers["payment-required"] || headers["x-payment-required"],
        issues,
        "headers.PAYMENT-REQUIRED",
      );
    }
    if (isObject(data.payload) && Array.isArray(data.payload.accepts)) return data.payload;
    if (data.body) {
      const parsed = parseMaybeJson(data.body);
      if (isObject(parsed) && Array.isArray(parsed.accepts)) return parsed;
    }
  }

  if (kind === "payment-signature") {
    if (headers["payment-signature"] || headers["x-payment"]) {
      return decodeBase64Json(
        "PAYMENT-SIGNATURE",
        headers["payment-signature"] || headers["x-payment"],
        issues,
        "headers.PAYMENT-SIGNATURE",
      );
    }
    if (isObject(data.payload) && data.payload.payload) return data.payload;
  }

  if (kind === "payment-response") {
    if (headers["payment-response"] || headers["x-payment-response"]) {
      return decodeBase64Json(
        "PAYMENT-RESPONSE",
        headers["payment-response"] || headers["x-payment-response"],
        issues,
        "headers.PAYMENT-RESPONSE",
      );
    }
    if (isObject(data.payload) && data.payload.transaction) return data.payload;
  }

  if (kind === "flow" && isObject(data.payload)) {
    return data.payload;
  }

  return null;
}

export async function runValidate(target, options = {}) {
  if (!target) {
    throw new Error(
      "Usage: x402_validate <url-or-file> [--kind auto|payment-required|payment-signature|payment-response|flow] [--json] [--timeout <ms>] [--max-bytes <n>]",
    );
  }

  const timeoutMs = Number(options.timeout || DEFAULT_TIMEOUT_MS);
  const maxBytes = Number(options["max-bytes"] || DEFAULT_MAX_BYTES);

  const loaded = await loadTarget(target, { timeoutMs, maxBytes });
  const kind = detectValidationKind(loaded, options.kind || "auto");

  const issues = [];
  let result = null;
  let payload = null;

  if (kind === "unknown") {
    issues.push(
      mkIssue(
        "error",
        "KIND_DETECTION_FAILED",
        "Could not determine x402 object type. Use --kind to force validation target.",
      ),
    );
  } else {
    payload = buildValidationPayload(loaded, kind, issues);
    if (!payload) {
      issues.push(mkIssue("error", "PAYLOAD_EXTRACTION_FAILED", `Could not extract ${kind} payload from input`));
    } else if (kind === "payment-required") {
      result = validatePaymentRequiredObject(payload);
    } else if (kind === "payment-signature") {
      result = validatePaymentSignatureObject(payload);
    } else if (kind === "payment-response") {
      result = validatePaymentResponseObject(payload);
    } else if (kind === "flow") {
      result = validateFlowObject(payload);
    }
  }

  if (result) {
    issues.push(...result.issues);
  }

  const summary = summarizeIssues(issues);
  const output = {
    command: "x402_validate",
    source: target,
    kind,
    status: loaded.status,
    bytesRead: loaded.bytesRead,
    checkedHeaders: redactHeaders(normalizeHeaders(loaded.headers || {})),
    result: {
      ok: summary.ok,
      errors: summary.errors,
      warnings: summary.warnings,
      issues,
    },
  };

  return output;
}

export async function runLint(target) {
  if (!target) {
    throw new Error("Usage: x402_lint <config-file.json> [--json]");
  }
  const fullPath = path.resolve(process.cwd(), target);
  const parsed = JSON.parse(fs.readFileSync(fullPath, "utf8"));
  const result = lintRouteConfig(parsed);
  return {
    command: "x402_lint",
    source: target,
    result: {
      ok: result.ok,
      errors: result.errors,
      warnings: result.warnings,
      issues: result.issues,
    },
  };
}

export async function runSelfTest() {
  const fixturesDir = path.join(__dirname, "fixtures");

  const cases = [
    {
      name: "valid-v2-required-header",
      run: () => runValidate(path.join(fixturesDir, "valid-v2-required.headers.json"), { kind: "payment-required" }),
      expectOk: true,
    },
    {
      name: "invalid-v2-required-header-missing-accepts",
      run: () => runValidate(path.join(fixturesDir, "invalid-required-missing-accepts.headers.json"), { kind: "payment-required" }),
      expectOk: false,
    },
    {
      name: "valid-v1-required-body",
      run: () => runValidate(path.join(fixturesDir, "valid-v1-required.body.json"), { kind: "payment-required" }),
      expectOk: true,
    },
    {
      name: "valid-route-config",
      run: () => runLint(path.join(fixturesDir, "valid-config.routes.json")),
      expectOk: true,
    },
    {
      name: "valid-route-config-price-only",
      run: () => runLint(path.join(fixturesDir, "valid-config-price-only.routes.json")),
      expectOk: true,
    },
    {
      name: "invalid-route-config",
      run: () => runLint(path.join(fixturesDir, "invalid-config.routes.json")),
      expectOk: false,
    },
    {
      name: "coinbase-realistic-flow",
      run: () => runValidate(path.join(fixturesDir, "coinbase-weather-flow.json"), { kind: "flow" }),
      expectOk: true,
    },
  ];

  const results = [];
  for (const testCase of cases) {
    const out = await testCase.run();
    const got = Boolean(out.result?.ok);
    results.push({
      name: testCase.name,
      expected: testCase.expectOk,
      actual: got,
      ok: got === testCase.expectOk,
      errors: out.result?.errors ?? 0,
      warnings: out.result?.warnings ?? 0,
    });
  }

  const allPassed = results.every(result => result.ok);
  return {
    command: "x402_test",
    result: {
      ok: allPassed,
      cases: results,
    },
  };
}

function printHuman(result) {
  if (result.command === "x402_validate") {
    const status = result.result.ok ? "PASS" : "FAIL";
    console.log(`x402_validate: ${status}`);
    console.log(`source: ${result.source}`);
    console.log(`kind: ${result.kind}`);
    if (typeof result.status === "number") console.log(`httpStatus: ${result.status}`);
    if (typeof result.bytesRead === "number") console.log(`bytesRead: ${result.bytesRead}`);
    if (Object.keys(result.checkedHeaders || {}).length > 0) {
      console.log("checkedHeaders:", result.checkedHeaders);
    }
    if (result.result.issues.length === 0) {
      console.log("issues: none");
    } else {
      console.log("issues:");
      for (const issue of result.result.issues) {
        const where = issue.where ? ` (${issue.where})` : "";
        console.log(`- [${issue.level}] ${issue.code}${where}: ${issue.message}`);
      }
    }
    return;
  }

  if (result.command === "x402_lint") {
    const status = result.result.ok ? "PASS" : "FAIL";
    console.log(`x402_lint: ${status}`);
    console.log(`source: ${result.source}`);
    if (result.result.issues.length === 0) {
      console.log("issues: none");
    } else {
      console.log("issues:");
      for (const issue of result.result.issues) {
        const where = issue.where ? ` (${issue.where})` : "";
        console.log(`- [${issue.level}] ${issue.code}${where}: ${issue.message}`);
      }
    }
    return;
  }

  if (result.command === "x402_test") {
    const status = result.result.ok ? "PASS" : "FAIL";
    console.log(`x402_test: ${status}`);
    for (const testCase of result.result.cases) {
      console.log(
        `- ${testCase.name}: ${testCase.ok ? "PASS" : "FAIL"} (expected=${testCase.expected}, actual=${testCase.actual}, errors=${testCase.errors}, warnings=${testCase.warnings})`,
      );
    }
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const command = normalizeCommand(args._[0]);
  const target = args._[1];
  const asJson = Boolean(args.json);

  let out;
  if (command === "x402_validate") {
    out = await runValidate(target, args);
  } else if (command === "x402_lint") {
    out = await runLint(target, args);
  } else if (command === "x402_test") {
    out = await runSelfTest(args);
  } else {
    throw new Error("Unknown command. Use: x402_validate | x402_lint | x402_test");
  }

  if (asJson) {
    console.log(JSON.stringify(out, null, 2));
  } else {
    printHuman(out);
  }

  if (!out.result.ok) process.exit(1);
}

if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  main().catch(error => {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`Error: ${message}`);
    process.exit(1);
  });
}
