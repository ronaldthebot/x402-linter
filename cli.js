#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const dns = require('dns').promises;
const net = require('net');

const DEFAULT_TIMEOUT_MS = 5000;
const DEFAULT_MAX_BYTES = 256 * 1024;
const SENSITIVE_HEADERS = new Set([
  'authorization',
  'proxy-authorization',
  'x-payment-token',
  'x-api-key',
  'cookie',
  'set-cookie'
]);

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const t = argv[i];
    if (t.startsWith('--')) {
      const [k, v] = t.slice(2).split('=');
      if (v !== undefined) args[k] = v;
      else if (i + 1 < argv.length && !argv[i + 1].startsWith('--')) args[k] = argv[++i];
      else args[k] = true;
    } else {
      args._.push(t);
    }
  }
  return args;
}

function redactHeaders(headers) {
  const out = {};
  for (const [k, v] of Object.entries(headers || {})) {
    out[k] = SENSITIVE_HEADERS.has(k.toLowerCase()) ? '[REDACTED]' : v;
  }
  return out;
}

function isPrivateIPv4(ip) {
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some(Number.isNaN)) return false;
  if (p[0] === 10) return true;
  if (p[0] === 127) return true;
  if (p[0] === 192 && p[1] === 168) return true;
  if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
  if (p[0] === 169 && p[1] === 254) return true;
  return false;
}

function isBlockedHostLiteral(hostname) {
  const h = String(hostname || '').toLowerCase();
  if (h === 'localhost') return true;
  if (h === '::1' || h === '[::1]') return true;
  if (net.isIP(h) === 4) return isPrivateIPv4(h);
  return false;
}

async function assertSafeUrl(rawUrl) {
  let u;
  try {
    u = new URL(rawUrl);
  } catch {
    throw new Error(`Invalid URL: ${rawUrl}`);
  }
  if (!['http:', 'https:'].includes(u.protocol)) {
    throw new Error('Only http/https URLs are allowed.');
  }
  if (isBlockedHostLiteral(u.hostname)) {
    throw new Error(`Blocked by SSRF policy: ${u.hostname}`);
  }
  const records = await dns.lookup(u.hostname, { all: true });
  for (const rec of records) {
    if (rec.family === 4 && isPrivateIPv4(rec.address)) {
      throw new Error(`Blocked by SSRF policy (resolved private IP): ${u.hostname} -> ${rec.address}`);
    }
    if (rec.family === 6 && rec.address === '::1') {
      throw new Error(`Blocked by SSRF policy (loopback IPv6): ${u.hostname} -> ${rec.address}`);
    }
  }
  return u;
}

function normalizeHeaderMap(obj) {
  const out = {};
  for (const [k, v] of Object.entries(obj || {})) out[String(k).toLowerCase()] = String(v);
  return out;
}

function validateHeaders(headers) {
  const issues = [];
  const h = normalizeHeaderMap(headers);

  const requiredMarker = h['payment-required'] || h['x-payment-required'];
  if (!requiredMarker) issues.push({ level: 'error', code: 'MISSING_PAYMENT_REQUIRED', message: 'Missing Payment-Required or X-Payment-Required header.' });

  const scheme = h['x-payment-scheme'];
  if (!scheme) issues.push({ level: 'error', code: 'MISSING_PAYMENT_SCHEME', message: 'Missing X-Payment-Scheme header.' });
  else if (!['x402', 'exact', 'erc20', 'solana'].includes(scheme.toLowerCase())) {
    issues.push({ level: 'warning', code: 'UNKNOWN_PAYMENT_SCHEME', message: `Unrecognized X-Payment-Scheme: ${scheme}` });
  }

  const network = h['x-payment-network'];
  if (network && !/^[a-z0-9._:-]{2,64}$/i.test(network)) {
    issues.push({ level: 'warning', code: 'INVALID_PAYMENT_NETWORK', message: `Invalid X-Payment-Network format: ${network}` });
  }

  const amount = h['x-payment-amount'];
  if (amount && !/^\d+(\.\d+)?$/.test(amount)) {
    issues.push({ level: 'error', code: 'INVALID_PAYMENT_AMOUNT', message: `Invalid X-Payment-Amount: ${amount}` });
  }

  const currency = h['x-payment-currency'];
  if (currency && !/^[A-Z0-9]{2,12}$/.test(currency)) {
    issues.push({ level: 'warning', code: 'INVALID_PAYMENT_CURRENCY', message: `Invalid X-Payment-Currency: ${currency}` });
  }

  return {
    ok: !issues.some(i => i.level === 'error'),
    issues,
    checkedHeaders: redactHeaders(h)
  };
}

function parseFileHeaders(filePath) {
  const raw = fs.readFileSync(filePath, 'utf8');
  const trimmed = raw.trim();

  if (trimmed.startsWith('{')) {
    const parsed = JSON.parse(trimmed);
    if (parsed.headers && typeof parsed.headers === 'object') return parsed.headers;
    if (typeof parsed === 'object') return parsed;
  }

  const lines = raw.split(/\r?\n/);
  const headers = {};
  for (const line of lines) {
    const idx = line.indexOf(':');
    if (idx > 0) headers[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
  }
  return headers;
}

async function fetchHeaders(url, timeoutMs, maxBytes) {
  await assertSafeUrl(url);
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(new Error(`Timeout after ${timeoutMs}ms`)), timeoutMs);
  try {
    const res = await fetch(url, { method: 'GET', signal: controller.signal, redirect: 'manual' });
    const headers = {};
    res.headers.forEach((v, k) => { headers[k] = v; });

    const reader = res.body?.getReader?.();
    let total = 0;
    if (reader) {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        total += (value?.byteLength || 0);
        if (total > maxBytes) {
          controller.abort(new Error(`Response exceeded max bytes (${maxBytes})`));
          break;
        }
      }
    }

    return { status: res.status, headers: redactHeaders(headers), bytesRead: total };
  } finally {
    clearTimeout(t);
  }
}

function printOutput(data, asJson) {
  if (asJson) {
    console.log(JSON.stringify(data, null, 2));
    return;
  }
  if (data.command === 'x402_validate') {
    console.log(`x402_validate: ${data.result.ok ? 'PASS' : 'FAIL'}`);
    if (data.source) console.log(`source: ${data.source}`);
    if (typeof data.httpStatus === 'number') console.log(`httpStatus: ${data.httpStatus}`);
    if (typeof data.bytesRead === 'number') console.log(`bytesRead: ${data.bytesRead}`);
    console.log('checkedHeaders:', data.result.checkedHeaders);
    if (data.result.issues.length) {
      console.log('issues:');
      data.result.issues.forEach(i => console.log(`- [${i.level}] ${i.code}: ${i.message}`));
    } else {
      console.log('issues: none');
    }
  } else if (data.command === 'x402_lint') {
    console.log(`x402_lint: ${data.result.ok ? 'PASS' : 'FAIL'}`);
    console.log(`file: ${data.source}`);
    if (data.result.issues.length) data.result.issues.forEach(i => console.log(`- [${i.level}] ${i.code}: ${i.message}`));
    else console.log('No lint issues detected.');
  } else {
    console.log(`x402_test: ${data.result.ok ? 'PASS' : 'FAIL'}`);
    data.result.cases.forEach(c => console.log(`- ${c.name}: ${c.ok ? 'PASS' : 'FAIL'}`));
  }
}

async function cmdValidate(target, opts) {
  if (!target) throw new Error('Usage: x402_validate <url-or-file> [--json] [--timeout <ms>] [--max-bytes <n>]');
  const timeoutMs = Number(opts.timeout || DEFAULT_TIMEOUT_MS);
  const maxBytes = Number(opts['max-bytes'] || DEFAULT_MAX_BYTES);
  const isUrl = /^https?:\/\//i.test(target);

  let headers;
  let meta = {};
  if (isUrl) {
    const fetched = await fetchHeaders(target, timeoutMs, maxBytes);
    headers = fetched.headers;
    meta = { httpStatus: fetched.status, bytesRead: fetched.bytesRead };
  } else {
    const full = path.resolve(process.cwd(), target);
    headers = parseFileHeaders(full);
  }

  const result = validateHeaders(headers);
  return { command: 'x402_validate', source: target, ...meta, result };
}

async function cmdLint(file, opts) {
  if (!file) throw new Error('Usage: x402_lint <config-file.json> [--json]');
  const full = path.resolve(process.cwd(), file);
  const parsed = JSON.parse(fs.readFileSync(full, 'utf8'));

  const issues = [];
  const required = ['scheme', 'network', 'payTo', 'maxAmountRequired'];
  for (const key of required) {
    if (!(key in parsed)) issues.push({ level: 'error', code: 'MISSING_FIELD', message: `Missing required field: ${key}` });
  }
  if (parsed.scheme && !['x402', 'exact'].includes(String(parsed.scheme).toLowerCase())) {
    issues.push({ level: 'warning', code: 'UNSUPPORTED_SCHEME', message: `Unsupported scheme: ${parsed.scheme}` });
  }
  if (parsed.maxAmountRequired !== undefined && !(Number(parsed.maxAmountRequired) > 0)) {
    issues.push({ level: 'error', code: 'INVALID_MAX_AMOUNT', message: 'maxAmountRequired must be > 0' });
  }
  if (parsed.payTo && !/^0x[a-fA-F0-9]{40}$/.test(String(parsed.payTo))) {
    issues.push({ level: 'warning', code: 'PAYTO_FORMAT', message: 'payTo does not match EVM address format' });
  }

  return {
    command: 'x402_lint',
    source: file,
    result: { ok: !issues.some(i => i.level === 'error'), issues }
  };
}

async function cmdTest(opts) {
  const cases = [];
  const good = validateHeaders({
    'Payment-Required': 'true',
    'X-Payment-Scheme': 'x402',
    'X-Payment-Amount': '0.01',
    'X-Payment-Currency': 'USDC',
    'X-Payment-Network': 'base-mainnet'
  });
  cases.push({ name: 'valid-header-set', ok: good.ok });

  const missing = validateHeaders({ 'X-Payment-Scheme': 'x402' });
  cases.push({ name: 'missing-payment-required', ok: !missing.ok });

  const invalidAmount = validateHeaders({ 'Payment-Required': 'true', 'X-Payment-Scheme': 'x402', 'X-Payment-Amount': 'abc' });
  cases.push({ name: 'invalid-amount', ok: !invalidAmount.ok });

  return { command: 'x402_test', mode: opts.mock ? 'mock' : 'self', result: { ok: cases.every(c => c.ok), cases } };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const command = args._[0];
  const target = args._[1];
  const asJson = Boolean(args.json);

  let out;
  if (command === 'x402_validate') out = await cmdValidate(target, args);
  else if (command === 'x402_lint') out = await cmdLint(target, args);
  else if (command === 'x402_test') out = await cmdTest(args);
  else {
    throw new Error('Unknown command. Use: x402_validate | x402_lint | x402_test');
  }

  printOutput(out, asJson);
  if (!out.result.ok) process.exit(1);
}

main().catch(err => {
  const msg = err instanceof Error ? err.message : String(err);
  console.error(`Error: ${msg}`);
  process.exit(1);
});
