// IRONBULL FX - EA licence check (HFM Affiliates API)
// GET /.netlify/functions/ea-license?login=12345678&nonce=abc...&server=HFMarketsSA-Live&v=3.0
// Reply (plain text, signed):  STATUS|login|nonce|expiry_unix|message|hmac_sha256_hex
//
// Netlify environment variables:
//   HFM_API_KEY           (required) your HFM Affiliates API key
//   EA_SECRET             (required) must match LIC_SECRET in the EA
//   SUPABASE_URL          (optional) manual overrides + attempt log
//   SUPABASE_SERVICE_KEY  (optional)
//
// Order of checks:
//   1. Supabase ea_allowed_accounts (optional): active=false -> BANNED, active=true -> approved (manual override)
//   2. HFM Affiliates API: account must be one of YOUR IB clients
const crypto = require('crypto');

const HFM = 'https://api.hfaffiliates.com';
const OK_HOURS = 72;          // EA keeps working this long if this server is unreachable
const HFM_TIMEOUT_MS = 8000;  // Netlify functions stop at 10s

exports.handler = async (event) => {
  const q = event.queryStringParameters || {};
  const login = String(q.login || '').replace(/\D/g, '').slice(0, 20);
  const nonce = String(q.nonce || '').replace(/[^A-Za-z0-9]/g, '').slice(0, 64);
  const server = String(q.server || '').slice(0, 80);
  const version = String(q.v || '').slice(0, 10);

  const SECRET = process.env.EA_SECRET;
  const HFM_KEY = process.env.HFM_API_KEY;
  if (!SECRET || !HFM_KEY) return plain(503, 'Server not configured');

  const reply = (status, msg, expiry) => {
    const clean = String(msg).replace(/[|\r\n]/g, '/');
    const payload = `${status}|${login}|${nonce}|${expiry}|${clean}`;
    const sig = crypto.createHmac('sha256', SECRET).update(payload).digest('hex');
    return plain(200, `${payload}|${sig}`);
  };
  const approve = (msg) => reply('OK', msg, Math.floor(Date.now() / 1000) + OK_HOURS * 3600);
  const deny = (msg) => reply('DENY', msg, 0);

  if (!login || !nonce) return deny('Bad request');

  // ── 1. manual overrides (optional) ──
  const override = await supabaseLookup(login);
  if (override && override.active === false) {
    await logAttempt(login, server, version, false, 'banned');
    return deny('This account has been deactivated by Ironbull FX.');
  }
  if (override && override.active === true) {
    await logAttempt(login, server, version, true, 'manual');
    return approve('Ironbull FX account verified');
  }

  // ── 2. HFM Affiliates API ──
  let result;
  try {
    result = await hfmFindAccount(login, HFM_KEY);
  } catch (e) {
    // HFM down / key problem: answer UNSIGNED so the EA falls back to its
    // cached approval instead of locking every client.
    console.error('HFM check failed:', e.message);
    return plain(503, 'HFM API unavailable');
  }

  if (!result) {
    await logAttempt(login, server, version, false, 'not_ib_client');
    return deny('Account not registered under the Ironbull FX IB.');
  }

  const dep = num(result.deposits), wd = num(result.withdrawals);
  await logAttempt(login, server, version, true,
    `hfm net_deposit=${(dep - wd).toFixed(2)} ${result.account_currency || ''}`);
  return approve('HFM IB client verified');
};

// Try the direct report first; fall back to scanning the full client list.
async function hfmFindAccount(login, key) {
  const r = await hfmGet(`/api/clients/${login}/report`, key);
  if (r.status === 200) {
    const d = await r.json();
    if (d && String(d.id) === login) return d;
    if (d && d.id) return d;
  } else if (r.status === 401) {
    throw new Error('HFM API key rejected (401)');
  } else if (r.status >= 500) {
    throw new Error(`HFM API error ${r.status}`);
  }

  // 403/404/422 etc. -> not found by that id; check the client list
  const l = await hfmGet('/api/clients/', key);
  if (l.status === 401) throw new Error('HFM API key rejected (401)');
  if (l.status !== 200) throw new Error(`HFM client list error ${l.status}`);
  const body = await l.json();
  const rows = Array.isArray(body) ? body : (body.data || []);
  return rows.find((c) => String(c.id) === login) || null;
}

async function hfmGet(path, key) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), HFM_TIMEOUT_MS);
  try {
    return await fetch(HFM + path, {
      headers: { Authorization: `Bearer ${key}`, Accept: 'application/json' },
      signal: ctrl.signal,
    });
  } finally {
    clearTimeout(t);
  }
}

// ── optional Supabase helpers ──
function sb() {
  const url = process.env.SUPABASE_URL, key = process.env.SUPABASE_SERVICE_KEY;
  if (!url || !key) return null;
  return { url, headers: { apikey: key, Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' } };
}

async function supabaseLookup(login) {
  const c = sb();
  if (!c) return null;
  try {
    const r = await fetch(`${c.url}/rest/v1/ea_allowed_accounts?login=eq.${login}&select=login,active`, { headers: c.headers });
    if (!r.ok) return null;
    const rows = await r.json();
    return rows[0] || null;
  } catch { return null; }
}

async function logAttempt(login, server, version, approved, note) {
  const c = sb();
  if (!c) return;
  try {
    await fetch(`${c.url}/rest/v1/ea_license_log`, {
      method: 'POST',
      headers: { ...c.headers, Prefer: 'return=minimal' },
      body: JSON.stringify({ login: Number(login), server, ea_version: version, approved, note }),
    });
  } catch {}
}

function num(v) { const n = parseFloat(v); return isNaN(n) ? 0 : n; }

function plain(code, body) {
  return { statusCode: code, headers: { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store' }, body };
}
