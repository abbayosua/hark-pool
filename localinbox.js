#!/usr/bin/env node
// Local-inbox backend for hark-pool: replaces mail.tm with the Gmail-backed
// REST inbox at http://localhost:8899 (inbox_api.py, already running).
//
// Adresses are Gmail plus-aliases of dinapratama.id@gmail.com, e.g.
//   dinapratama.id+hark9f3a@gmail.com
// which all land in the same inbox and are queryable via /latest?to=...
//
// Same export shape as the mail.tm helpers in register.js:
//   createMailbox({ localpart }) -> { address, password, token, id }
//   waitForMagicLink(key, { timeoutMs, intervalMs, log }) -> verifyUrl
// where `key` is the address (mail.tm token unused here).

import { randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";

const INBOX_URL = process.env.LOCALINBOX_URL || "http://localhost:8899";
const INBOX_KEY = process.env.LOCALINBOX_KEY || "NTKM2026OTP";
const BASE_USER = process.env.LOCALINBOX_USER || "dinapratama.id";
const BASE_DOMAIN = process.env.LOCALINBOX_DOMAIN || "gmail.com";
// Read-only Gmail fetch for the ONE message body (the :8899 /get endpoint
// truncates bodies, and Hark's HTML-only mail keeps the link past the cut).
// Discovery/polling still goes through :8899.
const TOKEN_FILE = process.env.LOCALINBOX_TOKEN || "/Users/user/Downloads/token.json";

const MAGIC_RE =
  /https:\/\/auth\.hark\.com\/api\/auth\/magic-link\/verify\?[^\s"'<>)\]]+/;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function api(path, params) {
  const qs = new URLSearchParams({ key: INBOX_KEY, ...params }).toString();
  const res = await fetch(`${INBOX_URL}${path}?${qs}`);
  if (!res.ok) throw new Error(`local inbox ${path} failed ${res.status}`);
  return res.json();
}

let cachedToken = null;
let cachedExpiry = 0;

async function gmailAccessToken() {
  if (cachedToken && Date.now() < cachedExpiry - 60000) return cachedToken;
  const creds = JSON.parse(await readFile(TOKEN_FILE, "utf8"));
  const res = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: creds.client_id,
      client_secret: creds.client_secret,
      refresh_token: creds.refresh_token,
      grant_type: "refresh_token",
    }).toString(),
  });
  if (!res.ok) throw new Error(`gmail refresh failed ${res.status}`);
  const j = await res.json();
  cachedToken = j.access_token;
  cachedExpiry = Date.now() + (j.expires_in || 3600) * 1000;
  return cachedToken;
}

function findHtml(part) {
  if (part.mimeType === "text/html" && part.body?.data) return part.body.data;
  for (const q of part.parts || []) {
    const hit = findHtml(q);
    if (hit) return hit;
  }
  return null;
}

async function gmailMessageHtml(id) {
  const token = await gmailAccessToken();
  const res = await fetch(
    `https://www.googleapis.com/gmail/v1/users/me/messages/${id}?format=full`,
    { headers: { Authorization: `Bearer ${token}` } }
  );
  if (!res.ok) throw new Error(`gmail get failed ${res.status}`);
  const m = await res.json();
  const b64 = findHtml(m.payload || {});
  if (!b64) throw new Error("no html part in message");
  return Buffer.from(b64.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
}

// NOTE: Hark's validator rejects Gmail plus-tags ("DISPOSABLE_EMAIL"), so we
// use Gmail dot-variants instead (dots are ignored for delivery, but the
// string looks like an ordinary address). Caveat: if Hark normalizes dots
// server-side, variants map to one user — fine for testing, not for pools.

function dotVariant(bare) {
  const cuts = new Set();
  const nDots = 1 + Math.floor(Math.random() * 2); // 1-2 dots
  while (cuts.size < nDots) {
    cuts.add(1 + Math.floor(Math.random() * (bare.length - 1)));
  }
  let out = "";
  for (let i = 0; i < bare.length; i++) {
    out += bare[i];
    if (cuts.has(i + 1) && i + 1 < bare.length) out += ".";
  }
  return out;
}

export async function createMailbox({ localpart } = {}) {
  if (BASE_DOMAIN.toLowerCase() === "gmail.com") {
    const bare = BASE_USER.replace(/\./g, "");
    const address = `${dotVariant(bare)}@${BASE_DOMAIN}`;
    return { address, password: null, token: null, id: null };
  }
  // Custom domain (e.g. kitamampu.web.id) routed to the same Gmail inbox:
  // free choice of localpart, suffixed for uniqueness.
  const tag = `${localpart || "hark"}${randomBytes(3).toString("hex")}`;
  const address = `${tag}@${BASE_DOMAIN}`;
  return { address, password: null, token: null, id: null };
}

export async function waitForMagicLink(
  address,
  {
    timeoutMs = Number(process.env.LOCALINBOX_TIMEOUT_MS) || 180000,
    intervalMs = Number(process.env.LOCALINBOX_INTERVAL_MS) || 10000,
    log = () => {},
  } = {}
) {
  const deadline = Date.now() + timeoutMs;
  const t0 = Date.now(); // ignore pre-existing mail to other dot-variants
  let attempt = 0;
  while (Date.now() < deadline) {
    attempt++;
    try {
      const latest = await api("/latest", { to: address });
      log(`poll ${attempt}: found=${!!latest.found}${latest.subject ? ` subj="${latest.subject.slice(0, 60)}"` : ""}`);
      if (latest.found && latest.id) {
        const ts = Date.parse(latest.date || "");
        if (ts && ts < t0 - 120000) {
          log(`poll ${attempt}: stale email (${latest.date}), waiting for fresh one`);
        } else {
          let html = "";
          try {
            html = await gmailMessageHtml(latest.id);
          } catch (e) {
            log(`poll ${attempt}: html fetch error ${e.message}`);
          }
          const body = `${latest.subject || ""}\n${html}`;
          const match = body.match(MAGIC_RE);
          if (match) return match[0].replace(/[)\]]+$/, "");
          log(`poll ${attempt}: email found but no magic link yet`);
        }
      }
    } catch (e) {
      log(`poll ${attempt}: error ${e.message}`);
    }
    await sleep(intervalMs);
  }
  throw new Error(`timed out waiting for the Hark magic-link email to ${address}`);
}
