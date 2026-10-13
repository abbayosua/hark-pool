#!/usr/bin/env node
// Minimal fetch-compatible wrapper with HTTP CONNECT proxy support.
// Zero dependencies (Node >= 18). Node's built-in fetch ignores
// HTTP_PROXY/HTTPS_PROXY, so Hark-bound requests go through a manual
// CONNECT tunnel + TLS + raw HTTP/1.1 here.
//
// Usage:
//   import { pfetch, setProxy } from "./proxyfetch.js";
//   setProxy("http://user:pass@host:port");  // or null for direct
//   const res = await pfetch(url, { method, headers, body, redirect });
// Response subset: { ok, status, headers:{get(),getSetCookie()}, text(), json() }
// Only these hosts are proxied; everything else (localhost inbox, gmail)
// always goes direct via built-in fetch.

import net from "node:net";
import tls from "node:tls";
import { AsyncLocalStorage } from "node:async_hooks";

let globalProxy = null;
const als = new AsyncLocalStorage();
export function setProxy(p) {
  globalProxy = p || null;
}
export function runWithProxy(p, fn) {
  return als.run(p || null, fn);
}
function effectiveProxy() {
  const v = als.getStore();
  return v !== undefined ? v : globalProxy;
}
export function getProxy() {
  return effectiveProxy();
}

const DIRECT_HOSTS = new Set(["localhost", "127.0.0.1", "::1"]);
// Gmail reads share one quota identity; keep them on the direct link.
const DIRECT_SUFFIXES = ["googleapis.com"];

function wantsProxy(hostname) {
  if (!effectiveProxy()) return false;
  if (DIRECT_HOSTS.has(hostname)) return false;
  return !DIRECT_SUFFIXES.some((s) => hostname.endsWith(s));
}

function parseProxy(p) {
  const s = /^[a-z]+:\/\//i.test(p) ? p : `http://${p}`;
  const u = new URL(s);
  const auth = u.username
    ? `${decodeURIComponent(u.username)}:${decodeURIComponent(u.password)}`
    : null;
  return { host: u.hostname, port: Number(u.port) || 8080, auth };
}

function connectTunnel(targetHost, targetPort, proxy) {
  return new Promise((resolve, reject) => {
    let done = false;
    const fail = (e) => {
      if (!done) {
        done = true;
        try {
          sock.destroy();
        } catch {}
        reject(e);
      }
    };
    const sock = net.connect(proxy.port, proxy.host);
    const timer = setTimeout(() => fail(new Error("proxy connect timeout")), 25000);
    sock.on("connect", () => {
      let req =
        `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\n` +
        `Host: ${targetHost}:${targetPort}\r\n`;
      if (proxy.auth) {
        req += `Proxy-Authorization: Basic ${Buffer.from(proxy.auth).toString("base64")}\r\n`;
      }
      req += "Proxy-Connection: Keep-Alive\r\n\r\n";
      sock.write(req);
    });
    let buf = "";
    sock.on("data", (d) => {
      buf += d.toString("latin1");
      const end = buf.indexOf("\r\n\r\n");
      if (end < 0) return;
      const status = parseInt((buf.slice(0, end).split("\r\n")[0] || "").split(" ")[1], 10);
      clearTimeout(timer);
      if (status !== 200) {
        fail(new Error(`proxy CONNECT rejected (${status || "?"})`));
        return;
      }
      done = true;
      sock.removeAllListeners("data");
      resolve(sock);
    });
    sock.on("error", (e) => fail(e));
    sock.on("close", () => fail(new Error("proxy socket closed during CONNECT")));
  });
}

function readResponse(sock) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let head = null; // { status, headers: {name: string|string[]} }
    let bodyLen = 0;
    let chunked = false;
    let finished = false;
    const timer = setTimeout(() => fail(new Error("proxy read timeout")), 60000);
    const fail = (e) => {
      if (!finished) {
        finished = true;
        clearTimeout(timer);
        try {
          sock.destroy();
        } catch {}
        reject(e);
      }
    };
    const parseHead = (raw) => {
      const lines = raw.split("\r\n");
      const status = parseInt((lines[0] || "").split(" ")[1], 10) || 0;
      const headers = {};
      for (const ln of lines.slice(1)) {
        const i = ln.indexOf(":");
        if (i < 0) continue;
        const k = ln.slice(0, i).trim().toLowerCase();
        const v = ln.slice(i + 1).trim();
        if (headers[k] === undefined) headers[k] = v;
        else if (Array.isArray(headers[k])) headers[k].push(v);
        else headers[k] = [headers[k], v];
      }
      return { status, headers };
    };
    let pending = Buffer.alloc(0);
    const tryParse = () => {
      if (head) return;
      const s = pending.toString("latin1");
      const end = s.indexOf("\r\n\r\n");
      if (end < 0) return;
      head = parseHead(s.slice(0, end));
      pending = pending.subarray(end + 4);
      const te = head.headers["transfer-encoding"];
      chunked = !!te && String(Array.isArray(te) ? te.join(",") : te).toLowerCase().includes("chunked");
      bodyLen = parseInt(head.headers["content-length"] || "0", 10) || 0;
      pump();
    };
    // chunked state
    let chunkSize = -1;
    let chunkBuf = Buffer.alloc(0);
    const body = [];
    const pump = () => {
      if (!head || finished) return;
      if (!chunked) {
        if (bodyLen === 0 || pending.length >= bodyLen) {
          body.push(pending.subarray(0, bodyLen));
          done();
        }
        return;
      }
      // chunked framing
      chunkBuf = Buffer.concat([chunkBuf, pending]);
      pending = Buffer.alloc(0);
      for (;;) {
        if (chunkSize < 0) {
          const s = chunkBuf.toString("latin1");
          const i = s.indexOf("\r\n");
          if (i < 0) return;
          chunkSize = parseInt(s.slice(0, i).split(";")[0].trim(), 16);
          if (Number.isNaN(chunkSize)) return fail(new Error("bad chunk size"));
          chunkBuf = chunkBuf.subarray(i + 2);
          if (chunkSize === 0) return done();
        }
        if (chunkBuf.length < chunkSize + 2) return;
        body.push(chunkBuf.subarray(0, chunkSize));
        chunkBuf = chunkBuf.subarray(chunkSize + 2);
        chunkSize = -1;
      }
    };
    const done = () => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      try {
        sock.destroy();
      } catch {}
      resolve({ head, body: Buffer.concat(body) });
    };
    sock.on("data", (d) => {
      pending = Buffer.concat([pending, d]);
      if (!head) tryParse();
      else pump();
    });
    sock.on("error", (e) => fail(e));
    sock.on("close", () => {
      // No content-length + connection close = body is what we have.
      if (head && !chunked && !head.headers["content-length"]) {
        body.push(pending);
        pending = Buffer.alloc(0);
        done();
      } else if (!finished) fail(new Error("proxy socket closed early"));
    });
  });
}

class PHeaders {
  constructor(raw) {
    this.raw = raw || {};
  }
  get(name) {
    const v = this.raw[String(name).toLowerCase()];
    if (v === undefined) return null;
    return Array.isArray(v) ? v.join(", ") : v;
  }
  getSetCookie() {
    const v = this.raw["set-cookie"];
    if (!v) return [];
    return Array.isArray(v) ? v : [v];
  }
}

async function proxiedFetch(url, opts = {}) {
  const u = new URL(url);
  const secure = u.protocol === "https:";
  const port = Number(u.port) || (secure ? 443 : 80);
  const proxy = parseProxy(effectiveProxy());
  const method = (opts.method || "GET").toUpperCase();
  const body = opts.body || "";
  const bodyBuf = Buffer.isBuffer(body) ? body : Buffer.from(String(body));

  const sock = await connectTunnel(u.hostname, port, proxy);
  const io = secure
    ? tls.connect({ socket: sock, servername: u.hostname })
    : sock;
  if (secure) {
    await new Promise((resolve, reject) => {
      io.on("secureConnect", resolve);
      io.on("error", reject);
      setTimeout(() => reject(new Error("tls handshake timeout")), 25000);
    });
  }

  const headers = { ...(opts.headers || {}) };
  const lc = {};
  for (const [k, v] of Object.entries(headers)) lc[k.toLowerCase()] = [k, v];
  if (!lc["host"]) lc["host"] = ["Host", u.host];
  if (!lc["connection"]) lc["connection"] = ["Connection", "close"];
  if (!lc["accept-encoding"]) lc["accept-encoding"] = ["Accept-Encoding", "identity"];
  if (bodyBuf.length && !lc["content-length"]) {
    lc["content-length"] = ["Content-Length", String(bodyBuf.length)];
  }
  let raw = `${method} ${u.pathname}${u.search} HTTP/1.1\r\n`;
  for (const [, [k, v]] of Object.entries(lc)) raw += `${k}: ${v}\r\n`;
  raw += "\r\n";

  await new Promise((resolve, reject) => {
    io.on("error", reject);
    io.write(raw, () => {
      if (!bodyBuf.length) return resolve();
      io.write(bodyBuf, resolve);
    });
  });

  const { head, body: respBody } = await readResponse(io);
  const text = respBody.toString("utf8");
  return {
    ok: head.status >= 200 && head.status < 300,
    status: head.status,
    headers: new PHeaders(head.headers),
    text: async () => text,
    json: async () => JSON.parse(text),
  };
}

export async function pfetch(url, opts = {}) {
  const hostname = new URL(url).hostname;
  if (!wantsProxy(hostname)) return fetch(url, opts);
  return proxiedFetch(url, opts);
}

export function maskProxy(p) {
  if (!p) return "-";
  try {
    const pr = parseProxy(p);
    return `${pr.host}:${pr.port}`;
  } catch {
    return "?";
  }
}
