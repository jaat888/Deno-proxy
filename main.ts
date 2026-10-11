// Proxy scanner for Deno Deploy (free). Replaces the Render scanner service.
//
// GET /good[?key=SCAN_KEY] -> {"updated": ts, "count": n, "good": [{"hp","ms","cc","t"}]}   (same format Render app.py reads)
// GET /scan[?key=SCAN_KEY] -> run ONE small batch now (use this with an uptime bot every 5 min if cron is unavailable)
// GET /ping                -> ok
// GET /                    -> short status
//
// Env (Deno Deploy -> Settings -> Environment variables), all optional:
//   SCAN_KEY   password for /good and /scan (set the same value as SCANNER_KEY on Render)
//   BATCH      new proxies tested per scan (default 80)
//   WORKERS    parallel tests (default 40)
//   MAX_MS     max ms per proxy (default 8000)
//   KEEP       how many fastest proxies to keep (default 40)
//   KEEP_AGE_MIN  keep a good proxy this long if it keeps passing re-test (default 180)
//
// Supports http:// (CONNECT) and socks5:// (no auth). socks4 is skipped (needs DNS lookup in handshake).

const env = (k: string, d: string) => {
  try {
    return Deno.env.get(k) ?? d;
  } catch {
    return d;
  }
};
const num = (k: string, d: number) => {
  const n = parseInt(env(k, String(d)), 10);
  return Number.isFinite(n) ? n : d;
};

const KEY = env("SCAN_KEY", "").trim();
const BATCH = Math.max(10, num("BATCH", 80));
const WORKERS = Math.max(1, Math.min(60, num("WORKERS", 40)));
const MAX_MS = Math.max(1000, num("MAX_MS", 8000));
const KEEP = Math.max(5, num("KEEP", 40));
const KEEP_AGE = num("KEEP_AGE_MIN", 180) * 60 * 1000;
const LIST_TTL = 30 * 60 * 1000;
const MAX_LIST_BYTES = 1024 * 1024; // per list, saves egress/CPU
const TEST_URL = new URL(env("POOL_TEST_URL", "https://www.cloudflare.com/cdn-cgi/trace"));
const SOURCES = [
  "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
  "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
  "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt",
  "https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/http.txt",
  "https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/socks5.txt",
];
const COUNTRIES = ["IN", "US", "DE", "GB", "SG", "NL", "FR", "BR", "ID"];
const IPLOC = "https://raw.githubusercontent.com/iplocate/free-proxy-list/main/countries/";

type Good = { hp: string; ms: number; cc: string | null; t: number };
type Saved = { updated: number | null; good: Good[]; note: string };

const kv = await Deno.openKv();
const enc = new TextEncoder();
const dec = new TextDecoder();

// ---------------------------------------------------------------- list fetching (cached in memory per isolate)
let listCache: { t: number; map: Map<string, string | null> } | null = null;
const IPPORT = /(?:(socks5|socks4|https?):\/\/)?(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})(?!\d)/i;

async function getList(src: string): Promise<string[]> {
  const def = src.toLowerCase().includes("socks5") ? "socks5" : src.toLowerCase().includes("socks4") ? "socks4" : "http";
  const r = await fetch(src, { headers: { "User-Agent": "Mozilla/5.0" }, signal: AbortSignal.timeout(15000) });
  if (!r.ok) return [];
  const buf = new Uint8Array(await r.arrayBuffer());
  const txt = dec.decode(buf.subarray(0, MAX_LIST_BYTES));
  const out: string[] = [];
  for (const raw of txt.split("\n")) {
    const line = raw.trim();
    if (line.toLowerCase().startsWith("https://")) continue; // TLS proxies: Chromium rejects the cert
    const m = IPPORT.exec(line);
    if (!m) continue;
    const port = parseInt(m[3], 10);
    if (port <= 0 || port >= 65536) continue;
    const sch = (m[1] || def).toLowerCase();
    if (sch === "socks4") continue;
    out.push(`${sch}://${m[2]}:${m[3]}`);
  }
  return out;
}

async function getAllProxies(): Promise<Map<string, string | null>> {
  const now = Date.now();
  if (listCache && now - listCache.t < LIST_TTL) return listCache.map;
  const jobs: [string | null, string][] = [
    ...SOURCES.map((s) => [null, s] as [string | null, string]),
    ...COUNTRIES.map((c) => [c, `${IPLOC}${c}/proxies.txt`] as [string | null, string]),
  ];
  const map = new Map<string, string | null>();
  const res = await Promise.all(jobs.map(async ([cc, src]) => {
    try {
      return [cc, await getList(src)] as [string | null, string[]];
    } catch {
      return [cc, []] as [string | null, string[]];
    }
  }));
  for (const [cc, list] of res) {
    for (const hp of list) if (cc || !map.has(hp)) map.set(hp, cc);
  }
  if (map.size) listCache = { t: now, map };
  else if (listCache) return listCache.map; // all fetches failed: keep the old list
  return map;
}

// ---------------------------------------------------------------- low-level socket helpers
class Reader {
  buf = new Uint8Array(0);
  conn: Deno.Conn;
  constructor(conn: Deno.Conn) {
    this.conn = conn;
  }
  async fill(): Promise<boolean> {
    const tmp = new Uint8Array(2048);
    const n = await this.conn.read(tmp);
    if (n === null) return false;
    const nb = new Uint8Array(this.buf.length + n);
    nb.set(this.buf);
    nb.set(tmp.subarray(0, n), this.buf.length);
    this.buf = nb;
    return true;
  }
  async exact(n: number): Promise<Uint8Array> {
    while (this.buf.length < n) if (!(await this.fill())) throw new Error("eof");
    const out = this.buf.slice(0, n);
    this.buf = this.buf.slice(n);
    return out;
  }
  async untilHeaderEnd(limit = 4096): Promise<string> {
    while (true) {
      const s = dec.decode(this.buf);
      const i = s.indexOf("\r\n\r\n");
      if (i >= 0) return s.slice(0, i);
      if (this.buf.length > limit) throw new Error("big");
      if (!(await this.fill())) return s;
    }
  }
}

async function writeAll(conn: Deno.Conn, data: Uint8Array) {
  let off = 0;
  while (off < data.length) off += await conn.write(data.subarray(off));
}

function statusOK(head: string): boolean {
  return /^HTTP\/1\.[01] 200/.test(head);
}

async function viaHttpProxy(host: string, port: number): Promise<boolean> {
  const conn = await Deno.connect({ hostname: host, port });
  let tls: Deno.TlsConn | null = null;
  try {
    const th = TEST_URL.hostname;
    const tp = TEST_URL.port || "443";
    await writeAll(conn, enc.encode(`CONNECT ${th}:${tp} HTTP/1.1\r\nHost: ${th}:${tp}\r\nUser-Agent: Mozilla/5.0\r\n\r\n`));
    const head = await new Reader(conn).untilHeaderEnd();
    if (!statusOK(head)) return false;
    tls = await Deno.startTls(conn, { hostname: th }); // certificate is verified
    await writeAll(tls, enc.encode(`GET ${TEST_URL.pathname}${TEST_URL.search} HTTP/1.1\r\nHost: ${th}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n`));
    const first = await new Reader(tls).untilHeaderEnd();
    return statusOK(first);
  } finally {
    try {
      (tls ?? conn).close();
    } catch { /* already closed */ }
  }
}

async function viaSocks5(host: string, port: number): Promise<boolean> {
  const conn = await Deno.connect({ hostname: host, port });
  let tls: Deno.TlsConn | null = null;
  try {
    const rd = new Reader(conn);
    await writeAll(conn, new Uint8Array([5, 1, 0])); // no auth
    const g = await rd.exact(2);
    if (g[0] !== 5 || g[1] !== 0) return false;
    const th = TEST_URL.hostname;
    const hb = enc.encode(th);
    const tp = parseInt(TEST_URL.port || "443", 10);
    const req = new Uint8Array(7 + hb.length);
    req.set([5, 1, 0, 3, hb.length]);
    req.set(hb, 5);
    req[5 + hb.length] = tp >> 8;
    req[6 + hb.length] = tp & 255;
    await writeAll(conn, req);
    const h = await rd.exact(4);
    if (h[0] !== 5 || h[1] !== 0) return false;
    if (h[3] === 1) await rd.exact(4 + 2);
    else if (h[3] === 4) await rd.exact(16 + 2);
    else if (h[3] === 3) {
      const l = (await rd.exact(1))[0];
      await rd.exact(l + 2);
    } else return false;
    tls = await Deno.startTls(conn, { hostname: th });
    await writeAll(tls, enc.encode(`GET ${TEST_URL.pathname}${TEST_URL.search} HTTP/1.1\r\nHost: ${th}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n`));
    return statusOK(await new Reader(tls).untilHeaderEnd());
  } finally {
    try {
      (tls ?? conn).close();
    } catch { /* already closed */ }
  }
}

async function testOne(hp: string): Promise<{ hp: string; ms: number } | null> {
  const t0 = Date.now();
  const [sch, rest] = hp.split("://");
  const i = rest.lastIndexOf(":");
  const host = rest.slice(0, i);
  const port = parseInt(rest.slice(i + 1), 10);
  let timer: number | undefined;
  const timeout = new Promise<boolean>((res) => {
    timer = setTimeout(() => res(false), MAX_MS);
  });
  try {
    const ok = await Promise.race([sch === "socks5" ? viaSocks5(host, port) : viaHttpProxy(host, port), timeout]);
    if (!ok) return null;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
  const ms = Date.now() - t0;
  return ms <= MAX_MS ? { hp, ms } : null;
}

async function mapLimit<T, R>(items: T[], limit: number, fn: (x: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (true) {
      const i = next++;
      if (i >= items.length) return;
      out[i] = await fn(items[i]);
    }
  }));
  return out;
}

// ---------------------------------------------------------------- scan (one batch)
async function loadSaved(): Promise<Saved> {
  const r = await kv.get<Saved>(["saved"]);
  return r.value ?? { updated: null, good: [], note: "abhi scan nahi hua" };
}

async function scanOnce(): Promise<string> {
  // simple lock so two overlapping scans don't clobber each other
  const lock = await kv.atomic().check({ key: ["lock"], versionstamp: null }).set(["lock"], 1, { expireIn: 60_000 }).commit();
  if (!lock.ok) return "scan already running";
  const t0 = Date.now();
  try {
    const saved = await loadSaved();
    const all = await getAllProxies();
    const have = new Set(saved.good.map((g) => g.hp));
    const keys = [...all.keys()].filter((k) => !have.has(k));
    for (let i = keys.length - 1; i > 0; i--) { // shuffle
      const j = Math.floor(Math.random() * (i + 1));
      [keys[i], keys[j]] = [keys[j], keys[i]];
    }
    const sample = [...saved.good.map((g) => g.hp), ...keys.slice(0, BATCH)]; // old good ones first, re-tested
    const res = await mapLimit(sample, WORKERS, testOne);
    const now = Date.now();
    const oldBy = new Map(saved.good.map((g) => [g.hp, g]));
    const good: Good[] = [];
    for (const r of res) {
      if (!r) continue;
      const prev = oldBy.get(r.hp);
      if (prev && now - prev.t > KEEP_AGE) continue; // too old, let it be replaced by fresh ones
      good.push({ hp: r.hp, ms: r.ms, cc: all.get(r.hp) ?? prev?.cc ?? null, t: prev?.t ?? now });
    }
    good.sort((a, b) => a.ms - b.ms);
    const out = good.slice(0, KEEP);
    const note = `${sample.length} test, ${res.filter(Boolean).length} chale, list me ${out.length}` +
      (out.length ? `, sabse tez ${out[0].ms} ms` : "") + ` (${Math.round((Date.now() - t0) / 1000)} sec)`;
    await kv.set(["saved"], { updated: Date.now(), good: out, note } satisfies Saved);
    console.log("scan:", note);
    return note;
  } catch (e) {
    const msg = `scan fail: ${(e as Error).name}`;
    console.log(msg, String(e).slice(0, 120));
    return msg;
  } finally {
    await kv.delete(["lock"]);
  }
}

// ---------------------------------------------------------------- cron (if Deno Deploy supports it for your project) + HTTP
try {
  Deno.cron("scan", "*/5 * * * *", async () => {
    await scanOnce();
  });
} catch (e) {
  console.log("cron unavailable, use /scan with an uptime bot:", String(e).slice(0, 100));
}

const json = (obj: unknown, code = 200) =>
  new Response(JSON.stringify(obj), {
    status: code,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });

Deno.serve(async (req) => {
  const u = new URL(req.url);
  if (u.pathname === "/ping") return new Response("ok", { headers: { "content-type": "text/plain" } });
  if (u.pathname === "/good" || u.pathname === "/scan") {
    if (KEY && u.searchParams.get("key") !== KEY) return json({ error: "key galat" }, 403);
    if (u.pathname === "/scan") return json({ note: await scanOnce() });
    const s = await loadSaved();
    return json({ updated: s.updated ? s.updated / 1000 : null, count: s.good.length, good: s.good.map((g) => ({ ...g, t: g.t / 1000 })) });
  }
  const s = await loadSaved();
  const ago = s.updated ? `${Math.round((Date.now() - s.updated) / 1000)} sec pehle` : "-";
  return new Response(`proxy scanner (deno)\nlist me: ${s.good.length}\nlast scan: ${ago}\n${s.note}\n`, {
    headers: { "content-type": "text/plain; charset=utf-8" },
  });
});
