// DJAEGER DNS — DNS-over-HTTPS handler untuk Vercel.
// Dipetakan dari /dns-query via vercel.json (rewrite -> /api/dns-query).
// Mekanisme sama dengan worker dns9r: query cocok blocklist -> NXDOMAIN,
// lolos -> forward ke 1.1.1.1 / 8.8.8.8.
// Blocklist (base 77 + learned dari eye.sh STB) diambil dari
// https://dns9r.schatzrasta.workers.dev/lists/djaeger.txt (format AdGuard),
// di-cache 10 menit di memory instance.

export const config = { api: { bodyParser: false } };

const LIST_URL = "https://dns9r.schatzrasta.workers.dev/lists/djaeger.txt";
const UPSTREAMS = ["https://1.1.1.1/dns-query", "https://dns.google/dns-query"];
const LIST_TTL_MS = 10 * 60 * 1000;
const UA = "DJAEGER-dns-vercel/1.0";

let blockCache = { at: 0, set: new Set() };

function cleanDomain(d) {
  if (typeof d !== "string") return "";
  d = d.trim().toLowerCase();
  if (d.endsWith(".")) d = d.slice(0, -1);
  if (!/^(?=.{1,253}$)(?!-)[a-z0-9-]+(\.[a-z0-9-]+)*$/.test(d)) return "";
  return d;
}

// Parse DNS wireformat: ambil ID, QNAME, QTYPE. Hanya QDCOUNT=1.
function parseQuery(buf) {
  if (!buf || buf.length < 12) return null;
  if (buf.readUInt16BE(4) !== 1) return null; // QDCOUNT
  let off = 12;
  const labels = [];
  while (off < buf.length) {
    const len = buf[off++];
    if (len === 0) break;
    if (len > 63 || off + len > buf.length) return null;
    labels.push(buf.slice(off, off + len).toString("ascii"));
    off += len;
  }
  if (off + 4 > buf.length) return null;
  const name = cleanDomain(labels.join("."));
  if (!name) return null;
  return { buf, id: buf.readUInt16BE(0), name, qend: off + 4 };
}

// Bangun respons NXDOMAIN: salin header+question, flags QR|RD|RA + RCODE 3.
function nxdomain(q) {
  const out = Buffer.alloc(q.qend);
  q.buf.copy(out, 0, 0, q.qend);
  out.writeUInt16BE(q.id, 0);
  out.writeUInt16BE(0x8183, 2);
  out.writeUInt16BE(1, 4);
  out.writeUInt16BE(0, 6);
  out.writeUInt16BE(0, 8);
  out.writeUInt16BE(0, 10);
  return out;
}

// Suffix-match: ads.doubleclick.net cocok bila doubleclick.net di set.
function isBlocked(name, set) {
  let d = name;
  while (d) {
    if (set.has(d)) return true;
    const i = d.indexOf(".");
    if (i < 0) break;
    d = d.slice(i + 1);
  }
  return false;
}

async function getBlockSet() {
  if (Date.now() - blockCache.at < LIST_TTL_MS && blockCache.set.size > 0) {
    return blockCache.set;
  }
  try {
    const r = await fetch(LIST_URL, { headers: { "User-Agent": UA } });
    if (!r.ok) throw new Error("list http " + r.status);
    const text = await r.text();
    const set = new Set();
    for (const line of text.split("\n")) {
      const m = line.trim().match(/^\|\|([a-z0-9.-]+)\^$/);
      if (m) set.add(m[1]);
    }
    if (set.size > 0) blockCache = { at: Date.now(), set };
  } catch (e) {
    // cache lama tetap dipakai bila fetch gagal
  }
  return blockCache.set;
}

async function forward(wire) {
  for (const up of UPSTREAMS) {
    try {
      const r = await fetch(up, {
        method: "POST",
        headers: { "content-type": "application/dns-message", "User-Agent": UA },
        body: wire,
      });
      if (r.ok) return Buffer.from(await r.arrayBuffer());
    } catch (e) {
      /* coba upstream berikutnya */
    }
  }
  return null;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

export default async function handler(req, res) {
  try {
    let wire = null;

    if (req.method === "POST") {
      wire = await readBody(req);
    } else if (req.method === "GET") {
      if (req.query.dns) {
        const b64 = String(req.query.dns).replace(/-/g, "+").replace(/_/g, "/");
        wire = Buffer.from(b64, "base64");
      } else if (req.query.name) {
        const set = await getBlockSet();
        const name = cleanDomain(req.query.name);
        res.status(200).json({ ok: true, name, blocked: isBlocked(name, set) });
        return;
      }
    }

    if (!wire || wire.length === 0) {
      res.status(400).json({ ok: false, error: "BAD_QUERY" });
      return;
    }

    const q = parseQuery(wire);
    const set = await getBlockSet();

    let out;
    if (q && isBlocked(q.name, set)) {
      out = nxdomain(q); // iklan/tracker -> NXDOMAIN
    } else {
      out = await forward(wire); // bersih -> teruskan ke upstream
    }

    if (!out) {
      res.status(502).json({ ok: false, error: "UPSTREAM_FAIL" });
      return;
    }
    res.setHeader("content-type", "application/dns-message");
    res.setHeader("content-length", String(out.length));
    res.status(200).send(out);
  } catch (e) {
    res.status(500).json({ ok: false, error: "INTERNAL" });
  }
}
