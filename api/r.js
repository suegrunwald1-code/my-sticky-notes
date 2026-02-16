export default async function handler(req, res) {
  const raw = req.query._p || req.url.replace(/^\/api\/r\/?/, "").replace(/^\/r\/?/, "");
  if (!raw) return res.status(400).send("Bad request");

  const segs = raw.split("/").filter(Boolean);
  if (segs.length < 1) return res.status(400).send("Bad request");

  let encoded = segs[0];
  const pad = (4 - (encoded.length % 4)) % 4;
  encoded += "=".repeat(pad);

  let origin;
  try {
    origin = Buffer.from(encoded, "base64").toString("utf-8");
  } catch {
    return res.status(400).send("Bad request");
  }

  const restPath = segs.length > 1 ? "/" + segs.slice(1).join("/") : "/";

  const urlObj = new URL(req.url, "http://localhost");
  const params = new URLSearchParams(urlObj.search);
  params.delete("_p");
  const qs = params.toString() ? "?" + params.toString() : "";

  const upstream = origin + restPath + qs;

  try {
    const upstreamRes = await fetch(upstream, {
      headers: {
        "User-Agent": req.headers["user-agent"] || "Mozilla/5.0",
        "Accept": req.headers["accept"] || "*/*",
        "Accept-Encoding": "identity",
        "Referer": origin + "/",
      },
      redirect: "follow",
    });

    const ct = upstreamRes.headers.get("content-type") || "application/octet-stream";
    const status = upstreamRes.status;

    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "*");

    if (req.method === "OPTIONS") return res.status(200).end();

    const skip = new Set([
      "x-frame-options", "content-security-policy",
      "content-security-policy-report-only", "content-encoding",
      "transfer-encoding", "connection", "keep-alive",
    ]);

    for (const [key, value] of upstreamRes.headers.entries()) {
      if (!skip.has(key.toLowerCase())) res.setHeader(key, value);
    }

    res.setHeader("content-type", ct);

    const isHTML = ct.includes("text/html");
    const isCSS = ct.includes("text/css");
    const encodedOrigin = segs[0];

    if (isHTML || isCSS) {
      let body = await upstreamRes.text();
      if (isHTML) {
        body = body.replace(/(src|href|action)=(["'])\//g, `$1=$2/r/${encodedOrigin}/`);
        body = body.replace(/<meta[^>]*content-security-policy[^>]*>/gi, "");
      }
      if (isCSS) {
        body = body.replace(/url\(\s*(['"]?)\//g, `url($1/r/${encodedOrigin}/`);
      }
      res.status(status).send(body);
    } else {
      const buffer = Buffer.from(await upstreamRes.arrayBuffer());
      res.status(status).send(buffer);
    }
  } catch (err) {
    res.status(502).send("Upstream error");
  }
}
