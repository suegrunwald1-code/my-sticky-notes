export const config = { maxDuration: 30 };

function toProxy(fullUrl) {
  try {
    const u = new URL(fullUrl);
    const enc = Buffer.from(u.origin).toString("base64").replace(/=+$/, "");
    const p = u.pathname.replace(/\/+$/, "") || "";
    return `/r/${enc}${p}${u.search}${u.hash}`;
  } catch {
    return fullUrl;
  }
}

function rewriteHtml(body, encodedOrigin, restPath) {
  // 1. Rewrite absolute paths (starting with /) to go through proxy with same origin
  body = body.replace(/(src|href|action|poster)=(["'])\//g, `$1=$2/r/${encodedOrigin}/`);

  // 2. Rewrite protocol-relative URLs (//domain.com/path) in attributes
  body = body.replace(/(src|href|action|poster)=(["'])(\/\/[a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,}\/[^"']*)(["'])/gi, (match, attr, q1, url, q2) => {
    return `${attr}=${q1}${toProxy('https:' + url)}${q2}`;
  });
  // 3. Rewrite full https:// URLs in src/href/action/poster attributes to go through proxy
  body = body.replace(/(src|href|action|poster)=(["'])(https?:\/\/[^"']+)(["'])/gi, (match, attr, q1, url, q2) => {
    if (url.startsWith("data:") || url.startsWith("blob:") || url.startsWith("javascript:")) return match;
    return `${attr}=${q1}${toProxy(url)}${q2}`;
  });

  // 3a. Rewrite iframe src assignments in inline scripts
  body = body.replace(/(\.src\s*=\s*)(["'])(https?:\/\/[^"']+)(["'])/gi, (match, prefix, q1, url, q2) => {
    return `${prefix}${q1}${toProxy(url)}${q2}`;
  });
  // 3b. Rewrite setAttribute('src', 'https://...') in inline scripts
  body = body.replace(/(setAttribute\s*\(\s*["']src["']\s*,\s*)(["'])(https?:\/\/[^"']+)(["'])/gi, (match, prefix, q1, url, q2) => {
    return `${prefix}${q1}${toProxy(url)}${q2}`;
  });
  // 3c. Rewrite protocol-relative URLs (//domain.com/path) in inline JS string literals
  body = body.replace(/(["'])(\/\/[a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,}\/[^"']*)(["'])/g, (match, q1, url, q2) => {
    return `${q1}${toProxy('https:' + url)}${q2}`;
  });

  // 4. Rewrite window.location and document.location assignments
  body = body.replace(/((?:window|document)\.location(?:\.href)?\s*=\s*)(["'])(https?:\/\/[^"']+)(["'])/gi, (match, prefix, q1, url, q2) => {
    return `${prefix}${q1}${toProxy(url)}${q2}`;
  });

  // 5. Remove CSP and X-Frame-Options meta tags
  body = body.replace(/<meta[^>]*content-security-policy[^>]*>/gi, "");
  body = body.replace(/<meta[^>]*http-equiv\s*=\s*["']?X-Frame-Options[^>]*>/gi, "");

  // 6. Inject <base> tag and security script
  // Strip filename from restPath so relative assets resolve to the directory
  const basePath = restPath.includes(".") && !restPath.endsWith("/")
    ? restPath.replace(/\/[^/]*$/, "/")
    : restPath + (restPath.endsWith("/") ? "" : "/");
  const proxyBase = `/r/${encodedOrigin}${basePath}`;
  const baseTag = `<base href="${proxyBase}">`;
  const secScript = `<script>window.open=function(){return null};window.__open=function(){return null};</script>`;
  const inject = baseTag + secScript;
  if (body.includes("<head>")) {
    body = body.replace("<head>", `<head>${inject}`);
  } else if (body.includes("<head ")) {
    body = body.replace(/<head\s[^>]*>/, `$&${inject}`);
  } else if (body.includes("<HEAD>")) {
    body = body.replace("<HEAD>", `<HEAD>${inject}`);
  } else {
    body = inject + body;
  }

  // 7. GD game wrapper fallback: if SDK never fires SDK_GAME_START, load game directly
  if (body.includes("gamedistribution-jssdk") && (body.includes('id=game') || body.includes('id="game"'))) {
    // Extract the gameSrc from the inline script (already rewritten to proxy URL by step 3c)
    const srcMatch = body.match(/gameSrc\s*=\s*["']([^"']+)["']/);
    if (srcMatch) {
      const gameSrc = srcMatch[1].replace(/["']\s*\+\s*searchPart/, "");
      const fallback = `<script>(function(){var _fl=false;var _t=setTimeout(function(){var f=document.getElementById("game");if(f&&!f.src&&!_fl){_fl=true;f.src="${gameSrc.replace(/"/g, '\\"')}"}},3000);var _oo=window.GD_OPTIONS&&window.GD_OPTIONS.onEvent;if(window.GD_OPTIONS){window.GD_OPTIONS.onEvent=function(e){if(e&&e.name==="SDK_GAME_START"){_fl=true;clearTimeout(_t)}if(_oo)return _oo.call(this,e)}}})();</script>`;
      body = body.replace("</body>", fallback + "</body>");
    }
  }

  return body;
}

function rewriteCss(body, encodedOrigin) {
  // Rewrite absolute paths in url()
  body = body.replace(/url\(\s*(['"]?)\//g, `url($1/r/${encodedOrigin}/`);
  // Rewrite full URLs in url()
  body = body.replace(/url\(\s*(['"]?)(https?:\/\/[^)'"]+)(['"]?)\)/gi, (match, q1, url, q2) => {
    return `url(${q1}${toProxy(url)}${q2})`;
  });
  return body;
}

function rewriteJs(body, encodedOrigin) {
  // Neutralize domain-check redirects to blocked pages
  body = body.replace(/window\.location\.href\s*=\s*[^;]*blocked\.html[^;]*;/gi, 'void 0;');
  // Neutralize bloc_gard domain blocking checks
  body = body.replace(/\.bloc_gard\s*&&\s*!0\s*===\s*[^.]*\.bloc_gard\.enabled/g, 'false');
  // Neutralize "to-blocked-page" redirect behavior
  body = body.replace(/"to-blocked-page"\s*===\s*\w+\s*&&\s*this\._redirectToBlocking\([^)]*\)/g, 'false');
  body = body.replace(/this\._redirectToBlocking\([^)]*\)/g, 'void 0');
  // Neutralize _blockDirectTokenURLEmbedding - always return not blocked
  body = body.replace(/this\._blockDirectTokenURLEmbedding\(\)\.blocked/g, 'false');

  // Rewrite protocol-relative URLs (//domain.com/path) in JS
  body = body.replace(/(["'])(\/\/[a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,}\/[^"']*)(["'])/g, (match, q1, url, q2) => {
    return `${q1}${toProxy('https:' + url)}${q2}`;
  });
  // Rewrite ALL https:// string literals in JS (single/double quotes)
  body = body.replace(/(["'])(https?:\/\/[^"']+)(["'])/gi, (match, q1, url, q2) => {
    if (url.startsWith("data:") || url.startsWith("blob:")) return match;
    return `${q1}${toProxy(url)}${q2}`;
  });
  // Rewrite template literal URLs: `https://...`  and `https://...${
  body = body.replace(/(`)(https?:\/\/[^`$]+)/gi, (match, tick, url) => {
    try {
      const u = new URL(url.split("$")[0].split("`")[0]);
      const enc = Buffer.from(u.origin).toString("base64").replace(/=+$/, "");
      const p = u.pathname.replace(/\/+$/, "") || "";
      return `${tick}/r/${enc}${p}${u.search}`;
    } catch {
      return match;
    }
  });
  return body;
}

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
        "Origin": origin,
      },
      redirect: "follow",
    });

    const ct = upstreamRes.headers.get("content-type") || "application/octet-stream";
    const status = upstreamRes.status;

    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS, HEAD");
    res.setHeader("Access-Control-Allow-Headers", "*");
    res.setHeader("Cross-Origin-Resource-Policy", "cross-origin");

    if (req.method === "OPTIONS") return res.status(200).end();

    const skip = new Set([
      "x-frame-options", "content-security-policy",
      "content-security-policy-report-only", "content-encoding",
      "transfer-encoding", "connection", "keep-alive",
      "cross-origin-resource-policy", "cross-origin-embedder-policy",
      "cross-origin-opener-policy",
    ]);

    for (const [key, value] of upstreamRes.headers.entries()) {
      if (!skip.has(key.toLowerCase())) res.setHeader(key, value);
    }

    res.setHeader("content-type", ct);

    const isHTML = ct.includes("text/html");
    const isCSS = ct.includes("text/css");
    const isJS = ct.includes("javascript") || ct.includes("ecmascript");
    const encodedOrigin = segs[0];

    if (isHTML) {
      let body = await upstreamRes.text();
      body = rewriteHtml(body, encodedOrigin, restPath);
      res.status(status).send(body);
    } else if (isCSS) {
      let body = await upstreamRes.text();
      body = rewriteCss(body, encodedOrigin);
      res.status(status).send(body);
    } else if (isJS) {
      let body = await upstreamRes.text();
      body = rewriteJs(body, encodedOrigin);
      res.status(status).send(body);
    } else {
      const buffer = Buffer.from(await upstreamRes.arrayBuffer());
      res.status(status).send(buffer);
    }
  } catch (err) {
    res.status(502).send("Upstream error");
  }
}
