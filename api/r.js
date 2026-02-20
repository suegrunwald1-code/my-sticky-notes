export const config = { maxDuration: 30 };

const _K = [83, 116, 105, 99, 107, 121];

function _enc(str) {
  const b = Buffer.from(str);
  const out = [];
  for (let i = 0; i < b.length; i++) {
    out.push((b[i] ^ _K[i % _K.length]).toString(16).padStart(2, "0"));
  }
  return out.join("");
}

function _dec(hex) {
  const bytes = [];
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.substring(i, i + 2), 16) ^ _K[(i / 2) % _K.length]);
  }
  return Buffer.from(bytes).toString("utf-8");
}

function toProxy(fullUrl) {
  try {
    const u = new URL(fullUrl);
    const enc = _enc(u.origin);
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
  const secScript = `<script>window.open=function(){return null};window.__open=function(){return null};` +
    // Interceptor: rewrite all dynamic requests to use full-URL encoding
    `(function(){` +
    `var K=[83,116,105,99,107,121];` +
    `function E(s){var b=new TextEncoder().encode(s);var o="";for(var i=0;i<b.length;i++){o+=((b[i]^K[i%K.length]).toString(16)).padStart(2,"0")}return o}` +
    `function R(u){try{var base=document.querySelector("base");var bh=base?base.href:location.href;var a=new URL(u,bh);if(a.protocol==="data:"||a.protocol==="blob:"||a.protocol==="javascript:")return u;if(a.origin!==location.origin){return"/r/_/"+E(a.href)}if(a.pathname.startsWith("/r/")){var p=a.pathname.replace(/^\\/r\\/[^/]+/,"");var oh=a.pathname.match(/^\\/r\\/([^/]+)/);if(oh){try{var bytes=[];var h=oh[1];for(var i=0;i<h.length;i+=2){bytes.push(parseInt(h.substring(i,i+2),16)^K[(i/2)%K.length])}var orig=new TextDecoder().decode(new Uint8Array(bytes));return"/r/_/"+E(orig+p+a.search+a.hash)}catch(e){}}}return u}catch(e){return u}}` +
    // Override fetch
    `var _f=window.fetch;window.fetch=function(a,b){if(typeof a==="string")a=R(a);else if(a&&a.url)a=new Request(R(a.url),a);return _f.call(this,a,b)};` +
    // Override XMLHttpRequest.open
    `var _x=XMLHttpRequest.prototype.open;XMLHttpRequest.prototype.open=function(m,u){u=R(u);return _x.apply(this,arguments)};` +
    // Override element src/href setters for dynamic elements
    `function W(tag,attr){var d=Object.getOwnPropertyDescriptor(tag.prototype,attr);if(d&&d.set){var os=d.set;Object.defineProperty(tag.prototype,attr,{set:function(v){os.call(this,R(v))},get:d.get})}}` +
    `try{W(HTMLImageElement,"src");W(HTMLScriptElement,"src");W(HTMLAudioElement,"src");W(HTMLVideoElement,"src");W(HTMLSourceElement,"src");W(HTMLIFrameElement,"src");W(HTMLLinkElement,"href")}catch(e){}` +
    `})();</script>`;
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
      const enc = _enc(u.origin);
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

  const urlObj = new URL(req.url, "http://localhost");
  const params = new URLSearchParams(urlObj.search);
  params.delete("_p");
  const qs = params.toString() ? "?" + params.toString() : "";

  let upstream, origin, encodedOrigin, restPath;

  if (segs[0] === "_" && segs.length >= 2) {
    // Full-URL mode: /r/_/FULL_ENCODED_HEX
    try {
      upstream = _dec(segs[1]);
    } catch {
      return res.status(400).send("Bad request");
    }
    if (qs) upstream += (upstream.includes("?") ? "&" : "?") + params.toString();
    const u = new URL(upstream);
    origin = u.origin;
    encodedOrigin = _enc(origin);
    restPath = u.pathname;
  } else {
    // Origin+path mode: /r/ENCODED_ORIGIN/path/...
    encodedOrigin = segs[0];
    try {
      origin = _dec(encodedOrigin);
    } catch {
      return res.status(400).send("Bad request");
    }
    if (!origin.startsWith("http")) return res.status(400).send("Bad request");
    restPath = segs.length > 1 ? "/" + segs.slice(1).join("/") : "/";
    upstream = origin + restPath + qs;
  }

  if (!upstream.startsWith("http")) return res.status(400).send("Bad request");

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
      "report-to", "nel", "server", "cf-ray", "cf-cache-status",
      "x-served-by", "x-cache", "x-cache-hits", "x-timer",
      "via", "alt-svc", "server-timing",
    ]);

    for (const [key, value] of upstreamRes.headers.entries()) {
      if (!skip.has(key.toLowerCase())) res.setHeader(key, value);
    }

    // Fix WASM MIME type - browsers require application/wasm for WebAssembly.instantiateStreaming
    const isWasm = upstream.endsWith(".wasm") || ct.includes("application/wasm");
    if (isWasm) {
      res.setHeader("content-type", "application/wasm");
    } else {
      res.setHeader("content-type", ct);
    }

    const isHTML = ct.includes("text/html");
    const isCSS = ct.includes("text/css");
    const isJS = ct.includes("javascript") || ct.includes("ecmascript");

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
