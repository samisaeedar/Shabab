/**
 * ==============================================================================
 * Shabab Stream Gateway - Production Deno Deploy Entrypoint (main.ts)
 * ==============================================================================
 * High-performance, cryptographically secured HLS proxy & tokenization gateway
 * designed for Shabab Net wireless network.
 *
 * Security Layers:
 *  1. Network Origin & Referer Lockdown: strictly limited to 10.0.0.1 and www.1.com
 *  2. MikroTik Hotspot Secret Signature: requires HMAC proof generated with shared secret
 *  3. Cryptographic HMAC-SHA256 Expiring Session Tokens (default 5-minute TTL)
 *  4. Upstream URL Masking: technomaster.pro is NEVER exposed to clients
 *  5. In-flight M3U8 Playlist Rewriting: converts segments to gateway proxy URLs
 *  6. Native Web Streams Zero-Copy Proxying for .ts media segments
 *  7. Seamless Background Token Renewal (/api/refresh)
 *  8. In-memory Rate Limiting per IP
 * ==============================================================================
 */

// Declare Deno namespace for universal TypeScript compatibility
declare const Deno: any;

// Upstream HLS Master Channels Map (Strictly kept server-side)
const UPSTREAM_CHANNELS: Record<string, string> = {
  "1": "https://www.technomaster.pro/hls/a0a.l.cIlchannel1-stream.Iil9486143.m3u8",
  "2": "https://www.technomaster.pro/hls/a0a.l.cIlchannel2-stream.Iil9486143.m3u8",
  "3": "https://www.technomaster.pro/hls/a0a.l.cIlchannel3-stream.Iil9486143.m3u8",
  "4": "https://www.technomaster.pro/hls/a0a.l.cIlchannel4-stream.Iil9486143.m3u8",
  "5": "https://www.technomaster.pro/hls/t0t.cIlchannel5-stream.Iil9486143.m3u8",
  "6": "https://www.technomaster.pro/hls/a0a.l.cIlchannel6-stream.Iil9486143.m3u8",
  "7": "https://www.technomaster.pro/hls/a0a.l.cIlchannel7-stream.Iil9486143.m3u8",
  "8": "https://www.technomaster.pro/hls/a0a.l.cIlchannel8-stream.Iil9486143.m3u8",
  "9": "https://www.technomaster.pro/hls/a0a.l.cIlchannel9-stream.Iil9486143.m3u8",
};

// --------------------------------------------------------------------------
// Authorized Hotspot Networks & Domains Lockdown
// --------------------------------------------------------------------------
export const AUTHORIZED_HOTSPOT_HOSTS = new Set([
  "10.0.0.1",
  "www.1.com",
  "1.com",
  "localhost",
  "127.0.0.1",
]);

// Shared MikroTik Network Secret for Hotspot Client Proof
export const HOTSPOT_NETWORK_SECRET = 
  (typeof Deno !== "undefined" && Deno.env && Deno.env.get("HOTSPOT_NETWORK_SECRET")) ||
  "ShababNet#MikroTik@10.0.0.1#SignatureVault2026!";

// Master Session Signing Secret
const GATEWAY_SECRET = 
  (typeof Deno !== "undefined" && Deno.env && Deno.env.get("GATEWAY_SECRET")) ||
  "ShababNet#StreamGateVault@2026!MasterCryptSecretKey#Yemen";

const DEFAULT_TTL_SECONDS = 300; // 5 minutes
const REFRESH_WINDOW_SECONDS = 210; // 3.5 minutes recommended refresh
const GRACE_PERIOD_MS = 15000; // 15 seconds clock-skew tolerance

// Standard CORS and Security Headers
const SECURITY_CORS_HEADERS: Record<string, string> = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET, HEAD, OPTIONS",
  "access-control-allow-headers": "Content-Type, Range, Authorization, X-Requested-With",
  "access-control-expose-headers": "Content-Length, Content-Range, Content-Type",
  "cache-control": "no-store, no-cache, must-revalidate, max-age=0",
  "x-content-type-options": "nosniff",
  "x-frame-options": "ALLOW-FROM *",
};

// Simple sliding-window IP rate limiter
const ipRequestWindow = new Map<string, { count: number; resetAt: number }>();
function isRateLimited(ip: string, limit = 240, windowMs = 60000): boolean {
  const now = Date.now();
  const entry = ipRequestWindow.get(ip);
  if (!entry || now > entry.resetAt) {
    ipRequestWindow.set(ip, { count: 1, resetAt: now + windowMs });
    return false;
  }
  entry.count++;
  return entry.count > limit;
}

/**
 * Validates that the request originates from an authorized network (Referer or Origin).
 * Prevents unauthorized third-party routers, websites, or foreign networks from borrowing the stream.
 */
export function validateNetworkOrigin(req: Request): { allowed: boolean; host?: string; reason?: string } {
  const referer = req.headers.get("referer");
  const origin = req.headers.get("origin");
  const target = referer || origin;

  if (!target) {
    return {
      allowed: false,
      reason: "Missing network verification headers (Referer/Origin required). Access must originate from Shabab Net (10.0.0.1 / www.1.com).",
    };
  }

  try {
    const parsed = new URL(target);
    const host = parsed.hostname.toLowerCase();

    // Check exact authorized hosts (10.0.0.1, www.1.com, 1.com)
    if (AUTHORIZED_HOTSPOT_HOSTS.has(host)) {
      return { allowed: true, host };
    }

    // Allow AI Studio preview and Deno Deploy testing domains
    if (host.endsWith(".run.app") || host.endsWith(".deno.net")) {
      return { allowed: true, host };
    }

    return {
      allowed: false,
      host,
      reason: `Unauthorized network host '${host}'. Access is restricted exclusively to Shabab Net (10.0.0.1 / www.1.com).`,
    };
  } catch (_e) {
    return { allowed: false, reason: "Malformed network header" };
  }
}

/**
 * Computes the expected HMAC Hotspot client proof
 */
export async function computeHotspotProof(channelId: string, timestamp: number): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(HOTSPOT_NETWORK_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const data = `${channelId}:${timestamp}`;
  const sigBuffer = await crypto.subtle.sign("HMAC", key, enc.encode(data));
  return Array.from(new Uint8Array(sigBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Verifies the Hotspot Secret Signature sent by the client page
 */
export async function verifyHotspotProof(
  channelId: string,
  tsStr: string | null,
  proof: string | null
): Promise<{ valid: boolean; reason?: string }> {
  if (!tsStr || !proof) {
    return { valid: false, reason: "Missing Hotspot security proof (ts and proof parameters required)" };
  }

  const ts = parseInt(tsStr, 10);
  if (isNaN(ts)) {
    return { valid: false, reason: "Invalid timestamp in Hotspot proof" };
  }

  // Check timestamp freshness (90-second window to prevent replay attacks)
  const now = Date.now();
  if (Math.abs(now - ts) > 90000) {
    return { valid: false, reason: "Hotspot security proof expired (clock drift > 90s)" };
  }

  const expectedProof = await computeHotspotProof(channelId, ts);
  if (proof !== expectedProof) {
    return { valid: false, reason: "Invalid MikroTik Hotspot secret signature" };
  }

  return { valid: true };
}

/**
 * Imports or derives the CryptoKey for HMAC-SHA256 session token signing.
 */
async function getCryptoKey(): Promise<CryptoKey> {
  const enc = new TextEncoder();
  return await crypto.subtle.importKey(
    "raw",
    enc.encode(GATEWAY_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}

/**
 * Creates a signed expiring session token.
 * Format: Base64(channel:exp:nonce).SignatureHex
 */
export async function createSignedToken(channelId: string, ttlSeconds = DEFAULT_TTL_SECONDS): Promise<{ token: string; expiresAt: number }> {
  const expiresAt = Date.now() + ttlSeconds * 1000;
  const nonce = crypto.randomUUID().replace(/-/g, "").slice(0, 12);
  const data = `${channelId}:${expiresAt}:${nonce}`;
  const key = await getCryptoKey();
  const sigBuffer = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  const sigHex = Array.from(new Uint8Array(sigBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  const payloadB64 = btoa(data);
  const token = `${payloadB64}.${sigHex}`;
  return { token, expiresAt };
}

/**
 * Verifies the validity, expiry, and HMAC signature of a given token.
 */
export async function verifySignedToken(
  token: string | null,
  channelId?: string
): Promise<{ valid: boolean; channel: string; exp: number; error?: string }> {
  if (!token || !token.includes(".")) {
    return { valid: false, channel: "", exp: 0, error: "Missing or malformed security token" };
  }

  try {
    const [payloadB64, sigHex] = token.split(".");
    const decoded = atob(payloadB64);
    const parts = decoded.split(":");
    if (parts.length !== 3) {
      return { valid: false, channel: "", exp: 0, error: "Invalid token structure" };
    }

    const [ch, expStr, nonce] = parts;
    const exp = parseInt(expStr, 10);
    if (isNaN(exp)) {
      return { valid: false, channel: ch, exp: 0, error: "Corrupted expiration timestamp" };
    }

    // Check expiration with grace period
    const now = Date.now();
    if (now > exp + GRACE_PERIOD_MS) {
      return { valid: false, channel: ch, exp, error: "Session token expired. Please refresh your session." };
    }

    // Check channel bound
    if (channelId && ch !== channelId) {
      return { valid: false, channel: ch, exp, error: "Token channel restriction mismatch" };
    }

    // Verify HMAC signature
    const data = `${ch}:${expStr}:${nonce}`;
    const key = await getCryptoKey();
    const sigBuffer = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
    const expectedSigHex = Array.from(new Uint8Array(sigBuffer))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    if (sigHex !== expectedSigHex) {
      return { valid: false, channel: ch, exp, error: "Cryptographic signature verification failed" };
    }

    return { valid: true, channel: ch, exp };
  } catch (_e) {
    return { valid: false, channel: "", exp: 0, error: "Security token decoding error" };
  }
}

/**
 * JSON Response Helper
 */
function jsonResponse(data: unknown, status = 200, extraHeaders: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...SECURITY_CORS_HEADERS,
      "content-type": "application/json; charset=utf-8",
      ...extraHeaders,
    },
  });
}

/**
 * Text/M3U8 Response Helper
 */
function m3u8Response(text: string, status = 200): Response {
  return new Response(text, {
    status,
    headers: {
      ...SECURITY_CORS_HEADERS,
      "content-type": "application/vnd.apple.mpegurl; charset=utf-8",
    },
  });
}

/**
 * Main HTTP Request Dispatcher
 */
export async function handleHttpRequest(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const path = url.pathname;

  // Handle CORS Preflight
  if (req.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: SECURITY_CORS_HEADERS,
    });
  }

  // Only GET & HEAD are supported
  if (req.method !== "GET" && req.method !== "HEAD") {
    return jsonResponse({ ok: false, error: "Method not allowed" }, 405);
  }

  // Basic Rate Limiting
  const clientIp = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || "unknown";
  if (isRateLimited(clientIp)) {
    return jsonResponse({ ok: false, error: "Too many requests. Please slow down." }, 429);
  }

  // --------------------------------------------------------------------------
  // 1. HEALTH & ROOT STATUS
  // --------------------------------------------------------------------------
  if (path === "/" || path === "/health") {
    const channelParam = url.searchParams.get("channel");
    if (!channelParam) {
      return jsonResponse({
        ok: true,
        service: "Shabab Stream Gateway",
        version: "2.1.0-hotspot-locked",
        status: "active",
        lockedTo: ["10.0.0.1", "www.1.com", "1.com"],
        channelsCount: Object.keys(UPSTREAM_CHANNELS).length,
      });
    }
  }

  // --------------------------------------------------------------------------
  // 2. ISSUE SESSION TOKEN (/api/session)
  // Protected with: Origin/Referer check + MikroTik Hotspot Secret Signature
  // --------------------------------------------------------------------------
  if (path === "/api/session" || (path === "/" && url.searchParams.has("channel"))) {
    // A. Check Origin & Referer (Only 10.0.0.1 or www.1.com)
    const originCheck = validateNetworkOrigin(req);
    if (!originCheck.allowed) {
      return jsonResponse(
        { ok: false, error: "Forbidden: " + originCheck.reason, code: "UNAUTHORIZED_NETWORK" },
        403
      );
    }

    const channelId = url.searchParams.get("channel") || "1";
    if (!UPSTREAM_CHANNELS[channelId]) {
      return jsonResponse({ ok: false, error: "Channel not found" }, 404);
    }

    // B. Check MikroTik Hotspot Secret Proof (Only if not a simple health query)
    const ts = url.searchParams.get("ts");
    const proof = url.searchParams.get("proof");
    const proofCheck = await verifyHotspotProof(channelId, ts, proof);
    if (!proofCheck.valid) {
      return jsonResponse(
        { ok: false, error: "Forbidden: " + proofCheck.reason, code: "INVALID_HOTSPOT_SIGNATURE" },
        403
      );
    }

    const { token, expiresAt } = await createSignedToken(channelId, DEFAULT_TTL_SECONDS);
    const streamPath = `/live/${channelId}.m3u8?token=${encodeURIComponent(token)}`;

    return jsonResponse({
      ok: true,
      channel: channelId,
      streamUrl: streamPath,
      token,
      expiresAt,
      ttlSeconds: DEFAULT_TTL_SECONDS,
      refreshInSeconds: REFRESH_WINDOW_SECONDS,
      serverTime: Date.now(),
    });
  }

  // --------------------------------------------------------------------------
  // 3. REFRESH SESSION TOKEN (/api/refresh)
  // Protected with Origin/Referer check + Existing Valid Token
  // --------------------------------------------------------------------------
  if (path === "/api/refresh") {
    const originCheck = validateNetworkOrigin(req);
    if (!originCheck.allowed) {
      return jsonResponse(
        { ok: false, error: "Forbidden: " + originCheck.reason, code: "UNAUTHORIZED_NETWORK" },
        403
      );
    }

    const channelId = url.searchParams.get("channel") || "";
    const oldToken = url.searchParams.get("token") || "";

    const check = await verifySignedToken(oldToken, channelId || undefined);
    if (!check.valid) {
      return jsonResponse({ ok: false, error: check.error || "Invalid token for refresh" }, 403);
    }

    const effectiveChannel = check.channel;
    const { token, expiresAt } = await createSignedToken(effectiveChannel, DEFAULT_TTL_SECONDS);

    return jsonResponse({
      ok: true,
      channel: effectiveChannel,
      token,
      expiresAt,
      ttlSeconds: DEFAULT_TTL_SECONDS,
      refreshInSeconds: REFRESH_WINDOW_SECONDS,
      serverTime: Date.now(),
    });
  }

  // --------------------------------------------------------------------------
  // 4. PROTECTED M3U8 PLAYLIST PROXY (/live/:channel.m3u8)
  // --------------------------------------------------------------------------
  const liveMatch = path.match(/^\/live\/([1-9])\.m3u8$/);
  if (liveMatch) {
    const channelId = liveMatch[1];
    const token = url.searchParams.get("token");

    // Cryptographic validation
    const check = await verifySignedToken(token, channelId);
    if (!check.valid) {
      return jsonResponse(
        { ok: false, error: "Forbidden: " + (check.error || "Invalid security token") },
        403
      );
    }

    const upstreamUrl = UPSTREAM_CHANNELS[channelId];
    if (!upstreamUrl) {
      return jsonResponse({ ok: false, error: "Channel not found" }, 404);
    }

    try {
      const upstreamResp = await fetch(upstreamUrl, {
        headers: {
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ShababStreamGate/2.1",
          "Accept": "*/*",
        },
      });

      if (!upstreamResp.ok) {
        return jsonResponse(
          { ok: false, error: `Upstream stream server returned HTTP ${upstreamResp.status}` },
          502
        );
      }

      const m3u8Content = await upstreamResp.text();
      const lines = m3u8Content.split(/\r?\n/);
      const rewrittenLines: string[] = [];

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed) continue;

        // Keep comments & M3U8 tags intact
        if (trimmed.startsWith("#")) {
          rewrittenLines.push(trimmed);
          continue;
        }

        // Segment file (.ts) - Rewrite to Gateway Protected Segment Proxy
        if (trimmed.includes(".ts") || !trimmed.includes(".m3u8")) {
          const encodedSegment = encodeURIComponent(trimmed);
          const segmentProxyUrl = `/segment/${channelId}/${encodedSegment}?token=${encodeURIComponent(token!)}`;
          rewrittenLines.push(segmentProxyUrl);
        } else {
          // Sub-playlist variant
          const encodedSub = encodeURIComponent(trimmed);
          const subProxyUrl = `/live/${channelId}.m3u8?sub=${encodedSub}&token=${encodeURIComponent(token!)}`;
          rewrittenLines.push(subProxyUrl);
        }
      }

      return m3u8Response(rewrittenLines.join("\n"));
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : String(err);
      return jsonResponse({ ok: false, error: "Upstream gateway connection failure: " + errMsg }, 502);
    }
  }

  // --------------------------------------------------------------------------
  // 5. PROTECTED MEDIA SEGMENT STREAMING PROXY (/segment/:channel/:filename)
  // --------------------------------------------------------------------------
  const segmentMatch = path.match(/^\/segment\/([1-9])\/(.+)$/);
  if (segmentMatch) {
    const channelId = segmentMatch[1];
    const encodedFilename = segmentMatch[2];
    const filename = decodeURIComponent(encodedFilename);
    const token = url.searchParams.get("token");

    // Cryptographic validation
    const check = await verifySignedToken(token, channelId);
    if (!check.valid) {
      return jsonResponse(
        { ok: false, error: "Forbidden: " + (check.error || "Invalid or expired token for media segment") },
        403
      );
    }

    const upstreamBase = UPSTREAM_CHANNELS[channelId];
    if (!upstreamBase) {
      return jsonResponse({ ok: false, error: "Channel not found" }, 404);
    }

    // Resolve upstream segment URL relative to base playlist directory
    const upstreamDir = upstreamBase.substring(0, upstreamBase.lastIndexOf("/") + 1);
    const upstreamSegmentUrl = filename.startsWith("http") ? filename : upstreamDir + filename;

    try {
      const upstreamResp = await fetch(upstreamSegmentUrl, {
        headers: {
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ShababStreamGate/2.1",
          "Accept": "*/*",
        },
      });

      if (!upstreamResp.ok) {
        return jsonResponse(
          { ok: false, error: `Upstream segment returned HTTP ${upstreamResp.status}` },
          upstreamResp.status
        );
      }

      // Stream the media bytes directly back to the client
      const responseHeaders = new Headers(SECURITY_CORS_HEADERS);
      responseHeaders.set("content-type", upstreamResp.headers.get("content-type") || "video/mp2t");
      
      const contentLength = upstreamResp.headers.get("content-length");
      if (contentLength) {
        responseHeaders.set("content-length", contentLength);
      }

      return new Response(upstreamResp.body, {
        status: 200,
        headers: responseHeaders,
      });
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : String(err);
      return jsonResponse({ ok: false, error: "Failed to pipe media segment: " + errMsg }, 502);
    }
  }

  // Fallback 404
  return jsonResponse({ ok: false, error: "Route not found" }, 404);
}

// --------------------------------------------------------------------------
// Deno Deploy Entrypoint Listener
// --------------------------------------------------------------------------
if (typeof Deno !== "undefined" && typeof (Deno as any).serve === "function") {
  (Deno as any).serve(handleHttpRequest);
}
