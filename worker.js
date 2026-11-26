/**
 * Cloudflare Worker — Secure Server-Side Auth (PBKDF2-SHA256 + HttpOnly HMAC Cookie)
 * & Global Permanent Profile Storage (Cloudflare KV).
 *
 * ZERO hardcoded default passwords.
 * First admin setup runs once via POST /api/auth/setup and locks permanently in PROFILE_KV.
 */

const COOKIE_NAME = "kv_admin_session";
const PBKDF2_ITERATIONS = 100000;
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 30; // 30 days
const MAX_LOGIN_FAILS = 5;
const LOCKOUT_SECONDS = 60 * 15; // 15 minutes

const SECURITY_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "strict-origin-when-cross-origin"
};

function jsonResponse(obj, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...SECURITY_HEADERS,
      ...extraHeaders
    }
  });
}

function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex) {
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < arr.length; i++) {
    arr[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return arr;
}

function timingSafeEqualHex(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

async function pbkdf2Hash(password, saltHex, iterations = PBKDF2_ITERATIONS) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: hexToBytes(saltHex),
      iterations,
      hash: "SHA-256"
    },
    keyMaterial,
    256
  );
  return bytesToHex(new Uint8Array(bits));
}

async function hmacSign(secretHex, message) {
  const key = await crypto.subtle.importKey(
    "raw",
    hexToBytes(secretHex),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return bytesToHex(new Uint8Array(sig));
}

function randomHex(byteLen = 32) {
  const arr = new Uint8Array(byteLen);
  crypto.getRandomValues(arr);
  return bytesToHex(arr);
}

function parseCookies(cookieHeader) {
  const out = {};
  if (!cookieHeader) return out;
  cookieHeader.split(";").forEach((part) => {
    const idx = part.indexOf("=");
    if (idx > 0) {
      out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
    }
  });
  return out;
}

function buildSessionCookie(token, isHttps, maxAge = SESSION_TTL_SECONDS) {
  const attrs = [
    `${COOKIE_NAME}=${encodeURIComponent(token)}`,
    "HttpOnly",
    "SameSite=Strict",
    "Path=/",
    `Max-Age=${maxAge}`
  ];
  if (isHttps) attrs.push("Secure");
  return attrs.join("; ");
}

async function getOrCreateSessionSecret(env) {
  let secret = await env.PROFILE_KV.get("session_secret");
  if (!secret) {
    secret = randomHex(32);
    await env.PROFILE_KV.put("session_secret", secret);
  }
  return secret;
}

async function issueSessionToken(env, tokenVersion) {
  const secret = await getOrCreateSessionSecret(env);
  const exp = Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS;
  const payload = `${tokenVersion}.${exp}`;
  const sig = await hmacSign(secret, payload);
  return `${payload}.${sig}`;
}

async function verifySession(request, env, authRecord) {
  if (!authRecord) return false;
  const cookies = parseCookies(request.headers.get("Cookie"));
  const token = cookies[COOKIE_NAME];
  if (!token) return false;

  const parts = token.split(".");
  if (parts.length !== 3) return false;
  const [verStr, expStr, sig] = parts;
  const exp = Number(expStr);
  if (!Number.isFinite(exp) || exp < Math.floor(Date.now() / 1000)) return false;
  if (Number(verStr) !== Number(authRecord.version || 1)) return false;

  const secret = await env.PROFILE_KV.get("session_secret");
  if (!secret) return false;
  const expectedSig = await hmacSign(secret, `${verStr}.${expStr}`);
  return timingSafeEqualHex(sig, expectedSig);
}

async function getAuthRecord(env) {
  if (!env.PROFILE_KV) return null;
  const raw = await env.PROFILE_KV.get("admin_auth");
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch (_) {
    return null;
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const isHttps = url.protocol === "https:";
    const kvReady = !!env.PROFILE_KV;

    // Protect worker source & config from ever being served as static assets
    if (url.pathname === "/worker.js" || url.pathname === "/wrangler.toml") {
      return new Response("Forbidden", { status: 403, headers: SECURITY_HEADERS });
    }

    // 1. Auth Status (auto-detects HttpOnly session cookie)
    if (url.pathname === "/api/auth/status" && request.method === "GET") {
      if (!kvReady) {
        return jsonResponse({ kvReady: false, initialized: false, isAdmin: false });
      }
      const authRecord = await getAuthRecord(env);
      const isAdmin = await verifySession(request, env, authRecord);
      return jsonResponse({
        kvReady: true,
        initialized: !!authRecord,
        isAdmin
      });
    }

    // 2. First-Time Admin Setup (ONLY works once when no password exists)
    if (url.pathname === "/api/auth/setup" && request.method === "POST") {
      if (!kvReady) return jsonResponse({ error: "Chưa gắn PROFILE_KV" }, 501);
      const existing = await getAuthRecord(env);
      if (existing) {
        return jsonResponse({ error: "Mật khẩu Admin đã được thiết lập từ trước." }, 409);
      }
      const { password } = await request.json().catch(() => ({}));
      if (typeof password !== "string" || password.length < 6) {
        return jsonResponse({ error: "Mật khẩu cần tối thiểu 6 ký tự." }, 400);
      }

      const salt = randomHex(16);
      const hash = await pbkdf2Hash(password, salt, PBKDF2_ITERATIONS);
      const record = { salt, hash, iterations: PBKDF2_ITERATIONS, version: 1 };
      await env.PROFILE_KV.put("admin_auth", JSON.stringify(record));

      const token = await issueSessionToken(env, record.version);
      return jsonResponse({ ok: true }, 200, {
        "Set-Cookie": buildSessionCookie(token, isHttps)
      });
    }

    // 3. Login with Brute-Force Rate Limiting
    if (url.pathname === "/api/auth/login" && request.method === "POST") {
      if (!kvReady) return jsonResponse({ error: "Chưa gắn PROFILE_KV" }, 501);
      const authRecord = await getAuthRecord(env);
      if (!authRecord) {
        return jsonResponse({ error: "Chưa thiết lập mật khẩu Admin." }, 400);
      }

      const ip = request.headers.get("CF-Connecting-IP") || "unknown";
      const rateKey = `rl:${ip}`;
      const fails = Number((await env.PROFILE_KV.get(rateKey)) || "0");
      if (fails >= MAX_LOGIN_FAILS) {
        return jsonResponse({ error: "Nhập sai quá nhiều lần. Vui lòng thử lại sau 15 phút." }, 429);
      }

      const { password } = await request.json().catch(() => ({}));
      if (typeof password !== "string" || !password) {
        return jsonResponse({ error: "Vui lòng nhập mật khẩu." }, 400);
      }

      const calc = await pbkdf2Hash(password, authRecord.salt, authRecord.iterations || PBKDF2_ITERATIONS);
      if (!timingSafeEqualHex(calc, authRecord.hash)) {
        await env.PROFILE_KV.put(rateKey, String(fails + 1), { expirationTtl: LOCKOUT_SECONDS });
        return jsonResponse({ error: "Mật khẩu không chính xác." }, 401);
      }

      await env.PROFILE_KV.delete(rateKey);
      const token = await issueSessionToken(env, authRecord.version || 1);
      return jsonResponse({ ok: true }, 200, {
        "Set-Cookie": buildSessionCookie(token, isHttps)
      });
    }

    // 4. Secure Password Update (Verifies current password & rotates session version)
    if (url.pathname === "/api/auth/change-password" && request.method === "POST") {
      if (!kvReady) return jsonResponse({ error: "Chưa gắn PROFILE_KV" }, 501);
      const authRecord = await getAuthRecord(env);
      const isAdmin = await verifySession(request, env, authRecord);
      if (!isAdmin) return jsonResponse({ error: "Chưa đăng nhập Admin." }, 401);

      const { currentPassword, newPassword } = await request.json().catch(() => ({}));
      if (typeof currentPassword !== "string" || typeof newPassword !== "string" || newPassword.length < 6) {
        return jsonResponse({ error: "Mật khẩu mới cần tối thiểu 6 ký tự." }, 400);
      }

      const checkHash = await pbkdf2Hash(currentPassword, authRecord.salt, authRecord.iterations || PBKDF2_ITERATIONS);
      if (!timingSafeEqualHex(checkHash, authRecord.hash)) {
        return jsonResponse({ error: "Mật khẩu hiện tại không đúng." }, 403);
      }

      const newSalt = randomHex(16);
      const newHash = await pbkdf2Hash(newPassword, newSalt, PBKDF2_ITERATIONS);
      const nextVersion = (Number(authRecord.version) || 1) + 1;
      const updated = { salt: newSalt, hash: newHash, iterations: PBKDF2_ITERATIONS, version: nextVersion };
      await env.PROFILE_KV.put("admin_auth", JSON.stringify(updated));

      const token = await issueSessionToken(env, nextVersion);
      return jsonResponse({ ok: true }, 200, {
        "Set-Cookie": buildSessionCookie(token, isHttps)
      });
    }

    // 5. Logout
    if (url.pathname === "/api/auth/logout" && request.method === "POST") {
      return jsonResponse({ ok: true }, 200, {
        "Set-Cookie": buildSessionCookie("", isHttps, 0)
      });
    }

    // 6. Get Profile (Public)
    if (url.pathname === "/api/profile" && request.method === "GET") {
      if (!kvReady) return jsonResponse({ error: "KV not bound" }, 404);
      const data = await env.PROFILE_KV.get("profile");
      if (!data) return jsonResponse({ error: "Not initialized" }, 404);
      return new Response(data, {
        headers: {
          "Content-Type": "application/json; charset=utf-8",
          "Cache-Control": "no-store",
          ...SECURITY_HEADERS
        }
      });
    }

    // 7. Save Profile (Admin Only via HttpOnly Cookie)
    if (url.pathname === "/api/profile" && request.method === "PUT") {
      if (!kvReady) return jsonResponse({ error: "KV not bound" }, 501);
      const authRecord = await getAuthRecord(env);
      const isAdmin = await verifySession(request, env, authRecord);
      if (!isAdmin) return jsonResponse({ error: "Unauthorized" }, 401);

      const body = await request.text();
      if (body.length > 1_500_000) {
        return jsonResponse({ error: "Dữ liệu vượt quá giới hạn 1.5MB." }, 413);
      }
      JSON.parse(body); // ensure valid JSON
      await env.PROFILE_KV.put("profile", body);
      return jsonResponse({ ok: true });
    }

    // Serve Static Frontend Assets
    if (env.ASSETS) {
      const resp = await env.ASSETS.fetch(request);
      const newHeaders = new Headers(resp.headers);
      Object.entries(SECURITY_HEADERS).forEach(([k, v]) => newHeaders.set(k, v));
      return new Response(resp.body, { status: resp.status, headers: newHeaders });
    }
    return new Response("Not Found", { status: 404, headers: SECURITY_HEADERS });
  }
};
