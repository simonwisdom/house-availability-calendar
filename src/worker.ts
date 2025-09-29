import type { Env } from "./env";
import { exchangeCodeForTokens, fetchPrimaryCalendar } from "./google";
import { performFreeBusySync, buildSyncWindow, DEFAULT_TIMEZONE, HORIZON_DAYS } from "./freebusy";

type AvailabilityCell = {
  date: string;
  freeCount: number;
  freeUserIds?: string[];
};

type AvailabilityResponse = {
  timezone: string;
  days: AvailabilityCell[];
  lastUpdatedIso?: string;
};

const SESSION_COOKIE_NAME = "household_session";
const SESSION_VERSION = "v1";
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
const SESSION_TTL_SECONDS = Math.floor(SESSION_TTL_MS / 1000);

type AuthMode = "public" | "page" | "api";

type SessionCheck =
  | { authorized: true }
  | { authorized: false; response: Response };

const hmacKeyCache = new Map<string, Promise<CryptoKey>>();

function authModeForRoute(method: string, pathname: string): AuthMode {
  if (method === "OPTIONS") return "public";
  if (pathname === "/health") return "public";
  if (pathname === "/auth/google/start") return "public";
  if (pathname === "/auth/google/callback") return "public";
  if (pathname === "/household/login") return "public";
  if (pathname === "/api/availability") return "public";
  if (pathname === "/household/logout") return "page";
  if (pathname.startsWith("/api/")) return "api";
  if (pathname.startsWith("/auth/")) return "page";
  return "page";
}

async function ensureSession(request: Request, env: Env, mode: AuthMode): Promise<SessionCheck> {
  const secret = env.HOUSEHOLD_SECRET;
  if (!secret) {
    console.error("HOUSEHOLD_SECRET is not configured");
    return {
      authorized: false,
      response: new Response("household_secret_not_configured", { status: 500 }),
    };
  }

  const cookieHeader = request.headers.get("Cookie");
  const cookieValue = getCookieValue(cookieHeader, SESSION_COOKIE_NAME);
  const isSecure = new URL(request.url).protocol === "https:";

  if (!cookieValue) {
    return { authorized: false, response: buildUnauthorizedResponse(request, mode, isSecure) };
  }

  const verification = await verifySessionToken(cookieValue, secret);
  if (!verification.valid) {
    if (verification.reason === "expired") {
      console.info("Session expired, forcing re-auth");
    }
    return { authorized: false, response: buildUnauthorizedResponse(request, mode, isSecure) };
  }

  return { authorized: true };
}

function renderHouseholdLoginPage(
  request: Request,
  options: { error?: string; next?: string } = {}
): Response {
  const url = new URL(request.url);
  const next = options.next ?? sanitizeNextParam(url.searchParams.get("next"));
  const error = options.error;

  const html = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Household Access</title>
    <style>
      :root {
        color-scheme: light dark;
        font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      }
      body {
        margin: 0;
        min-height: 100vh;
        display: flex;
        align-items: center;
        justify-content: center;
        padding: 2rem 1rem;
      }
      main {
        width: min(380px, 100%);
        border: 1px solid rgba(0, 0, 0, 0.1);
        border-radius: 12px;
        padding: 1.5rem;
        background: rgba(255, 255, 255, 0.82);
        backdrop-filter: blur(6px);
        box-shadow: 0 12px 32px rgba(15, 23, 42, 0.18);
      }
      h1 {
        margin-top: 0;
        margin-bottom: 1rem;
        font-size: 1.45rem;
      }
      form {
        display: flex;
        flex-direction: column;
        gap: 1rem;
      }
      label {
        display: flex;
        flex-direction: column;
        gap: 0.35rem;
        font-size: 0.95rem;
      }
      input[type="password"] {
        padding: 0.75rem 0.9rem;
        border-radius: 8px;
        border: 1px solid rgba(148, 163, 184, 0.8);
        font-size: 1rem;
      }
      button {
        padding: 0.75rem 1.1rem;
        border: none;
        border-radius: 8px;
        font-size: 1rem;
        background: #0f172a;
        color: white;
        cursor: pointer;
      }
      button:hover {
        filter: brightness(1.05);
      }
      .error {
        border-radius: 8px;
        padding: 0.75rem 1rem;
        background: rgba(220, 38, 38, 0.12);
        color: #7f1d1d;
        font-size: 0.92rem;
      }
      p.hint {
        margin-top: 0.25rem;
        font-size: 0.85rem;
        color: rgba(15, 23, 42, 0.7);
      }
    </style>
  </head>
  <body>
    <main>
      <h1>Household access</h1>
      <p class="hint">Enter the shared passphrase once to unlock the dashboard and Google connect flow.</p>
      ${error ? `<p class="error">${escapeHtml(error)}</p>` : ""}
      <form method="post" action="/household/login">
        <label>
          Passphrase
          <input type="password" name="passphrase" autocomplete="current-password" required autofocus />
        </label>
        ${next ? `<input type="hidden" name="next" value="${escapeAttribute(next)}" />` : ""}
        <button type="submit">Unlock</button>
      </form>
    </main>
  </body>
</html>`;

  const headers = new Headers({
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
  });

  const status = error ? 401 : 200;
  return new Response(html, { status, headers });
}

async function handleHouseholdLogin(request: Request, env: Env): Promise<Response> {
  const secret = env.HOUSEHOLD_SECRET;
  if (!secret) {
    console.error("HOUSEHOLD_SECRET is not configured");
    return new Response("household_secret_not_configured", { status: 500 });
  }

  const formData = await request.formData().catch(() => undefined);
  if (!formData) {
    return renderHouseholdLoginPage(request, { error: "Invalid form submission" });
  }

  const passphrase = String(formData.get("passphrase") ?? "").trim();
  const next = sanitizeNextParam(formData.get("next"));

  if (!passphrase) {
    return renderHouseholdLoginPage(request, { error: "Enter the household passphrase.", next });
  }

  if (passphrase !== secret) {
    return renderHouseholdLoginPage(request, { error: "Incorrect passphrase. Try again.", next });
  }

  const isSecure = new URL(request.url).protocol === "https:";
  const setCookieHeader = await createSessionCookie(secret, isSecure);
  const target = resolveRedirectTarget(request, env, next);

  const headers = new Headers();
  headers.set("Location", target);
  headers.append("Set-Cookie", setCookieHeader);

  return new Response(null, { status: 303, headers });
}

function handleHouseholdLogout(request: Request, env: Env): Response {
  const isSecure = new URL(request.url).protocol === "https:";
  const url = new URL(request.url);
  const next = sanitizeNextParam(url.searchParams.get("next"));
  const target = resolveRedirectTarget(request, env, next);

  const headers = new Headers();
  headers.set("Location", target);
  headers.append("Set-Cookie", buildExpiredSessionCookie(isSecure));

  return new Response(null, { status: 303, headers });
}

async function createSessionCookie(secret: string, isSecure: boolean): Promise<string> {
  const token = await createSessionToken(secret);
  return buildSessionCookie(token, isSecure);
}

async function createSessionToken(secret: string): Promise<string> {
  const timestamp = Date.now().toString();
  const nonceBytes = new Uint8Array(12);
  crypto.getRandomValues(nonceBytes);
  const nonce = toBase64Url(nonceBytes.buffer);
  const payload = `${SESSION_VERSION}.${timestamp}.${nonce}`;
  const signature = await signPayload(secret, payload);
  return `${payload}.${signature}`;
}

async function verifySessionToken(
  token: string,
  secret: string
): Promise<{ valid: true } | { valid: false; reason: string }> {
  const parts = token.split(".");
  if (parts.length !== 4) {
    return { valid: false, reason: "format" };
  }

  const [version, timestampStr, nonce, signature] = parts;
  if (version !== SESSION_VERSION) {
    return { valid: false, reason: "version" };
  }

  const timestamp = Number(timestampStr);
  if (!Number.isFinite(timestamp)) {
    return { valid: false, reason: "timestamp" };
  }

  if (!nonce) {
    return { valid: false, reason: "nonce" };
  }

  if (!signature) {
    return { valid: false, reason: "signature" };
  }

  if (Date.now() - timestamp > SESSION_TTL_MS) {
    return { valid: false, reason: "expired" };
  }

  const payload = `${version}.${timestampStr}.${nonce}`;
  const ok = await verifyPayload(secret, payload, signature);
  if (!ok) {
    return { valid: false, reason: "signature" };
  }

  return { valid: true };
}

async function signPayload(secret: string, payload: string): Promise<string> {
  const key = await getHmacKey(secret);
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload));
  return toBase64Url(signature);
}

async function verifyPayload(secret: string, payload: string, signature: string): Promise<boolean> {
  try {
    const key = await getHmacKey(secret);
    return await crypto.subtle.verify(
      "HMAC",
      key,
      fromBase64Url(signature),
      new TextEncoder().encode(payload)
    );
  } catch (error) {
    console.warn("Failed to verify session payload", error);
    return false;
  }
}

function getHmacKey(secret: string): Promise<CryptoKey> {
  let cached = hmacKeyCache.get(secret);
  if (!cached) {
    cached = crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign", "verify"]
    );
    hmacKeyCache.set(secret, cached);
  }
  return cached;
}

function buildUnauthorizedResponse(request: Request, mode: AuthMode, isSecure: boolean): Response {
  if (mode === "api") {
    const response = jsonWithCors({ ok: false, error: "unauthorized" }, request, 401);
    response.headers.append("Set-Cookie", buildExpiredSessionCookie(isSecure));
    return response;
  }

  const requestUrl = new URL(request.url);
  const next = sanitizeNextParam(`${requestUrl.pathname}${requestUrl.search}`);
  const loginUrl = new URL("/household/login", request.url);
  if (next) {
    loginUrl.searchParams.set("next", next);
  }

  const headers = new Headers();
  headers.set("Location", loginUrl.toString());
  headers.append("Set-Cookie", buildExpiredSessionCookie(isSecure));

  return new Response(null, { status: 303, headers });
}

function buildSessionCookie(token: string, isSecure: boolean): string {
  const expires = new Date(Date.now() + SESSION_TTL_MS).toUTCString();
  const parts = [
    `${SESSION_COOKIE_NAME}=${token}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    `Max-Age=${SESSION_TTL_SECONDS}`,
    `Expires=${expires}`,
  ];
  if (isSecure) {
    parts.push("Secure");
  }
  return parts.join("; ");
}

function buildExpiredSessionCookie(isSecure: boolean): string {
  const parts = [
    `${SESSION_COOKIE_NAME}=`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    "Max-Age=0",
    "Expires=Thu, 01 Jan 1970 00:00:00 GMT",
  ];
  if (isSecure) {
    parts.push("Secure");
  }
  return parts.join("; ");
}

function sanitizeNextParam(value: FormDataEntryValue | string | null | undefined): string | undefined {
  if (!value) return undefined;
  const text = typeof value === "string" ? value : String(value);
  if (!text.startsWith("/")) return undefined;
  if (text.startsWith("//")) return undefined;
  return text;
}

function resolveRedirectTarget(request: Request, env: Env, next: string | undefined): string {
  if (next) {
    return new URL(next, request.url).toString();
  }

  const fallback = env.APP_BASE_URL;
  if (fallback) {
    try {
      return new URL(fallback).toString();
    } catch {
      // ignore invalid fallback and continue to default below
    }
  }

  return new URL("/", request.url).toString();
}

function getCookieValue(header: string | null, name: string): string | undefined {
  if (!header) return undefined;
  const pairs = header.split(/;\s*/);
  for (const pair of pairs) {
    if (!pair) continue;
    const [rawName, ...rest] = pair.split("=");
    if (rawName?.trim() === name) {
      return rest.join("=");
    }
  }
  return undefined;
}

function toBase64Url(buffer: ArrayBuffer): string {
  const binary = String.fromCharCode(...new Uint8Array(buffer));
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(value: string): ArrayBuffer {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  const padLength = (4 - (padded.length % 4)) % 4;
  const base64 = padded + "=".repeat(padLength);
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function escapeAttribute(value: string): string {
  return escapeHtml(value).replace(/`/g, "&#96;");
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const method = request.method.toUpperCase();

    if (method === "OPTIONS" && url.pathname.startsWith("/api/")) {
      return handleCorsPreflight(request);
    }

    if (method === "GET" && url.pathname === "/health") {
      return Response.json({ ok: true, message: "house-availability worker alive" });
    }

    const authMode = authModeForRoute(method, url.pathname);
    if (authMode !== "public") {
      const session = await ensureSession(request, env, authMode);
      if (!session.authorized) {
        return session.response;
      }
    }

    if (method === "GET" && url.pathname === "/household/login") {
      return renderHouseholdLoginPage(request);
    }

    if (method === "POST" && url.pathname === "/household/login") {
      return handleHouseholdLogin(request, env);
    }

    if (method === "POST" && url.pathname === "/household/logout") {
      return handleHouseholdLogout(request, env);
    }

    if (method === "GET" && url.pathname === "/api/availability") {
      return handleAvailability(env, request);
    }

    if (method === "POST" && url.pathname === "/api/manual-sync") {
      return handleManualSync(request, env, ctx);
    }

    if (method === "GET" && url.pathname === "/auth/google/start") {
      return handleGoogleStart(env);
    }

    if (url.pathname === "/auth/google/callback") {
      return handleGoogleCallback(request, env, ctx);
    }

    return new Response("Not found", { status: 404 });
  },

  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(runNightlySync(env));
  },
};

async function handleAvailability(env: Env, request: Request): Promise<Response> {
  const timezone = env.HOUSE_TIMEZONE || DEFAULT_TIMEZONE;
  const { dateStrings } = buildSyncWindow(timezone, HORIZON_DAYS);

  if (dateStrings.length === 0) {
    return Response.json({ timezone, days: [] } satisfies AvailabilityResponse);
  }

  const startDate = dateStrings[0];
  const endDate = dateStrings[dateStrings.length - 1];

  const { results } = await env.DB.prepare(
    `SELECT date, free_count, free_user_ids, computed_at
       FROM daily_summary
      WHERE date BETWEEN ? AND ?`
  )
    .bind(startDate, endDate)
    .all<{ date: string; free_count: number; free_user_ids: string | null; computed_at: string }>();

  const map = new Map<string, { freeCount: number; freeUserIds: string[]; computedAt: string }>();
  let latest: string | undefined;

  if (results) {
    for (const row of results) {
      const freeUserIds = parseJsonArray(row.free_user_ids);
      map.set(row.date, {
        freeCount: row.free_count ?? 0,
        freeUserIds,
        computedAt: row.computed_at,
      });
      if (!latest || row.computed_at > latest) {
        latest = row.computed_at;
      }
    }
  }

  const days: AvailabilityCell[] = dateStrings.map((date) => {
    const entry = map.get(date);
    return {
      date,
      freeCount: entry?.freeCount ?? 0,
      freeUserIds: entry?.freeUserIds,
    };
  });

  const payload: AvailabilityResponse = {
    timezone,
    days,
    lastUpdatedIso: latest,
  };

  return jsonWithCors(payload, request);
}

function handleGoogleStart(env: Env): Response {
  const redirectUri = env.GOOGLE_REDIRECT_URI;
  const clientId = env.GOOGLE_CLIENT_ID;
  if (!redirectUri || !clientId) {
    return Response.json({ ok: false, error: "missing_google_config" }, { status: 500 });
  }

  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: "code",
    access_type: "offline",
    prompt: "consent",
    scope: [
      "openid",
      "email",
      "profile",
      "https://www.googleapis.com/auth/calendar.readonly",
    ].join(" "),
  });

  const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  url.search = params.toString();

  return Response.redirect(url.toString(), 302);
}

async function handleManualSync(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  try {
    const body = (await request.json().catch(() => ({}))) as Record<string, unknown>;
    const userId = typeof body.userId === "string" ? (body.userId as string).trim() : "";
    if (!userId) {
      return jsonWithCors({ ok: false, error: "missing_user_id" }, request, 400);
    }

    const user = await env.DB.prepare(
      `SELECT id, google_calendar_id as calendarId, refresh_token_encrypted as refreshToken
         FROM users WHERE id = ?`
    )
      .bind(userId)
      .first<{ id: string; calendarId: string; refreshToken: string }>();

    if (!user) {
      return jsonWithCors({ ok: false, error: "not_found" }, request, 404);
    }

    ctx.waitUntil(
      performFreeBusySync(env, user).catch((error) => {
        console.error("Manual sync failed", { userId, error });
        throw error;
      })
    );

    return jsonWithCors({ ok: true, queued: true }, request);
  } catch (error) {
    console.error("Manual sync handler error", error);
    return jsonWithCors({ ok: false, error: "internal" }, request, 500);
  }
}

async function handleGoogleCallback(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  // TODO: exchange auth code for tokens, persist refresh token, and trigger initial sync.
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  if (!code) {
    return Response.json({ ok: false, error: "missing_code" }, { status: 400 });
  }

  try {
    const tokens = await exchangeCodeForTokens(env, code);
    const primaryCalendar = await fetchPrimaryCalendar(tokens.access_token);
    const idTokenClaims = decodeIdToken(tokens.id_token);

    const email = determineUserEmail(idTokenClaims.email, primaryCalendar.id);
    const displayName = idTokenClaims.name || primaryCalendar.summary || email;
    const nowIso = new Date().toISOString();

    const existing = await env.DB.prepare("SELECT id FROM users WHERE email = ?").bind(email).first<{ id: string }>();
    const userId = existing?.id ?? crypto.randomUUID();

    if (existing) {
      await env.DB.prepare(
        `UPDATE users
         SET display_name = ?,
             google_calendar_id = ?,
             refresh_token_encrypted = ?,
             last_auth_at = ?,
             updated_at = ?
         WHERE id = ?`
      )
        .bind(displayName, primaryCalendar.id, tokens.refresh_token, nowIso, nowIso, userId)
        .run();
    } else {
      await env.DB.prepare(
        `INSERT INTO users (id, email, display_name, google_calendar_id, refresh_token_encrypted, last_auth_at, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      )
        .bind(userId, email, displayName, primaryCalendar.id, tokens.refresh_token, nowIso, nowIso, nowIso)
        .run();
    }

    ctx.waitUntil(queueInitialSync(env, userId));

    const redirectUrl = buildRedirectUrl(env.APP_BASE_URL, "success");
    return Response.redirect(redirectUrl, 303);
  } catch (error) {
    console.error("OAuth callback failed", error);
    const redirectUrl = buildRedirectUrl(env.APP_BASE_URL, "error");
    return Response.redirect(redirectUrl, 303);
  }
}

async function runNightlySync(env: Env): Promise<void> {
  const timezone = env.HOUSE_TIMEZONE || DEFAULT_TIMEZONE;
  const { results } = await env.DB.prepare(
    `SELECT id, google_calendar_id as calendarId, refresh_token_encrypted as refreshToken FROM users`
  ).all<{ id: string; calendarId: string; refreshToken: string }>();

  if (!results || results.length === 0) {
    console.log("Nightly sync: no users to process");
    return;
  }

  console.log("Nightly sync: processing users", { count: results.length, timezone });

  for (const row of results) {
    try {
      await performFreeBusySync(env, row);
    } catch (error) {
      console.error("Nightly sync failed for user", { userId: row.id, error });
    }
  }
}

function decodeIdToken(idToken?: string): { email?: string; name?: string } {
  if (!idToken) return {};

  try {
    const [, payload] = idToken.split(".");
    if (!payload) return {};
    const normalized = payload.replace(/-/g, "+").replace(/_/g, "/");
    const json = JSON.parse(atob(normalized));
    return { email: json.email, name: json.name };
  } catch (error) {
    console.warn("Failed to decode id_token", error);
    return {};
  }
}

function determineUserEmail(claimEmail: string | undefined, calendarId: string): string {
  if (claimEmail) return claimEmail;
  if (calendarId.includes("@")) return calendarId;
  throw new Error("Unable to determine user email from Google response");
}

function buildRedirectUrl(baseUrl: string, _status: "success" | "error"): string {
  const target = baseUrl?.trim() || "https://example.com";
  // Just return the base URL without status query param since we're showing status via the dashboard
  return new URL(target).toString();
}

async function queueInitialSync(env: Env, userId: string): Promise<void> {
  // TODO: Replace direct call with durable background job if needed.
  const user = await env.DB.prepare(
    `SELECT id, google_calendar_id as calendarId, refresh_token_encrypted as refreshToken
     FROM users WHERE id = ?`
  )
    .bind(userId)
    .first<{ id: string; calendarId: string; refreshToken: string }>();

  if (!user) {
    console.warn("queueInitialSync: user not found", { userId });
    return;
  }

  try {
    await performFreeBusySync(env, user);
  } catch (error) {
    console.error("Initial sync failed", { userId, error });
  }
}

function parseJsonArray(value: string | null | undefined): string[] {
  if (!value) return [];
  try {
    const parsed = JSON.parse(value);
    if (Array.isArray(parsed)) {
      return parsed.filter((item): item is string => typeof item === "string");
    }
    return [];
  } catch (error) {
    console.warn("Failed to parse JSON array", { error, value });
    return [];
  }
}

function jsonWithCors(data: unknown, request: Request, status = 200): Response {
  const headers = new Headers({
    "Content-Type": "application/json",
  });

  const origin = request.headers.get("Origin");
  if (origin) {
    headers.set("Access-Control-Allow-Origin", origin);
    headers.set("Vary", "Origin");
    headers.set("Access-Control-Allow-Credentials", "true");
  }

  return new Response(JSON.stringify(data), { status, headers });
}

function handleCorsPreflight(request: Request): Response {
  const headers = new Headers();
  const origin = request.headers.get("Origin");
  if (origin) {
    headers.set("Access-Control-Allow-Origin", origin);
    headers.set("Vary", "Origin");
  }
  headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  headers.set(
    "Access-Control-Allow-Headers",
    request.headers.get("Access-Control-Request-Headers") ?? "content-type"
  );
  headers.set("Access-Control-Max-Age", "86400");
  headers.set("Access-Control-Allow-Credentials", "true");
  return new Response(null, { status: 204, headers });
}
