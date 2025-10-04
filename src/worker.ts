import type { Env } from "./env";
import { exchangeCodeForTokens, fetchPrimaryCalendar } from "./providers/google";
import {
  exchangeCodeForTokens as exchangeOutlookCode,
  fetchPrimaryCalendar as fetchOutlookPrimaryCalendar,
} from "./providers/outlook";
import { detectCalDAVServer } from "./providers/caldav";
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

const SESSION_COOKIE_NAME = "user_session";
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

type CookieOptions = {
  isSecure: boolean;
  sameSite: "Lax" | "None";
};

type AuthMode = "public" | "page" | "api";

type SessionCheck =
  | { authorized: true; userId: string }
  | { authorized: false; response: Response };

function authModeForRoute(method: string, pathname: string): AuthMode {
  if (method === "OPTIONS") return "public";
  if (pathname === "/health") return "public";
  if (pathname === "/auth/google/start") return "public";
  if (pathname === "/auth/google/callback") return "public";
  if (pathname === "/auth/outlook/start") return "public";
  if (pathname === "/auth/outlook/callback") return "public";
  if (pathname === "/auth/caldav/setup") return "public";
  if (pathname === "/api/calendars/list") return "public";
  if (pathname === "/api/calendars/select") return "public";
  if (pathname === "/api/user/calendars") return "public";
  if (pathname === "/api/user/info") return "api";
  if (pathname === "/household/logout") return "public";
  if (pathname.startsWith("/api/")) return "api";
  if (pathname.startsWith("/auth/")) return "page";
  return "page";
}

async function ensureSession(request: Request, env: Env, mode: AuthMode): Promise<SessionCheck> {
  // Bypass auth for localhost
  const url = new URL(request.url);
  if (url.hostname === "localhost" || url.hostname === "127.0.0.1") {
    return { authorized: true, userId: "local-dev-user" };
  }

  const cookieHeader = request.headers.get("Cookie");
  const cookieValue = getCookieValue(cookieHeader, SESSION_COOKIE_NAME);

  if (!cookieValue) {
    return { authorized: false, response: buildUnauthorizedResponse(request, env, mode) };
  }

  const userId = await decryptUserId(cookieValue, env);
  if (!userId) {
    console.info("Invalid or expired session cookie");
    return { authorized: false, response: buildUnauthorizedResponse(request, env, mode) };
  }

  return { authorized: true, userId };
}


async function handleHouseholdLogout(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const url = new URL(request.url);
  const next = sanitizeNextParam(url.searchParams.get("next"));
  const target = resolveRedirectTarget(request, env, next);
  const cookieOptions = getCookieOptions(request, env);

  // Get userId from session before clearing it
  const cookieHeader = request.headers.get("Cookie");
  const cookieValue = getCookieValue(cookieHeader, SESSION_COOKIE_NAME);

  if (cookieValue) {
    const userId = await decryptUserId(cookieValue, env);
    if (userId) {
      // Disconnect calendar: clear user's calendar data
      await env.DB.prepare("DELETE FROM user_calendars WHERE user_id = ?").bind(userId).run();
      await env.DB.prepare("DELETE FROM freebusy_windows WHERE user_id = ?").bind(userId).run();
      await env.DB.prepare("DELETE FROM daily_availability WHERE user_id = ?").bind(userId).run();

      // Clear calendar credentials from users table
      await env.DB.prepare(
        `UPDATE users
         SET calendar_id = NULL,
             refresh_token_encrypted = NULL,
             caldav_url = NULL,
             caldav_username = NULL,
             updated_at = ?
         WHERE id = ?`
      ).bind(new Date().toISOString(), userId).run();

      // Recompute daily summaries in background since user's availability has changed
      const timezone = env.HOUSE_TIMEZONE || DEFAULT_TIMEZONE;
      const { dateStrings } = buildSyncWindow(timezone, HORIZON_DAYS);
      if (dateStrings.length > 0) {
        ctx.waitUntil(recomputeSummariesAfterLogout(env, dateStrings));
      }
    }
  }

  const headers = new Headers();
  headers.set("Location", target);
  headers.append("Set-Cookie", buildExpiredSessionCookie(cookieOptions));

  return new Response(null, { status: 303, headers });
}

async function recomputeSummariesAfterLogout(env: Env, dateStrings: string[]): Promise<void> {
  try {
    const timestampIso = new Date().toISOString();
    const startDate = dateStrings[0];
    const endDate = dateStrings[dateStrings.length - 1];

    const { results } = await env.DB.prepare(
      `SELECT date, user_id, is_free_evening
         FROM daily_availability
        WHERE date BETWEEN ? AND ?`
    )
      .bind(startDate, endDate)
      .all<{ date: string; user_id: string; is_free_evening: number }>();

    const grouped = new Map<string, { freeCount: number; freeUsers: string[] }>();

    for (const date of dateStrings) {
      grouped.set(date, { freeCount: 0, freeUsers: [] });
    }

    if (results) {
      for (const row of results) {
        const entry = grouped.get(row.date);
        if (!entry) continue;
        if (row.is_free_evening === 1) {
          entry.freeCount += 1;
          entry.freeUsers.push(row.user_id);
        }
      }
    }

    await env.DB.prepare(
      `DELETE FROM daily_summary WHERE date BETWEEN ? AND ?`
    )
      .bind(startDate, endDate)
      .run();

    for (const [date, stats] of grouped) {
      await env.DB.prepare(
        `INSERT INTO daily_summary (date, free_count, free_user_ids, computed_at)
         VALUES (?, ?, ?, ?)`
      )
        .bind(date, stats.freeCount, JSON.stringify(stats.freeUsers), timestampIso)
        .run();
    }
  } catch (error) {
    console.error("Failed to recompute summaries after logout", error);
  }
}

async function createUserSessionCookie(userId: string, env: Env, request: Request): Promise<string> {
  const token = await encryptUserId(userId, env);
  const options = getCookieOptions(request, env);
  return buildSessionCookie(token, options);
}

async function encryptUserId(userId: string, env: Env): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(JSON.stringify({ userId, exp: Date.now() + SESSION_TTL_MS }));

  // Use a simple encryption key derived from APP_BASE_URL (or a default)
  const keyMaterial = env.APP_BASE_URL || "default-session-key";
  const keyData = encoder.encode(keyMaterial);
  const key = await crypto.subtle.importKey(
    "raw",
    await crypto.subtle.digest("SHA-256", keyData),
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"]
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    data
  );

  // Combine IV + encrypted data
  const combined = new Uint8Array(iv.length + encrypted.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(encrypted), iv.length);

  return toBase64Url(combined.buffer);
}

async function decryptUserId(token: string, env: Env): Promise<string | null> {
  try {
    const encoder = new TextEncoder();
    const combined = new Uint8Array(fromBase64Url(token));

    const iv = combined.slice(0, 12);
    const encrypted = combined.slice(12);

    const keyMaterial = env.APP_BASE_URL || "default-session-key";
    const keyData = encoder.encode(keyMaterial);
    const key = await crypto.subtle.importKey(
      "raw",
      await crypto.subtle.digest("SHA-256", keyData),
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"]
    );

    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      encrypted
    );

    const decoded = JSON.parse(new TextDecoder().decode(decrypted));

    // Check expiration
    if (decoded.exp && Date.now() > decoded.exp) {
      return null;
    }

    return decoded.userId || null;
  } catch (error) {
    console.warn("Failed to decrypt session token", error);
    return null;
  }
}

function buildUnauthorizedResponse(request: Request, env: Env, mode: AuthMode): Response {
  const cookieOptions = getCookieOptions(request, env);
  if (mode === "api") {
    const response = jsonWithCors({ ok: false, error: "unauthorized" }, request, 401);
    response.headers.append("Set-Cookie", buildExpiredSessionCookie(cookieOptions));
    return response;
  }

  // Redirect to homepage where users can choose their OAuth provider
  const headers = new Headers();
  headers.set("Location", "/");
  headers.append("Set-Cookie", buildExpiredSessionCookie(cookieOptions));

  return new Response(null, { status: 303, headers });
}

function buildSessionCookie(token: string, options: CookieOptions): string {
  const expires = new Date(Date.now() + SESSION_TTL_MS).toUTCString();
  const maxAge = Math.floor(SESSION_TTL_MS / 1000);
  const parts = [
    `${SESSION_COOKIE_NAME}=${token}`,
    "Path=/",
    "HttpOnly",
    `SameSite=${options.sameSite}`,
    `Max-Age=${maxAge}`,
    `Expires=${expires}`,
  ];
  if (options.isSecure) {
    parts.push("Secure");
  }
  return parts.join("; ");
}

function buildExpiredSessionCookie(options: CookieOptions): string {
  const parts = [
    `${SESSION_COOKIE_NAME}=`,
    "Path=/",
    "HttpOnly",
    `SameSite=${options.sameSite}`,
    "Max-Age=0",
    "Expires=Thu, 01 Jan 1970 00:00:00 GMT",
  ];
  if (options.isSecure) {
    parts.push("Secure");
  }
  return parts.join("; ");
}

function getCookieOptions(request: Request, env: Env): CookieOptions {
  const requestUrl = new URL(request.url);
  const isSecure = requestUrl.protocol === "https:";
  const appBaseUrl = parseUrl(env.APP_BASE_URL);
  const crossSite = shouldUseSameSiteNone(requestUrl, appBaseUrl);
  const sameSite: CookieOptions["sameSite"] = isSecure && crossSite ? "None" : "Lax";
  return { isSecure, sameSite };
}

function shouldUseSameSiteNone(requestUrl: URL, appBaseUrl?: URL): boolean {
  if (!appBaseUrl) return false;
  return appBaseUrl.origin !== requestUrl.origin;
}

function parseUrl(value: string | undefined): URL | undefined {
  if (!value) return undefined;
  try {
    return new URL(value);
  } catch {
    return undefined;
  }
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

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const method = request.method.toUpperCase();

    if (method === "OPTIONS" && (url.pathname.startsWith("/api/") || url.pathname.startsWith("/auth/"))) {
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


    if (method === "POST" && url.pathname === "/household/logout") {
      return handleHouseholdLogout(request, env, ctx);
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

    if (method === "GET" && url.pathname === "/auth/outlook/start") {
      return handleOutlookStart(env);
    }

    if (url.pathname === "/auth/outlook/callback") {
      return handleOutlookCallback(request, env, ctx);
    }

    if (method === "POST" && url.pathname === "/auth/caldav/setup") {
      return handleCalDAVSetup(request, env, ctx);
    }

    if (method === "GET" && url.pathname === "/api/calendars/list") {
      return handleListCalendars(request, env);
    }

    if ((method === "POST" || method === "GET") && url.pathname === "/api/calendars/select") {
      return handleSelectCalendars(request, env);
    }

    if (method === "GET" && url.pathname === "/api/user/calendars") {
      return handleGetUserCalendars(request, env);
    }

    if (method === "GET" && url.pathname === "/api/user/info") {
      return handleGetUserInfo(request, env);
    }

    // Serve static assets
    if (method === "GET") {
      return handleStaticAsset(request, env);
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
      `SELECT id, provider, calendar_id as calendarId, refresh_token_encrypted as refreshToken,
              caldav_url as caldavUrl, caldav_username as caldavUsername
         FROM users WHERE id = ?`
    )
      .bind(userId)
      .first<{
        id: string;
        provider: "google" | "caldav";
        calendarId: string;
        refreshToken: string;
        caldavUrl?: string;
        caldavUsername?: string;
      }>();

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
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  if (!code) {
    return Response.json({ ok: false, error: "missing_code" }, { status: 400 });
  }

  try {
    const tokens = await exchangeCodeForTokens(env, code);
    const idTokenClaims = decodeIdToken(tokens.id_token);

    // Determine email from ID token or fall back to primary calendar
    let email = idTokenClaims.email;
    const primaryCalendar = await fetchPrimaryCalendar(tokens.access_token);
    if (!email) {
      email = determineUserEmail(undefined, primaryCalendar.id);
    }

    const displayName = idTokenClaims.name || email;
    const nowIso = new Date().toISOString();

    // Use primary calendar directly - skip calendar picker
    const primaryCalendarId = primaryCalendar.id;

    // Create or update user directly
    const existing = await env.DB.prepare("SELECT id FROM users WHERE email = ?")
      .bind(email)
      .first<{ id: string }>();

    const userId = existing?.id ?? crypto.randomUUID();

    if (existing) {
      await env.DB.prepare(
        `UPDATE users
         SET display_name = ?,
             provider = 'google',
             calendar_id = ?,
             refresh_token_encrypted = ?,
             last_auth_at = ?,
             updated_at = ?
         WHERE id = ?`
      )
        .bind(
          displayName,
          primaryCalendarId,
          tokens.refresh_token,
          nowIso,
          nowIso,
          userId
        )
        .run();

      // Delete existing calendar selections
      await env.DB.prepare("DELETE FROM user_calendars WHERE user_id = ?").bind(userId).run();
    } else {
      await env.DB.prepare(
        `INSERT INTO users (id, email, display_name, provider, calendar_id, refresh_token_encrypted, last_auth_at, created_at, updated_at)
         VALUES (?, ?, ?, 'google', ?, ?, ?, ?, ?)`
      )
        .bind(
          userId,
          email,
          displayName,
          primaryCalendarId,
          tokens.refresh_token,
          nowIso,
          nowIso,
          nowIso
        )
        .run();
    }

    // Store the primary calendar in user_calendars
    await env.DB.prepare(
      `INSERT INTO user_calendars (id, user_id, calendar_id, calendar_name, is_primary, created_at)
       VALUES (?, ?, ?, ?, 1, ?)`
    )
      .bind(
        crypto.randomUUID(),
        userId,
        primaryCalendarId,
        primaryCalendar.summary,
        nowIso
      )
      .run();

    // Queue initial sync
    ctx.waitUntil(queueInitialSync(env, userId));

    // Create user session cookie
    const sessionCookie = await createUserSessionCookie(userId, env, request);

    const redirectUrl = buildRedirectUrl(env.APP_BASE_URL, "success");

    // Redirect to dashboard
    const headers = new Headers();
    headers.set("Location", redirectUrl);
    headers.append("Set-Cookie", sessionCookie);

    return new Response(null, { status: 303, headers });

    /* FUTURE: Calendar picker flow (commented out for now)
    // Create pending auth record
    const pendingAuthId = crypto.randomUUID();
    await env.DB.prepare(
      `INSERT INTO pending_auth (id, email, display_name, provider, refresh_token_encrypted, created_at)
       VALUES (?, ?, ?, 'google', ?, ?)`
    )
      .bind(pendingAuthId, email, displayName, tokens.refresh_token, nowIso)
      .run();

    // Redirect to calendar selection page
    const baseUrl = env.APP_BASE_URL || new URL("/", request.url).toString();
    const redirectUrl = new URL("/select-calendars.html", baseUrl);
    redirectUrl.searchParams.set("pending_auth_id", pendingAuthId);

    return Response.redirect(redirectUrl.toString(), 303);
    */
  } catch (error) {
    console.error("OAuth callback failed", error);
    const redirectUrl = buildRedirectUrl(env.APP_BASE_URL, "error");
    return Response.redirect(redirectUrl, 303);
  }
}

async function runNightlySync(env: Env): Promise<void> {
  const timezone = env.HOUSE_TIMEZONE || DEFAULT_TIMEZONE;
  const { results } = await env.DB.prepare(
    `SELECT id, provider, calendar_id as calendarId, refresh_token_encrypted as refreshToken,
            caldav_url as caldavUrl, caldav_username as caldavUsername
       FROM users`
  ).all<{
    id: string;
    provider: "google" | "caldav";
    calendarId: string;
    refreshToken: string;
    caldavUrl?: string;
    caldavUsername?: string;
  }>();

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

function handleOutlookStart(env: Env): Response {
  const redirectUri = env.OUTLOOK_REDIRECT_URI;
  const clientId = env.OUTLOOK_CLIENT_ID;
  if (!redirectUri || !clientId) {
    return Response.json({ ok: false, error: "missing_outlook_config" }, { status: 500 });
  }

  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: "code",
    scope: [
      "https://graph.microsoft.com/Calendars.Read",
      "https://graph.microsoft.com/User.Read",
      "offline_access",
      "openid",
      "email",
      "profile",
    ].join(" "),
    response_mode: "query",
  });

  const url = new URL("https://login.microsoftonline.com/common/oauth2/v2.0/authorize");
  url.search = params.toString();

  return Response.redirect(url.toString(), 302);
}

async function handleOutlookCallback(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  if (!code) {
    return Response.json({ ok: false, error: "missing_code" }, { status: 400 });
  }

  try {
    const tokens = await exchangeOutlookCode(env, code);

    // Fetch primary calendar and user email
    const primaryCalendar = await fetchOutlookPrimaryCalendar(tokens.access_token);

    // For Outlook, we need to fetch user profile to get email
    const profileResponse = await fetch("https://graph.microsoft.com/v1.0/me", {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });

    if (!profileResponse.ok) {
      throw new Error("Failed to fetch Outlook user profile");
    }

    const profile = (await profileResponse.json()) as {
      mail?: string;
      userPrincipalName?: string;
      displayName?: string;
    };

    const email = profile.mail || profile.userPrincipalName || "unknown@outlook.com";
    const displayName = profile.displayName || email;
    const nowIso = new Date().toISOString();

    // Use primary calendar directly - skip calendar picker
    const primaryCalendarId = primaryCalendar.id;

    // Create or update user directly
    const existing = await env.DB.prepare("SELECT id FROM users WHERE email = ?")
      .bind(email)
      .first<{ id: string }>();

    const userId = existing?.id ?? crypto.randomUUID();

    if (existing) {
      await env.DB.prepare(
        `UPDATE users
         SET display_name = ?,
             provider = 'outlook',
             calendar_id = ?,
             refresh_token_encrypted = ?,
             last_auth_at = ?,
             updated_at = ?
         WHERE id = ?`
      )
        .bind(displayName, primaryCalendarId, tokens.refresh_token, nowIso, nowIso, userId)
        .run();

      // Delete existing calendar selections
      await env.DB.prepare("DELETE FROM user_calendars WHERE user_id = ?").bind(userId).run();
    } else {
      await env.DB.prepare(
        `INSERT INTO users (id, email, display_name, provider, calendar_id, refresh_token_encrypted, last_auth_at, created_at, updated_at)
         VALUES (?, ?, ?, 'outlook', ?, ?, ?, ?, ?)`
      )
        .bind(userId, email, displayName, primaryCalendarId, tokens.refresh_token, nowIso, nowIso, nowIso)
        .run();
    }

    // Store the primary calendar in user_calendars
    await env.DB.prepare(
      `INSERT INTO user_calendars (id, user_id, calendar_id, calendar_name, is_primary, created_at)
       VALUES (?, ?, ?, ?, 1, ?)`
    )
      .bind(crypto.randomUUID(), userId, primaryCalendarId, primaryCalendar.summary, nowIso)
      .run();

    // Queue initial sync
    ctx.waitUntil(queueInitialSync(env, userId));

    // Create user session cookie
    const sessionCookie = await createUserSessionCookie(userId, env, request);

    const redirectUrl = buildRedirectUrl(env.APP_BASE_URL, "success");

    // Redirect to dashboard
    const headers = new Headers();
    headers.set("Location", redirectUrl);
    headers.append("Set-Cookie", sessionCookie);

    return new Response(null, { status: 303, headers });
  } catch (error) {
    console.error("Outlook OAuth callback error:", error);
    const redirectUrl = buildRedirectUrl(env.APP_BASE_URL, "error");
    return Response.redirect(redirectUrl, 303);
  }
}

async function handleCalDAVSetup(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  try {
    const body = (await request.json().catch(() => ({}))) as Record<string, unknown>;
    const email = typeof body.email === "string" ? body.email.trim() : "";
    const password = typeof body.password === "string" ? body.password.trim() : "";
    const displayName = typeof body.displayName === "string" ? body.displayName.trim() : email;

    if (!email || !password) {
      return jsonWithCors({ ok: false, error: "Email and password are required" }, request, 400);
    }

    const caldavUrl = detectCalDAVServer(email, "apple");
    const nowIso = new Date().toISOString();

    // Create pending auth record
    const pendingAuthId = crypto.randomUUID();
    await env.DB.prepare(
      `INSERT INTO pending_auth (id, email, display_name, provider, refresh_token_encrypted, caldav_url, caldav_username, created_at)
       VALUES (?, ?, ?, 'caldav', ?, ?, ?, ?)`
    )
      .bind(pendingAuthId, email, displayName, password, caldavUrl, email, nowIso)
      .run();

    // Return the pending_auth_id for the frontend to redirect
    const baseUrl = request.headers.get("Origin") || env.APP_BASE_URL || new URL("/", request.url).toString();
    const redirectUrl = new URL("/select-calendars.html", baseUrl);
    redirectUrl.searchParams.set("pending_auth_id", pendingAuthId);

    return jsonWithCors({ ok: true, redirectUrl: redirectUrl.toString() }, request);
  } catch (error) {
    console.error("CalDAV setup failed", error);
    return jsonWithCors({ ok: false, error: "setup_failed" }, request, 500);
  }
}

async function queueInitialSync(env: Env, userId: string): Promise<void> {
  const user = await env.DB.prepare(
    `SELECT id, provider, calendar_id as calendarId, refresh_token_encrypted as refreshToken,
            caldav_url as caldavUrl, caldav_username as caldavUsername
     FROM users WHERE id = ?`
  )
    .bind(userId)
    .first<{
      id: string;
      provider: "google" | "caldav";
      calendarId: string;
      refreshToken: string;
      caldavUrl?: string;
      caldavUsername?: string;
    }>();

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

async function handleListCalendars(request: Request, env: Env): Promise<Response> {
  try {
    // Get pending_auth_id from query params (passed from callback redirect)
    const url = new URL(request.url);
    const pendingAuthId = url.searchParams.get("pending_auth_id");

    if (!pendingAuthId) {
      return jsonWithCors({ ok: false, error: "Missing pending_auth_id" }, request, 400);
    }

    // Fetch pending auth record
    const pendingAuth = await env.DB.prepare(
      `SELECT provider, refresh_token_encrypted as refreshToken, caldav_url as caldavUrl,
              caldav_username as caldavUsername
       FROM pending_auth WHERE id = ?`
    )
      .bind(pendingAuthId)
      .first<{
        provider: "google" | "caldav";
        refreshToken: string;
        caldavUrl?: string;
        caldavUsername?: string;
      }>();

    if (!pendingAuth) {
      return jsonWithCors({ ok: false, error: "Pending auth not found or expired" }, request, 404);
    }

    // Create provider and list calendars
    const { createProvider } = await import("./providers/base");
    const provider = createProvider(env, pendingAuth.provider);

    const credentials = {
      provider: pendingAuth.provider,
      refreshToken: pendingAuth.refreshToken,
      caldavUrl: pendingAuth.caldavUrl,
      caldavUsername: pendingAuth.caldavUsername,
      calendarId: "temp", // Not used for listing
    };

    const calendars = await provider.listCalendars(credentials);

    return jsonWithCors({ ok: true, calendars }, request);
  } catch (error) {
    console.error("List calendars error:", error);
    return jsonWithCors({ ok: false, error: "Failed to list calendars" }, request, 500);
  }
}

async function handleGetUserInfo(request: Request, env: Env): Promise<Response> {
  try {
    // This route requires authentication - userId comes from ensureSession
    const session = await ensureSession(request, env, "api");
    if (!session.authorized) {
      return session.response;
    }

    // Fetch user info from database
    const user = await env.DB.prepare("SELECT email, display_name FROM users WHERE id = ?")
      .bind(session.userId)
      .first<{ email: string; display_name: string }>();

    if (!user) {
      return jsonWithCors({ ok: false, error: "User not found" }, request, 404);
    }

    // Fetch user's synced calendars
    const { results: userCalendars } = await env.DB.prepare(
      `SELECT calendar_id as calendarId, calendar_name as calendarName
       FROM user_calendars WHERE user_id = ? ORDER BY is_primary DESC, calendar_name ASC`
    )
      .bind(session.userId)
      .all<{ calendarId: string; calendarName: string | null }>();

    const calendars = userCalendars?.map((c) => c.calendarName || c.calendarId) || [];

    const { results: contributorRows } = await env.DB.prepare(
      `SELECT u.email
         FROM users u
        WHERE (
          u.calendar_id IS NOT NULL AND TRIM(u.calendar_id) != ''
        )
           OR EXISTS (
             SELECT 1 FROM user_calendars uc WHERE uc.user_id = u.id
           )
        ORDER BY LOWER(u.email), u.email`
    ).all<{ email: string }>();

    const contributors = contributorRows?.map((row) => row.email) || [];

    return jsonWithCors({
      ok: true,
      email: user.email,
      displayName: user.display_name,
      calendars,
      contributors,
    }, request);
  } catch (error) {
    console.error("Get user info error:", error);
    return jsonWithCors({ ok: false, error: "Failed to get user info" }, request, 500);
  }
}

async function handleGetUserCalendars(request: Request, env: Env): Promise<Response> {
  try {
    // Get user email from query parameter (simple approach for now)
    const url = new URL(request.url);
    const userEmail = url.searchParams.get("email");

    if (!userEmail) {
      return jsonWithCors({ ok: false, calendars: [] }, request);
    }

    // Fetch user and their calendars
    const user = await env.DB.prepare("SELECT id, email FROM users WHERE email = ?")
      .bind(userEmail)
      .first<{ id: string; email: string }>();

    if (!user) {
      return jsonWithCors({ ok: false, calendars: [] }, request);
    }

    const { results } = await env.DB.prepare(
      `SELECT calendar_id as calendarId, calendar_name as calendarName
       FROM user_calendars WHERE user_id = ? ORDER BY is_primary DESC, calendar_name ASC`
    )
      .bind(user.id)
      .all<{ calendarId: string; calendarName: string | null }>();

    const calendars = results?.map((c) => c.calendarName || c.calendarId) || [];

    return jsonWithCors({ ok: true, calendars }, request);
  } catch (error) {
    console.error("Get user calendars error:", error);
    return jsonWithCors({ ok: false, calendars: [] }, request);
  }
}

async function handleSelectCalendars(request: Request, env: Env): Promise<Response> {
  try {
    const url = new URL(request.url);
    let body: Record<string, unknown>;

    // Handle GET with query params (for same-origin navigation)
    if (request.method === "GET") {
      body = {
        pendingAuthId: url.searchParams.get("pendingAuthId"),
        calendarIds: JSON.parse(url.searchParams.get("calendarIds") || "[]"),
        calendarNames: JSON.parse(url.searchParams.get("calendarNames") || "{}"),
      };
    } else {
      // Handle POST with JSON or form data
      const contentType = request.headers.get("Content-Type") || "";
      if (contentType.includes("application/x-www-form-urlencoded")) {
        const formData = await request.formData();
        body = {
          pendingAuthId: formData.get("pendingAuthId"),
          calendarIds: JSON.parse((formData.get("calendarIds") as string) || "[]"),
          calendarNames: JSON.parse((formData.get("calendarNames") as string) || "{}"),
        };
      } else {
        body = (await request.json().catch(() => ({}))) as Record<string, unknown>;
      }
    }

    const pendingAuthId = typeof body.pendingAuthId === "string" ? body.pendingAuthId.trim() : "";
    const selectedCalendarIds = Array.isArray(body.calendarIds) ? body.calendarIds : [];

    if (!pendingAuthId) {
      return jsonWithCors({ ok: false, error: "Missing pendingAuthId" }, request, 400);
    }

    if (selectedCalendarIds.length === 0) {
      return jsonWithCors({ ok: false, error: "At least one calendar must be selected" }, request, 400);
    }

    // Fetch pending auth record
    const pendingAuth = await env.DB.prepare(
      `SELECT email, display_name as displayName, provider, refresh_token_encrypted as refreshToken,
              caldav_url as caldavUrl, caldav_username as caldavUsername
       FROM pending_auth WHERE id = ?`
    )
      .bind(pendingAuthId)
      .first<{
        email: string;
        displayName: string;
        provider: "google" | "caldav";
        refreshToken: string;
        caldavUrl?: string;
        caldavUsername?: string;
      }>();

    if (!pendingAuth) {
      return jsonWithCors({ ok: false, error: "Pending auth not found or expired" }, request, 404);
    }

    // Create or update user
    const nowIso = new Date().toISOString();
    const existing = await env.DB.prepare("SELECT id FROM users WHERE email = ?")
      .bind(pendingAuth.email)
      .first<{ id: string }>();

    const userId = existing?.id ?? crypto.randomUUID();

    // Use first selected calendar as primary
    const primaryCalendarId = selectedCalendarIds[0];

    if (existing) {
      await env.DB.prepare(
        `UPDATE users
         SET display_name = ?,
             provider = ?,
             calendar_id = ?,
             caldav_url = ?,
             caldav_username = ?,
             refresh_token_encrypted = ?,
             last_auth_at = ?,
             updated_at = ?
         WHERE id = ?`
      )
        .bind(
          pendingAuth.displayName,
          pendingAuth.provider,
          primaryCalendarId,
          pendingAuth.caldavUrl,
          pendingAuth.caldavUsername,
          pendingAuth.refreshToken,
          nowIso,
          nowIso,
          userId
        )
        .run();

      // Delete existing calendar selections
      await env.DB.prepare("DELETE FROM user_calendars WHERE user_id = ?").bind(userId).run();
    } else {
      await env.DB.prepare(
        `INSERT INTO users (id, email, display_name, provider, calendar_id, caldav_url, caldav_username, refresh_token_encrypted, last_auth_at, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
        .bind(
          userId,
          pendingAuth.email,
          pendingAuth.displayName,
          pendingAuth.provider,
          primaryCalendarId,
          pendingAuth.caldavUrl,
          pendingAuth.caldavUsername,
          pendingAuth.refreshToken,
          nowIso,
          nowIso,
          nowIso
        )
        .run();
    }

    // Insert selected calendars into user_calendars
    for (let i = 0; i < selectedCalendarIds.length; i++) {
      const calendarId = selectedCalendarIds[i];
      const calendarName = typeof body.calendarNames === "object" && body.calendarNames !== null
        ? (body.calendarNames as Record<string, string>)[calendarId]
        : null;

      await env.DB.prepare(
        `INSERT INTO user_calendars (id, user_id, calendar_id, calendar_name, is_primary, created_at)
         VALUES (?, ?, ?, ?, ?, ?)`
      )
        .bind(
          crypto.randomUUID(),
          userId,
          calendarId,
          calendarName,
          i === 0 ? 1 : 0,
          nowIso
        )
        .run();
    }

    // Delete pending auth record
    await env.DB.prepare("DELETE FROM pending_auth WHERE id = ?").bind(pendingAuthId).run();

    // Queue initial sync
    await queueInitialSync(env, userId);

    // Create user session cookie
    const sessionCookie = await createUserSessionCookie(userId, env, request);

    const redirectUrl = buildRedirectUrl(env.APP_BASE_URL, "success");

    // Use server-side redirect to ensure cookie is properly set before navigation
    const headers = new Headers();
    headers.set("Location", redirectUrl);
    headers.append("Set-Cookie", sessionCookie);

    return new Response(null, { status: 303, headers });
  } catch (error) {
    console.error("Select calendars error:", error);
    return jsonWithCors({ ok: false, error: "Failed to save calendar selection" }, request, 500);
  }
}

async function handleStaticAsset(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  let pathname = url.pathname;

  // Map root to index.html
  if (pathname === "/" || pathname === "") {
    pathname = "/index.html";
  }

  // Try to fetch the asset
  const assetRequest = new Request(new URL(pathname, request.url), request);
  const response = await env.ASSETS.fetch(assetRequest);

  // If not found and it doesn't have an extension, try with .html
  if (response.status === 404 && !pathname.includes(".")) {
    const htmlPath = pathname.endsWith("/") ? `${pathname}index.html` : `${pathname}.html`;
    const htmlRequest = new Request(new URL(htmlPath, request.url), request);
    return await env.ASSETS.fetch(htmlRequest);
  }

  return response;
}
