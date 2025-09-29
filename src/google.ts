import type { Env } from "./env";

type GoogleTokenResponse = {
  access_token: string;
  expires_in: number;
  refresh_token?: string;
  scope: string;
  token_type: string;
  id_token?: string;
};

type GoogleRefreshResponse = {
  access_token: string;
  expires_in: number;
  scope: string;
  token_type: string;
};

export async function exchangeCodeForTokens(env: Env, code: string) {
  const body = new URLSearchParams({
    client_id: env.GOOGLE_CLIENT_ID,
    client_secret: env.GOOGLE_CLIENT_SECRET,
    code,
    grant_type: "authorization_code",
    redirect_uri: env.GOOGLE_REDIRECT_URI,
  });

  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Google token exchange failed: ${response.status} ${errorText}`);
  }

  const json = (await response.json()) as GoogleTokenResponse;
  if (!json.refresh_token) {
    throw new Error("Google did not return a refresh_token; ensure access_type=offline and prompt=consent are used on the authorize step.");
  }

  return json;
}

export async function fetchPrimaryCalendar(accessToken: string) {
  const response = await fetch("https://www.googleapis.com/calendar/v3/users/me/calendarList", {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Fetching calendar list failed: ${response.status} ${errorText}`);
  }

  const json = (await response.json()) as {
    items?: Array<{
      id: string;
      summary?: string;
      primary?: boolean;
    }>;
  };
  const primary = json.items?.find((item) => item.primary) || json.items?.[0];

  if (!primary) {
    throw new Error("No calendars returned from Google Calendar API.");
  }

  return { id: primary.id, summary: primary.summary };
}

export async function refreshAccessToken(env: Env, refreshToken: string) {
  const body = new URLSearchParams({
    client_id: env.GOOGLE_CLIENT_ID,
    client_secret: env.GOOGLE_CLIENT_SECRET,
    refresh_token: refreshToken,
    grant_type: "refresh_token",
  });

  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Google refresh failed: ${response.status} ${errorText}`);
  }

  return (await response.json()) as GoogleRefreshResponse;
}

export async function fetchFreeBusy(
  accessToken: string,
  calendarId: string,
  timeMinIso: string,
  timeMaxIso: string,
  timezone: string
) {
  const response = await fetch("https://www.googleapis.com/calendar/v3/freeBusy", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      timeMin: timeMinIso,
      timeMax: timeMaxIso,
      timeZone: timezone,
      items: [{ id: calendarId }],
    }),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`FreeBusy fetch failed: ${response.status} ${errorText}`);
  }

  const json = (await response.json()) as {
    calendars: Record<
      string,
      {
        busy: Array<{
          start: string;
          end: string;
        }>;
      }
    >;
  };
  const calendar = json.calendars?.[calendarId];
  if (!calendar) {
    return [];
  }
  return calendar.busy ?? [];
}
