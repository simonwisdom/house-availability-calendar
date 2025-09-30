import type { Env } from "../env";
import type { BusyWindow, CalendarInfo, CalendarProvider, UserCredentials } from "./base";

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

export class GoogleProvider implements CalendarProvider {
  constructor(private env: Env) {}

  async fetchFreeBusy(
    credentials: UserCredentials,
    timeMinIso: string,
    timeMaxIso: string,
    timezone: string
  ): Promise<BusyWindow[]> {
    if (!credentials.refreshToken) {
      throw new Error("Google provider requires refreshToken");
    }

    const tokenResponse = await this.refreshAccessToken(credentials.refreshToken);
    const busyWindows = await this.fetchFreeBusyFromApi(
      tokenResponse.access_token,
      credentials.calendarId,
      timeMinIso,
      timeMaxIso,
      timezone
    );

    return busyWindows;
  }

  async listCalendars(credentials: UserCredentials): Promise<CalendarInfo[]> {
    if (!credentials.refreshToken) {
      throw new Error("Google provider requires refreshToken");
    }

    const tokenResponse = await this.refreshAccessToken(credentials.refreshToken);
    return await fetchAllCalendarsInternal(tokenResponse.access_token);
  }

  private async refreshAccessToken(refreshToken: string): Promise<GoogleRefreshResponse> {
    const body = new URLSearchParams({
      client_id: this.env.GOOGLE_CLIENT_ID,
      client_secret: this.env.GOOGLE_CLIENT_SECRET,
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

  private async fetchFreeBusyFromApi(
    accessToken: string,
    calendarId: string,
    timeMinIso: string,
    timeMaxIso: string,
    timezone: string
  ): Promise<BusyWindow[]> {
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
          busy?: Array<{
            start: string;
            end: string;
          }>;
          errors?: Array<{
            domain: string;
            reason: string;
          }>;
        }
      >;
    };
    const calendar = json.calendars?.[calendarId];
    if (!calendar) {
      console.warn(`Calendar ${calendarId} not found in freebusy response`);
      return [];
    }

    // Check for errors (e.g., insufficient permissions)
    if (calendar.errors && calendar.errors.length > 0) {
      console.warn(`Calendar ${calendarId} has errors:`, calendar.errors);
      // Don't throw - just return empty busy windows
      return [];
    }

    return calendar.busy ?? [];
  }
}

export async function exchangeCodeForTokens(env: Env, code: string): Promise<GoogleTokenResponse> {
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
    throw new Error(
      "Google did not return a refresh_token; ensure access_type=offline and prompt=consent are used on the authorize step."
    );
  }

  return json;
}

export async function fetchPrimaryCalendar(accessToken: string): Promise<CalendarInfo> {
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

async function fetchAllCalendarsInternal(accessToken: string): Promise<CalendarInfo[]> {
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
      accessRole?: string; // "owner", "writer", "reader", "freeBusyReader"
    }>;
  };

  if (!json.items || json.items.length === 0) {
    throw new Error("No calendars returned from Google Calendar API.");
  }

  // Filter calendars to only those with at least freeBusyReader access
  // Typical roles: owner, writer, reader, freeBusyReader
  const calendars = json.items
    .filter((item) => {
      // Include if accessRole is owner, writer, reader, or freeBusyReader
      // Exclude if no role or insufficient permissions
      const role = item.accessRole?.toLowerCase() || "";
      return role === "owner" || role === "writer" || role === "reader" || role === "freebusyreader";
    })
    .map((item) => {
      const displayName = item.primary
        ? `${item.summary || item.id} (Default)`
        : (item.summary || item.id);

      return {
        id: item.id,
        summary: displayName,
      };
    });

  // Sort: primary calendar first, then alphabetically
  calendars.sort((a, b) => {
    const aIsPrimary = a.summary.includes("(Default)");
    const bIsPrimary = b.summary.includes("(Default)");

    if (aIsPrimary && !bIsPrimary) return -1;
    if (!aIsPrimary && bIsPrimary) return 1;

    return a.summary.localeCompare(b.summary);
  });

  return calendars;
}