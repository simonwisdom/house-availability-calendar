import type { Env } from "../env";
import type { BusyWindow, CalendarInfo, CalendarProvider, UserCredentials } from "./base";

type OutlookTokenResponse = {
  access_token: string;
  expires_in: number;
  refresh_token?: string;
  scope: string;
  token_type: string;
};

type OutlookRefreshResponse = {
  access_token: string;
  expires_in: number;
  scope: string;
  token_type: string;
};

export class OutlookProvider implements CalendarProvider {
  constructor(private env: Env) {}

  async fetchFreeBusy(
    credentials: UserCredentials,
    timeMinIso: string,
    timeMaxIso: string,
    timezone: string
  ): Promise<BusyWindow[]> {
    if (!credentials.refreshToken) {
      throw new Error("Outlook provider requires refreshToken");
    }

    const tokenResponse = await this.refreshAccessToken(credentials.refreshToken);
    const busyWindows = await this.fetchFreeBusyFromGraph(
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
      throw new Error("Outlook provider requires refreshToken");
    }

    const tokenResponse = await this.refreshAccessToken(credentials.refreshToken);
    return await this.fetchAllCalendarsInternal(tokenResponse.access_token);
  }

  private async refreshAccessToken(refreshToken: string): Promise<OutlookRefreshResponse> {
    const body = new URLSearchParams({
      client_id: this.env.OUTLOOK_CLIENT_ID,
      client_secret: this.env.OUTLOOK_CLIENT_SECRET,
      refresh_token: refreshToken,
      grant_type: "refresh_token",
      scope: "https://graph.microsoft.com/Calendars.Read offline_access",
    });

    const response = await fetch("https://login.microsoftonline.com/common/oauth2/v2.0/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Outlook refresh failed: ${response.status} ${errorText}`);
    }

    return (await response.json()) as OutlookRefreshResponse;
  }

  private async fetchFreeBusyFromGraph(
    accessToken: string,
    calendarId: string,
    timeMinIso: string,
    timeMaxIso: string,
    timezone: string
  ): Promise<BusyWindow[]> {
    // Microsoft Graph getSchedule API
    const response = await fetch("https://graph.microsoft.com/v1.0/me/calendar/getSchedule", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        schedules: [calendarId],
        startTime: {
          dateTime: timeMinIso,
          timeZone: timezone,
        },
        endTime: {
          dateTime: timeMaxIso,
          timeZone: timezone,
        },
        availabilityViewInterval: 60,
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Outlook getSchedule failed: ${response.status} ${errorText}`);
    }

    const json = (await response.json()) as {
      value?: Array<{
        scheduleId: string;
        scheduleItems?: Array<{
          start: { dateTime: string; timeZone: string };
          end: { dateTime: string; timeZone: string };
          status: string;
        }>;
        error?: {
          message: string;
          responseCode: string;
        };
      }>;
    };

    const schedule = json.value?.[0];
    if (!schedule) {
      console.warn(`Calendar ${calendarId} not found in getSchedule response`);
      return [];
    }

    // Check for errors
    if (schedule.error) {
      console.warn(`Calendar ${calendarId} has error:`, schedule.error);
      return [];
    }

    // Filter to only "busy" items (not tentative, free, etc.)
    const busyItems = schedule.scheduleItems?.filter((item) => item.status === "busy") || [];

    return busyItems.map((item) => ({
      start: this.convertGraphDateTime(item.start.dateTime),
      end: this.convertGraphDateTime(item.end.dateTime),
    }));
  }

  private async fetchAllCalendarsInternal(accessToken: string): Promise<CalendarInfo[]> {
    const response = await fetch("https://graph.microsoft.com/v1.0/me/calendars", {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Fetching Outlook calendars failed: ${response.status} ${errorText}`);
    }

    const json = (await response.json()) as {
      value?: Array<{
        id: string;
        name: string;
        isDefaultCalendar?: boolean;
        canEdit?: boolean;
      }>;
    };

    if (!json.value || json.value.length === 0) {
      throw new Error("No calendars returned from Microsoft Graph API.");
    }

    // Filter to calendars user can read
    const calendars = json.value.map((item) => {
      const displayName = item.isDefaultCalendar ? `${item.name} (Default)` : item.name;

      return {
        id: item.id,
        summary: displayName,
      };
    });

    // Sort: default calendar first, then alphabetically
    calendars.sort((a, b) => {
      const aIsDefault = a.summary.includes("(Default)");
      const bIsDefault = b.summary.includes("(Default)");

      if (aIsDefault && !bIsDefault) return -1;
      if (!aIsDefault && bIsDefault) return 1;

      return a.summary.localeCompare(b.summary);
    });

    return calendars;
  }

  private convertGraphDateTime(graphDateTime: string): string {
    // Graph API returns format like "2025-10-03T18:00:00.0000000"
    // We need ISO 8601: "2025-10-03T18:00:00.000Z"
    const match = graphDateTime.match(/^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})/);
    if (!match) {
      throw new Error(`Invalid Graph API datetime format: ${graphDateTime}`);
    }
    return `${match[1]}.000Z`;
  }
}

export async function exchangeCodeForTokens(env: Env, code: string): Promise<OutlookTokenResponse> {
  const body = new URLSearchParams({
    client_id: env.OUTLOOK_CLIENT_ID,
    client_secret: env.OUTLOOK_CLIENT_SECRET,
    code,
    grant_type: "authorization_code",
    redirect_uri: env.OUTLOOK_REDIRECT_URI,
    scope: "https://graph.microsoft.com/Calendars.Read offline_access",
  });

  const response = await fetch("https://login.microsoftonline.com/common/oauth2/v2.0/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Outlook token exchange failed: ${response.status} ${errorText}`);
  }

  const json = (await response.json()) as OutlookTokenResponse;
  if (!json.refresh_token) {
    throw new Error("Microsoft did not return a refresh_token; check OAuth configuration.");
  }

  return json;
}

export async function fetchPrimaryCalendar(accessToken: string): Promise<CalendarInfo> {
  const response = await fetch("https://graph.microsoft.com/v1.0/me/calendars", {
    headers: { Authorization: `Bearer ${accessToken}` },
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Fetching calendar list failed: ${response.status} ${errorText}`);
  }

  const json = (await response.json()) as {
    value?: Array<{
      id: string;
      name: string;
      isDefaultCalendar?: boolean;
    }>;
  };

  const primary = json.value?.find((item) => item.isDefaultCalendar) || json.value?.[0];

  if (!primary) {
    throw new Error("No calendars returned from Microsoft Graph API.");
  }

  return { id: primary.id, summary: primary.name };
}
