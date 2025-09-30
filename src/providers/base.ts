import type { Env } from "../env";
import { GoogleProvider } from "./google";
import { CalDAVProvider } from "./caldav";

export type CalendarProviderType = "google" | "caldav";

export type BusyWindow = {
  start: string; // ISO 8601
  end: string; // ISO 8601
};

export type CalendarInfo = {
  id: string;
  summary?: string;
};

export type UserCredentials = {
  provider: CalendarProviderType;
  refreshToken?: string;
  caldavUrl?: string;
  caldavUsername?: string;
  calendarId: string;
};

export interface CalendarProvider {
  fetchFreeBusy(
    credentials: UserCredentials,
    timeMinIso: string,
    timeMaxIso: string,
    timezone: string
  ): Promise<BusyWindow[]>;

  listCalendars(credentials: UserCredentials): Promise<CalendarInfo[]>;
}

export function createProvider(env: Env, type: CalendarProviderType): CalendarProvider {
  switch (type) {
    case "google":
      return new GoogleProvider(env);
    case "caldav":
      return new CalDAVProvider();
    default:
      throw new Error(`Unknown provider type: ${type}`);
  }
}