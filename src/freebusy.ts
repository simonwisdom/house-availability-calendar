import { formatInTimeZone, zonedTimeToUtc } from "date-fns-tz";
import type { Env } from "./env";
import { createProvider, type BusyWindow, type CalendarProviderType, type UserCredentials } from "./providers/base";

export const DEFAULT_TIMEZONE = "Europe/London";
export const HORIZON_DAYS = 28;

const SEGMENT_DEFINITIONS = {
  morning: { start: "09:00:00", end: "12:00:00" },
  evening: { start: "18:00:00", end: "22:00:00" },
} as const;

type DaySegmentKey = keyof typeof SEGMENT_DEFINITIONS;

const SEGMENT_KEYS = Object.keys(SEGMENT_DEFINITIONS) as DaySegmentKey[];

export type UserSyncContext = {
  id: string;
  provider: CalendarProviderType;
  calendarId: string;
  refreshToken: string;
  caldavUrl?: string;
  caldavUsername?: string;
};

export type { BusyWindow };

export async function performFreeBusySync(env: Env, user: UserSyncContext): Promise<void> {
  const timezone = env.HOUSE_TIMEZONE || DEFAULT_TIMEZONE;
  const nowIso = new Date().toISOString();

  const insertResult = await env.DB.prepare(
    `INSERT INTO sync_runs (id, user_id, started_at, status, message)
     VALUES (NULL, ?, ?, ?, NULL)`
  )
    .bind(user.id, nowIso, "running")
    .run();

  const syncId = insertResult.meta?.last_row_id;

  if (typeof syncId !== "number") {
    throw new Error("Unable to determine sync run id");
  }

  try {
    const { timeMinIso, timeMaxIso, dateStrings } = buildSyncWindow(timezone);

    // Fetch user's selected calendars
    const { results: userCalendars } = await env.DB.prepare(
      `SELECT calendar_id as calendarId FROM user_calendars WHERE user_id = ?`
    )
      .bind(user.id)
      .all<{ calendarId: string }>();

    // If no calendars selected yet, fall back to the primary calendar_id from users table
    const calendarIds = userCalendars && userCalendars.length > 0
      ? userCalendars.map((c) => c.calendarId)
      : [user.calendarId];

    const provider = createProvider(env, user.provider);

    // Fetch busy windows from all selected calendars
    const allBusyWindows: BusyWindow[] = [];
    const fetchErrors: Array<{ calendarId: string; reason: string }> = [];
    let successfulCalendars = 0;
    let reauthFlagged = false;

    for (const calendarId of calendarIds) {
      try {
        const credentials: UserCredentials = {
          provider: user.provider,
          calendarId,
          refreshToken: user.refreshToken,
          caldavUrl: user.caldavUrl,
          caldavUsername: user.caldavUsername,
        };

        const busyWindows = await provider.fetchFreeBusy(credentials, timeMinIso, timeMaxIso, timezone);
        successfulCalendars += 1;
        allBusyWindows.push(...busyWindows);
        if (!reauthFlagged) {
          await clearUserReauthRequired(env, user.id);
        }
      } catch (error) {
        // Log the error but continue with other calendars
        console.error(`Failed to fetch freebusy for calendar ${calendarId}:`, error);
        fetchErrors.push({ calendarId, reason: describeError(error) });
        if (!reauthFlagged && isReauthRequiredError(user.provider, error)) {
          await markUserReauthRequired(env, user.id, describeError(error));
          reauthFlagged = true;
        }
        // Continue to next calendar
      }
    }

    if (successfulCalendars === 0) {
      const errorSummary =
        fetchErrors.length > 0
          ? fetchErrors.map(({ calendarId, reason }) => `${calendarId}: ${reason}`).join("; ")
          : "unknown errors";
      throw new Error(`All calendar free/busy fetches failed: ${errorSummary}`);
    }

    if (fetchErrors.length > 0) {
      console.warn("Freebusy fetch completed with partial failures", {
        userId: user.id,
        failedCalendars: fetchErrors.map(({ calendarId }) => calendarId),
      });
    }

    const normalizedWindows = normalizeWindows(allBusyWindows);

    await persistFreeBusyWindows(env, user.id, syncId, normalizedWindows, timeMinIso, timeMaxIso, nowIso, user.provider);
    await updateAvailability(env, user.id, normalizedWindows, dateStrings, timezone, nowIso);

    const completedIso = new Date().toISOString();
    const completionMessage = fetchErrors.length > 0 ? buildPartialFailureMessage(fetchErrors) : null;
    await env.DB.prepare(
      `UPDATE sync_runs
         SET completed_at = ?, status = ?, message = ?
       WHERE id = ?`
    )
      .bind(completedIso, "success", completionMessage, syncId)
      .run();
  } catch (error) {
    const completedIso = new Date().toISOString();
    const message = error instanceof Error ? error.message : String(error);
    await env.DB.prepare(
      `UPDATE sync_runs
         SET completed_at = ?, status = ?, message = ?
       WHERE id = ?`
    )
      .bind(completedIso, "error", message, syncId)
      .run();
    throw error;
  }
}

export function buildSyncWindow(timezone: string, horizonDays: number = HORIZON_DAYS) {
  const startDateStr = formatInTimeZone(new Date(), timezone, "yyyy-MM-dd");
  const dateStrings = buildDateStrings(startDateStr, horizonDays);

  const timeMin = zonedTimeToUtc(`${startDateStr}T00:00:00`, timezone);
  const afterLast = addDaysToDateString(dateStrings[dateStrings.length - 1], 1);
  const timeMax = zonedTimeToUtc(`${afterLast}T00:00:00`, timezone);

  return {
    timeMinIso: timeMin.toISOString(),
    timeMaxIso: timeMax.toISOString(),
    dateStrings,
  };
}

function buildDateStrings(startDate: string, days: number): string[] {
  const dates: string[] = [];
  for (let i = 0; i < days; i += 1) {
    const date = addDaysToDateString(startDate, i);
    dates.push(date);
  }
  return dates;
}

function addDaysToDateString(dateStr: string, days: number): string {
  const date = new Date(`${dateStr}T00:00:00Z`);
  date.setUTCDate(date.getUTCDate() + days);
  return date.toISOString().slice(0, 10);
}

function normalizeWindows(windows: BusyWindow[]): BusyWindow[] {
  return windows
    .map((window) => {
      try {
        const startDate = new Date(window.start);
        const endDate = new Date(window.end);

        if (Number.isNaN(startDate.getTime()) || Number.isNaN(endDate.getTime())) {
          return undefined;
        }

        const startIso = startDate.toISOString();
        const endIso = endDate.toISOString();

        if (Date.parse(endIso) <= Date.parse(startIso)) {
          return undefined;
        }

        return { start: startIso, end: endIso };
      } catch (error) {
        console.warn("Failed to parse date", { start: window.start, end: window.end, error });
        return undefined;
      }
    })
    .filter((window): window is BusyWindow => Boolean(window))
    .sort((a, b) => Date.parse(a.start) - Date.parse(b.start));
}


async function persistFreeBusyWindows(
  env: Env,
  userId: string,
  syncId: number,
  windows: BusyWindow[],
  timeMinIso: string,
  timeMaxIso: string,
  timestampIso: string,
  provider: CalendarProviderType
): Promise<void> {
  await env.DB.prepare(
    `DELETE FROM freebusy_windows
      WHERE user_id = ?
        AND start_at >= ?
        AND start_at < ?`
  )
    .bind(userId, timeMinIso, timeMaxIso)
    .run();

  if (windows.length === 0) {
    return;
  }

  const sourceLabel = `${provider}-freebusy`;
  const statements = windows.map((window) =>
    env.DB.prepare(
      `INSERT INTO freebusy_windows (id, user_id, start_at, end_at, source, sync_run_id, created_at, updated_at)
       VALUES (NULL, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(userId, window.start, window.end, sourceLabel, syncId, timestampIso, timestampIso)
  );

  await env.DB.batch(statements);
}

async function updateAvailability(
  env: Env,
  userId: string,
  windows: BusyWindow[],
  dateStrings: string[],
  timezone: string,
  timestampIso: string
): Promise<void> {
  if (dateStrings.length === 0) return;

  const startDate = dateStrings[0];
  const endDate = dateStrings[dateStrings.length - 1];

  await env.DB.prepare(
    `DELETE FROM daily_availability
      WHERE user_id = ?
        AND date BETWEEN ? AND ?`
  )
    .bind(userId, startDate, endDate)
    .run();

  const availabilityStatements = dateStrings.map((date) => {
    const segmentFlags = computeSegmentFlags(windows, date, timezone);
    const isMorningFree = segmentFlags.morning ? 1 : 0;
    const isEveningFree = segmentFlags.evening ? 1 : 0;
    return env.DB.prepare(
      `INSERT INTO daily_availability (date, user_id, is_free_evening, computed_at, is_free_morning)
       VALUES (?, ?, ?, ?, ?)`
    ).bind(date, userId, isEveningFree, timestampIso, isMorningFree);
  });

  if (availabilityStatements.length > 0) {
    await env.DB.batch(availabilityStatements);
  }

  await recomputeDailySummaries(env, dateStrings, timestampIso);
}

function computeSegmentFlags(
  windows: BusyWindow[],
  date: string,
  timezone: string
): Record<DaySegmentKey, boolean> {
  const flags: Record<DaySegmentKey, boolean> = {} as Record<DaySegmentKey, boolean>;
  for (const key of SEGMENT_KEYS) {
    flags[key] = isSegmentFree(windows, date, timezone, key);
  }
  return flags;
}

function isSegmentFree(
  windows: BusyWindow[],
  date: string,
  timezone: string,
  segment: DaySegmentKey
): boolean {
  if (windows.length === 0) return true;

  const { start, end } = SEGMENT_DEFINITIONS[segment];
  const segmentStart = zonedTimeToUtc(`${date}T${start}`, timezone).getTime();
  const segmentEnd = zonedTimeToUtc(`${date}T${end}`, timezone).getTime();

  for (const window of windows) {
    const startMs = Date.parse(window.start);
    const endMs = Date.parse(window.end);

    if (Number.isNaN(startMs) || Number.isNaN(endMs)) {
      return false;
    }

    if (endMs > segmentStart && startMs < segmentEnd) {
      return false;
    }
  }

  return true;
}

async function recomputeDailySummaries(env: Env, dateStrings: string[], timestampIso: string): Promise<void> {
  const startDate = dateStrings[0];
  const endDate = dateStrings[dateStrings.length - 1];

  const { results } = await env.DB.prepare(
    `SELECT date, user_id, is_free_evening, is_free_morning
       FROM daily_availability
      WHERE date BETWEEN ? AND ?`
  )
    .bind(startDate, endDate)
    .all<{ date: string; user_id: string; is_free_evening: number; is_free_morning: number }>();

  const grouped = new Map<
    string,
    {
      segments: Record<DaySegmentKey, { freeCount: number; freeUsers: string[] }>;
    }
  >();

  for (const date of dateStrings) {
    grouped.set(date, {
      segments: SEGMENT_KEYS.reduce((acc, key) => {
        acc[key] = { freeCount: 0, freeUsers: [] };
        return acc;
      }, {} as Record<DaySegmentKey, { freeCount: number; freeUsers: string[] }>),
    });
  }

  if (results) {
    for (const row of results) {
      const entry = grouped.get(row.date);
      if (!entry) continue;

      if (row.is_free_morning === 1) {
        const segment = entry.segments.morning;
        segment.freeCount += 1;
        segment.freeUsers.push(row.user_id);
      }

      if (row.is_free_evening === 1) {
        const segment = entry.segments.evening;
        segment.freeCount += 1;
        segment.freeUsers.push(row.user_id);
      }
    }
  }

  await env.DB.prepare(
    `DELETE FROM daily_summary
      WHERE date BETWEEN ? AND ?`
  )
    .bind(startDate, endDate)
    .run();

  const summaryStatements = dateStrings.map((date) => {
    const entry = grouped.get(date);
    const morning = entry?.segments.morning ?? { freeCount: 0, freeUsers: [] };
    const evening = entry?.segments.evening ?? { freeCount: 0, freeUsers: [] };
    const mergedIds = new Set<string>([...morning.freeUsers, ...evening.freeUsers]);
    const combinedList = Array.from(mergedIds);

    return env.DB.prepare(
      `INSERT INTO daily_summary (
         date,
         free_count,
         free_user_ids,
         computed_at,
         free_count_morning,
         free_user_ids_morning,
         free_count_evening,
         free_user_ids_evening
       )
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      date,
      combinedList.length,
      JSON.stringify(combinedList),
      timestampIso,
      morning.freeCount,
      JSON.stringify(morning.freeUsers),
      evening.freeCount,
      JSON.stringify(evening.freeUsers)
    );
  });

  if (summaryStatements.length > 0) {
    await env.DB.batch(summaryStatements);
  }
}

function buildPartialFailureMessage(errors: Array<{ calendarId: string; reason: string }>): string {
  const parts = errors.map(({ calendarId, reason }) => `${calendarId}: ${reason}`);
  const joined = parts.join("; ");
  const prefix = "partial_failure: ";
  const maxLength = 480;
  const fullMessage = `${prefix}${joined}`;
  if (fullMessage.length <= maxLength) {
    return fullMessage;
  }
  return `${fullMessage.slice(0, maxLength - 1)}…`;
}

function describeError(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  if (typeof error === "string") {
    return error;
  }
  try {
    return JSON.stringify(error);
  } catch {
    return String(error);
  }
}

function isReauthRequiredError(provider: CalendarProviderType, error: unknown): boolean {
  const message = describeError(error).toLowerCase();
  if (message.includes("invalid_grant")) return true;
  if (provider === "outlook" && message.includes("interaction_required")) return true;
  return false;
}

async function markUserReauthRequired(env: Env, userId: string, reason: string): Promise<void> {
  const nowIso = new Date().toISOString();
  const normalizedReason = reason.replace(/\s+/g, " ").trim().slice(0, 480);
  await env.DB.prepare(
    `UPDATE users
        SET reauth_required = 1,
            reauth_required_reason = ?,
            reauth_required_at = ?,
            updated_at = ?
      WHERE id = ?`
  )
    .bind(normalizedReason || "Reauthentication required", nowIso, nowIso, userId)
    .run();
}

async function clearUserReauthRequired(env: Env, userId: string): Promise<void> {
  const nowIso = new Date().toISOString();
  await env.DB.prepare(
    `UPDATE users
        SET reauth_required = 0,
            reauth_required_reason = NULL,
            reauth_required_at = NULL,
            updated_at = ?
      WHERE id = ?
        AND reauth_required = 1`
  )
    .bind(nowIso, userId)
    .run();
}
