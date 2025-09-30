import type { BusyWindow, CalendarInfo, CalendarProvider, UserCredentials } from "./base";

export class CalDAVProvider implements CalendarProvider {
  async fetchFreeBusy(
    credentials: UserCredentials,
    timeMinIso: string,
    timeMaxIso: string,
    timezone: string
  ): Promise<BusyWindow[]> {
    if (!credentials.caldavUrl || !credentials.caldavUsername || !credentials.refreshToken) {
      throw new Error("CalDAV provider requires caldavUrl, caldavUsername, and password (refreshToken)");
    }

    const calendarUrl = this.buildCalendarUrl(credentials.caldavUrl, credentials.calendarId);
    const busyWindows = await this.fetchFreeBusyViaCalDAV(
      calendarUrl,
      credentials.caldavUsername,
      credentials.refreshToken,
      timeMinIso,
      timeMaxIso
    );

    return busyWindows;
  }

  async listCalendars(credentials: UserCredentials): Promise<CalendarInfo[]> {
    if (!credentials.caldavUrl || !credentials.caldavUsername || !credentials.refreshToken) {
      throw new Error("CalDAV provider requires caldavUrl, caldavUsername, and password (refreshToken)");
    }

    const calendarHome = await this.discoverCalendarHome(
      credentials.caldavUrl,
      credentials.caldavUsername,
      credentials.refreshToken
    );

    return await this.findAllCalendars(
      calendarHome,
      credentials.caldavUsername,
      credentials.refreshToken
    );
  }

  private buildCalendarUrl(baseUrl: string, calendarId: string): string {
    // For iCloud, we need the principal URL format
    if (baseUrl.includes("caldav.icloud.com")) {
      // iCloud uses principal URLs - calendarId should be the calendar home
      return baseUrl;
    }
    const base = baseUrl.endsWith("/") ? baseUrl : `${baseUrl}/`;
    return `${base}${calendarId}`;
  }

  private async fetchFreeBusyViaCalDAV(
    calendarUrl: string,
    username: string,
    password: string,
    timeMinIso: string,
    timeMaxIso: string
  ): Promise<BusyWindow[]> {
    const timeMin = this.formatAsICalDateTime(timeMinIso);
    const timeMax = this.formatAsICalDateTime(timeMaxIso);

    // For iCloud, we need to query the calendar-home-set first
    const calendarHome = await this.discoverCalendarHome(calendarUrl, username, password);

    // Get the first calendar from the calendar home
    const actualCalendar = await this.findFirstCalendar(calendarHome, username, password);

    // Use calendar-query instead of free-busy-query (iCloud doesn't support free-busy-query)
    const reportBody = `<?xml version="1.0" encoding="UTF-8"?>
<C:calendar-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:prop>
    <D:getetag/>
    <C:calendar-data/>
  </D:prop>
  <C:filter>
    <C:comp-filter name="VCALENDAR">
      <C:comp-filter name="VEVENT">
        <C:time-range start="${timeMin}" end="${timeMax}"/>
      </C:comp-filter>
    </C:comp-filter>
  </C:filter>
</C:calendar-query>`;

    const auth = btoa(`${username}:${password}`);

    console.log("CalDAV REPORT to:", actualCalendar);

    const response = await fetch(actualCalendar, {
      method: "REPORT",
      headers: {
        "Content-Type": "application/xml; charset=utf-8",
        Authorization: `Basic ${auth}`,
        Depth: "1",
      },
      body: reportBody,
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error("CalDAV REPORT error:", response.status, errorText);
      throw new Error(`CalDAV REPORT failed: ${response.status} - URL: ${actualCalendar}`);
    }

    const responseText = await response.text();
    return this.parseCalendarQueryResponse(responseText);
  }

  private async findFirstCalendar(
    calendarHomeUrl: string,
    username: string,
    password: string
  ): Promise<string> {
    const calendars = await this.findAllCalendars(calendarHomeUrl, username, password);
    if (calendars.length === 0) {
      console.log("No specific calendar found, using calendar home");
      return calendarHomeUrl;
    }
    return calendars[0].id;
  }

  private async findAllCalendars(
    calendarHomeUrl: string,
    username: string,
    password: string
  ): Promise<CalendarInfo[]> {
    const auth = btoa(`${username}:${password}`);

    console.log("Step 3: Listing calendars from:", calendarHomeUrl);

    try {
      const response = await fetch(calendarHomeUrl, {
        method: "PROPFIND",
        headers: {
          "Content-Type": "application/xml; charset=utf-8",
          Authorization: `Basic ${auth}`,
          Depth: "1",
        },
        body: `<?xml version="1.0" encoding="UTF-8"?>
<d:propfind xmlns:d="DAV:" xmlns:cs="http://calendarserver.org/ns/" xmlns:c="urn:ietf:params:xml:ns:caldav">
  <d:prop>
    <d:resourcetype />
    <d:displayname />
  </d:prop>
</d:propfind>`,
      });

      if (response.ok) {
        const text = await response.text();
        console.log("Calendar list response (truncated):", text.substring(0, 500));

        const calendars: CalendarInfo[] = [];
        const systemCalendars = ["inbox", "outbox", "notification"];

        // Parse XML response using regex (since DOMParser is not available in Workers)
        // Split by <response> elements
        const responseBlocks = text.split(/<[^:>]*:?response[^>]*>/gi);

        for (const block of responseBlocks) {
          if (!block.trim()) continue;

          // Extract href
          const hrefMatch = block.match(/<[^:>]*:?href[^>]*>([^<]+)<\/[^:>]*:?href>/i);
          if (!hrefMatch) continue;

          const href = hrefMatch[1].trim();

          // Skip the calendar home itself
          if (href === calendarHomeUrl || href.endsWith("/calendars/")) {
            continue;
          }

          // Only include actual calendars
          if (href.includes("/calendars/") && !href.endsWith("/calendars/")) {
            // Skip system calendars
            const calendarName = href.split("/").pop()?.toLowerCase() || "";
            if (systemCalendars.includes(calendarName)) {
              continue;
            }

            let fullUrl = href;

            // Make absolute if needed
            if (href.startsWith("http")) {
              fullUrl = href;
            } else if (href.startsWith("/")) {
              const base = new URL(calendarHomeUrl);
              fullUrl = `${base.protocol}//${base.host}${href}`;
            } else {
              fullUrl = `${calendarHomeUrl}${href}`;
            }

            // Extract display name
            const displaynameMatch = block.match(/<[^:>]*:?displayname[^>]*>([^<]+)<\/[^:>]*:?displayname>/i);
            let displayName = displaynameMatch?.[1]?.trim() || calendarName;

            // Capitalize first letter for display if it's all lowercase
            if (displayName && displayName === displayName.toLowerCase()) {
              displayName = displayName.charAt(0).toUpperCase() + displayName.slice(1);
            }

            // Add indicator if this is the default calendar (check both lowercase path and displayname)
            const isDefault = calendarName === "home" || displayName.toLowerCase() === "home";
            if (isDefault) {
              displayName = `${displayName} (Default)`;
            }

            calendars.push({
              id: fullUrl,
              summary: displayName,
            });
          }
        }

        // Sort calendars: default (home) first, then alphabetically
        calendars.sort((a, b) => {
          const aIsDefault = a.id.toLowerCase().includes("/home/");
          const bIsDefault = b.id.toLowerCase().includes("/home/");

          if (aIsDefault && !bIsDefault) return -1;
          if (!aIsDefault && bIsDefault) return 1;

          return a.summary.localeCompare(b.summary);
        });

        console.log("Found calendars:", calendars.length);
        return calendars;
      }

      // Fallback: return empty array
      console.log("No calendars found");
      return [];
    } catch (error) {
      console.error("Error finding calendars:", error);
      return [];
    }
  }

  private async discoverCalendarHome(
    principalUrl: string,
    username: string,
    password: string
  ): Promise<string> {
    // For iCloud CalDAV, we need to use PROPFIND to discover the actual calendar home
    if (principalUrl.includes("caldav.icloud.com")) {
      return await this.propfindCalendarHome(principalUrl, username, password);
    }

    // For other providers, try PROPFIND to discover calendar-home-set
    return principalUrl;
  }

  private async propfindCalendarHome(
    principalUrl: string,
    username: string,
    password: string
  ): Promise<string> {
    const auth = btoa(`${username}:${password}`);

    // Step 1: Discover the current-user-principal from the well-known URL
    const wellKnownUrl = `${principalUrl}/.well-known/caldav`;
    console.log("Step 1: Discovering principal from:", wellKnownUrl);

    try {
      const principalResponse = await fetch(wellKnownUrl, {
        method: "PROPFIND",
        headers: {
          "Content-Type": "application/xml; charset=utf-8",
          Authorization: `Basic ${auth}`,
          Depth: "0",
        },
        body: `<?xml version="1.0" encoding="UTF-8"?>
<d:propfind xmlns:d="DAV:">
  <d:prop>
    <d:current-user-principal />
  </d:prop>
</d:propfind>`,
      });

      let principalPath = null;
      if (principalResponse.ok) {
        const text = await principalResponse.text();
        console.log("Principal response (full):", text);

        // Try multiple patterns to extract the principal href
        let match = text.match(/<current-user-principal[^>]*>.*?<href[^>]*>(.*?)<\/href>/s);
        if (!match) {
          match = text.match(/<d:current-user-principal[^>]*>.*?<d:href[^>]*>(.*?)<\/d:href>/s);
        }
        if (!match) {
          // Try without namespace prefix
          match = text.match(/<href[^>]*>(\/\d+\/principal\/)<\/href>/);
        }

        if (match && match[1]) {
          principalPath = match[1].trim();
          console.log("Found principal:", principalPath);
        } else {
          console.log("Could not extract principal from response");
        }
      }

      // Step 2: Query the principal for calendar-home-set
      const principalFullUrl = principalPath
        ? `https://caldav.icloud.com${principalPath}`
        : `${principalUrl}/`;

      console.log("Step 2: Querying calendar-home-set from:", principalFullUrl);

      const homeResponse = await fetch(principalFullUrl, {
        method: "PROPFIND",
        headers: {
          "Content-Type": "application/xml; charset=utf-8",
          Authorization: `Basic ${auth}`,
          Depth: "0",
        },
        body: `<?xml version="1.0" encoding="UTF-8"?>
<d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">
  <d:prop>
    <c:calendar-home-set />
  </d:prop>
</d:propfind>`,
      });

      if (homeResponse.ok) {
        const text = await homeResponse.text();
        console.log("Calendar-home-set response (full):", text);

        // Try multiple patterns to extract calendar-home-set
        let match = text.match(/<calendar-home-set[^>]*>.*?<href[^>]*>(.*?)<\/href>/s);
        if (!match) {
          match = text.match(/<c:calendar-home-set[^>]*>.*?<d:href[^>]*>(.*?)<\/d:href>/s);
        }
        if (!match) {
          // Try simpler pattern
          match = text.match(/<href[^>]*>(\/\d+\/calendars\/)<\/href>/);
        }

        if (match && match[1]) {
          const calendarHome = match[1].trim();
          console.log("Found calendar-home-set:", calendarHome);
          if (calendarHome.startsWith("/")) {
            return `https://caldav.icloud.com${calendarHome}`;
          }
          return calendarHome;
        } else {
          console.log("Could not extract calendar-home-set from response");
        }
      }

      // Fallback: Use principal URL
      return principalFullUrl;
    } catch (error) {
      console.error("Calendar discovery error:", error);
      return `${principalUrl}/`;
    }
  }

  private formatAsICalDateTime(isoString: string): string {
    return isoString.replace(/[-:]/g, "").replace(/\.\d{3}/, "");
  }

  private parseCalendarQueryResponse(xmlText: string): BusyWindow[] {
    const busyWindows: BusyWindow[] = [];

    // Extract calendar-data blocks from the XML response
    const calendarDataMatches = xmlText.matchAll(
      /<C:calendar-data[^>]*>([\s\S]*?)<\/C:calendar-data>/gi
    );

    for (const match of calendarDataMatches) {
      const calendarData = match[1];
      const events = this.extractEventsFromVCalendar(calendarData);
      busyWindows.push(...events);
    }

    return busyWindows;
  }

  private extractEventsFromVCalendar(vcalText: string): BusyWindow[] {
    const busyWindows: BusyWindow[] = [];
    const lines = vcalText.split(/\r?\n/);

    let inEvent = false;
    let dtstart: string | null = null;
    let dtend: string | null = null;
    let transp: string | null = null;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();

      if (line.startsWith("BEGIN:VEVENT")) {
        inEvent = true;
        dtstart = null;
        dtend = null;
        transp = null;
      } else if (line.startsWith("END:VEVENT") && inEvent) {
        // Check if event is not transparent (transparent events don't block time)
        if (dtstart && dtend && transp !== "TRANSPARENT") {
          const start = this.parseICalDateTimeValue(dtstart);
          const end = this.parseICalDateTimeValue(dtend);
          if (start && end) {
            busyWindows.push({ start, end });
          }
        }
        inEvent = false;
      } else if (inEvent) {
        if (line.startsWith("DTSTART")) {
          const match = line.match(/DTSTART[^:]*:(.*)/);
          if (match) dtstart = match[1].trim();
        } else if (line.startsWith("DTEND")) {
          const match = line.match(/DTEND[^:]*:(.*)/);
          if (match) dtend = match[1].trim();
        } else if (line.startsWith("TRANSP")) {
          const match = line.match(/TRANSP:(.*)/);
          if (match) transp = match[1].trim();
        }
      }
    }

    return busyWindows;
  }

  private parseICalDateTimeValue(value: string): string | null {
    // Handle both date-time and date formats
    const match = value.match(/^(\d{8}T\d{6}Z?|\d{8})/);
    if (!match) return null;
    return this.parseICalDateTime(match[1]);
  }

  private parseICalDateTime(icalDate: string): string | null {
    const match = icalDate.match(/^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z?$/);
    if (!match) return null;

    const [, year, month, day, hour, minute, second] = match;
    return `${year}-${month}-${day}T${hour}:${minute}:${second}.000Z`;
  }
}

export function detectCalDAVServer(email: string, hint?: "apple" | "google" | "outlook"): string {
  const domain = email.split("@")[1]?.toLowerCase();

  // If hint is provided, use that
  if (hint === "apple") {
    return "https://caldav.icloud.com";
  }

  if (hint === "google") {
    return "https://www.google.com/calendar/dav";
  }

  if (hint === "outlook") {
    return "https://outlook.office365.com";
  }

  // Otherwise, auto-detect based on domain
  if (domain === "icloud.com" || domain === "me.com" || domain === "mac.com") {
    return "https://caldav.icloud.com";
  }

  if (domain === "gmail.com" || domain === "googlemail.com") {
    return "https://www.google.com/calendar/dav";
  }

  if (domain === "outlook.com" || domain === "hotmail.com" || domain === "live.com") {
    return "https://outlook.office365.com";
  }

  return `https://caldav.${domain}`;
}