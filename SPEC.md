# House Evening Availability Heat Map Spec

## Background
Seven housemates want an at-a-glance view of which evenings are free for everyone so they can plan house events. Calendars come from personal Google Calendars. The application should import these calendars, determine who is free between 6 pm and 10 pm each day, and visualize the group’s availability as a heat map that people can check on their phones or on a shared display in the house.

## Goals
- Aggregate each person’s calendar data in a privacy-aware way.
- Compute evening (6 pm–10 pm) free/busy status per person, per day.
- Show a calendar-like heat map that highlights days with more housemates free.
- Keep availability reasonably up to date with minimal manual steps.

## Non-Goals
- Hourly or custom time-range availability beyond 6 pm–10 pm.
- Detailed event sharing or exposing individual event contents.
- Automatic RSVP, reminders, or event creation flows.
- Full-featured user management or external sharing.

## Users & Use Cases
- **Housemates:** View upcoming weeks to pick nights for events; optionally trigger a manual refresh if something seems stale.
- **Wall Display:** Runs in kiosk mode on a small screen; needs an authenticated way to fetch the aggregated heat map without user interaction.

## Functional Requirements
### Calendar Ingestion
- Authenticate each housemate via Google OAuth with the `calendar.readonly` scope and request access only to free/busy data.
- Use the Google Calendar FreeBusy endpoint to fetch daily busy blocks and convert them into canonical start/end windows.
- Keep OAuth refresh tokens in D1 with access limited to the ingestion worker; allow users to revoke and re-authenticate.

### Free/Busy Processing
- Define a day as **free** for a user when no events overlap 6 pm–10 pm local time (events spanning the window count as busy even if only partial).
- Treat all-day busy events as blocking unless explicitly marked “free” or “transparent.”
- Default computations to the `Europe/London` timezone (override later if needed) and handle daylight saving transitions.
- Store per-user daily free/busy flags plus an aggregated free count (0–7) for quick lookup.

### Heat Map Presentation
- Display a rolling 4-week grid (configurable) with days colored by number of people free; include legend for 0–7 scale.
- Provide quick filtering for weekdays vs. weekends and optional per-person toggles.
- Show last-updated timestamp and data freshness indicators.
- Ensure colors meet accessibility guidelines (colorblind-safe palette, sufficient contrast).

### Sync & Updates
- Nightly automatic sync via Cloudflare Cron Triggers that invoke the ingestion Worker; manual “sync now” action on the web UI.
- Surface sync errors per user with guidance to re-authenticate.
- Log sync operations for debugging and show minimal status history (e.g., last 5 sync attempts).

## Technical Considerations
- **Backend:** Cloudflare Workers handle API endpoints and scheduled ingestion; D1 stores normalized data, and KV/Cache can memoize recent heat map responses.
- **Frontend:** Cloudflare Pages deploys a responsive SPA (e.g., Svelte/React) optimized for phones and kiosk mode; optionally leverage the Workers site for server-rendered pages.
- **Auth:** Email-based magic links or shared household secret implemented in Workers; issue scoped API tokens for the wall display device and store hashed tokens in D1.
- **Security & Privacy:** Treat OAuth credentials like passwords—store refresh tokens securely in D1, avoid logging them, and expose only aggregated free/busy data.
- **Testing:** Unit tests for free/busy overlap logic, Worker integration tests for ingestion and cron flows, and visual regression checks for heat map coloring.

## Data Model (MVP sketch)

- `users`: id, name, email, auth metadata, refresh_token_hash, last_auth_at.
- `freebusy_windows`: user_id, start_at, end_at, source, sync_id, last_synced_at.
- `daily_availability`: date, user_id, is_free_evening, computed_at.
- `daily_summary`: date, free_count, free_user_ids (optional JSON array).
- `sync_runs`: id, started_at, completed_at, status, message.

## Operations & Monitoring
- Track sync failures and expose them in an admin dashboard; send email/slack alert if a calendar hasn’t synced in >48 hours.
- Provide tools to backfill or reprocess a single user’s data without impacting others.
- Keep an audit trail of auth changes (new tokens, revocations).

## Open Questions
- How frictionless can we make the Google OAuth onboarding (e.g., pre-auth links, short-lived sessions)?
- How often should the wall display auto-refresh, and what happens offline?
- Should “tentative” events block the evening or be treated as free unless confirmed?
- Do we need historical data retention (e.g., past months) for trends?

## MVP Deliverables
1. Authenticated web app with invite/household login.
2. Google OAuth flow for capturing/storing per-user refresh tokens and syncing their free/busy data.
3. Nightly job that processes free/busy windows and updates `daily_summary`.
4. Heat map UI with legend, last updated timestamp, and manual refresh button.
5. Basic admin panel/status view showing sync health per user.
