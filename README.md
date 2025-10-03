# House Availability App

A Cloudflare-based heat map showing when housemates are free for house events. The app aggregates calendar data from Google Calendar, Outlook Calendar, and Apple Calendar (via CalDAV) to show evening availability (6-10pm) across the household.

## What It Does

- Connects to Google Calendar, Outlook Calendar, or Apple Calendar for each housemate
- Syncs calendar data nightly via Cloudflare Cron Triggers
- Computes who is free between 6-10pm each evening
- Displays a rolling 4-week heat map showing availability counts
- Mobile-friendly with week-by-week navigation
- Supports multiple calendars per user

## Prerequisites

- Cloudflare account with access to Workers, D1, and Cron Triggers
- Node.js 20+ for local development tooling
- `wrangler` CLI (installed via `npm install` in this repository)

## Initial Setup

### 1. Install Dependencies
```bash
npm install
```

### 2. Create D1 Database
```bash
npx wrangler d1 create house_availability
```
Note the database ID from the output.

### 3. Update Configuration
Edit `wrangler.toml` and replace `database_id` with the ID from step 2.

### 4. Run Database Migrations
```bash
npx wrangler d1 migrations apply house_availability --local
npx wrangler d1 migrations apply house_availability
```

### 5. Configure Secrets
Create a `.dev.vars` file in the project root (not checked into git):

```ini
# .dev.vars
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URI=http://127.0.0.1:8787/auth/google/callback
OUTLOOK_CLIENT_ID=your-outlook-client-id
OUTLOOK_CLIENT_SECRET=your-outlook-client-secret
OUTLOOK_REDIRECT_URI=http://127.0.0.1:8787/auth/outlook/callback
APP_BASE_URL=http://127.0.0.1:8788/
HOUSE_TIMEZONE=Europe/London
```

Wrangler automatically loads `.dev.vars` when you run `wrangler dev`.

For production, set secrets using:
```bash
npx wrangler secret put GOOGLE_CLIENT_ID
npx wrangler secret put GOOGLE_CLIENT_SECRET
npx wrangler secret put GOOGLE_REDIRECT_URI
npx wrangler secret put OUTLOOK_CLIENT_ID
npx wrangler secret put OUTLOOK_CLIENT_SECRET
npx wrangler secret put OUTLOOK_REDIRECT_URI
```

## Google OAuth Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the Google Calendar API
4. Create OAuth 2.0 credentials (Web application type)
5. Add authorized redirect URIs:
   - Local: `http://127.0.0.1:8787/auth/google/callback`
   - Production: `https://your-worker.workers.dev/auth/google/callback`
6. Copy the Client ID and Client Secret to your `.dev.vars` file

The app requests these scopes:
- `openid email profile` - Basic user information
- `https://www.googleapis.com/auth/calendar.readonly` - Read-only calendar access

## Outlook Calendar Setup

1. Go to [Azure Portal](https://portal.azure.com/) and sign in
2. Navigate to **Azure Active Directory** → **App registrations** → **New registration**
3. Enter an application name (e.g., "House Availability Calendar")
4. Set **Supported account types** to "Accounts in any organizational directory and personal Microsoft accounts"
5. Add redirect URIs under **Web**:
   - Local: `http://127.0.0.1:8787/auth/outlook/callback`
   - Production: `https://your-worker.workers.dev/auth/outlook/callback`
6. Click **Register**
7. Copy the **Application (client) ID** to your `.dev.vars` as `OUTLOOK_CLIENT_ID`
8. Navigate to **Certificates & secrets** → **New client secret**
9. Create a secret and copy the **Value** to your `.dev.vars` as `OUTLOOK_CLIENT_SECRET`
10. Navigate to **API permissions** → **Add a permission** → **Microsoft Graph** → **Delegated permissions**
11. Add these permissions:
    - `Calendars.Read` - Read user calendars
    - `openid`, `email`, `profile` - Basic user information
    - `offline_access` - Refresh token support
12. Click **Grant admin consent** (if available) or have users consent on first login

The app requests read-only access to calendars via Microsoft Graph API.

## Apple Calendar Setup

Apple Calendar (iCloud) uses CalDAV and requires an app-specific password:

1. Users go to [appleid.apple.com](https://appleid.apple.com/)
2. Navigate to Sign-In & Security → App-Specific Passwords
3. Generate a new password
4. Enter credentials in the app's Apple Calendar connection form

The app automatically discovers the CalDAV server URL and syncs calendar data.

## Development Commands

- `npm run dev` — run the Worker locally with `wrangler dev`
- `npm run deploy` — deploy the Worker to Cloudflare
- `npm run check` — type-check the TypeScript sources
- `npm run fmt` — format the project with Prettier

## Managing the Database

### Run Migrations
```bash
npx wrangler d1 migrations apply house_availability
```

### Inspect Data
```bash
npx wrangler d1 execute house_availability --local --command "SELECT * FROM users LIMIT 5;"
```

### Add New Migrations
Create files using the pattern `migrations/NNNN_description.sql`. Wrangler applies them in order.

## User Interface

### Main Dashboard (`/` or `/index.html`)
The primary interface showing the availability heat map. Features:
- Week-by-week navigation on mobile
- Desktop grid view showing 4 weeks
- Color-coded cells (lighter = fewer free, darker = more free)
- Today's date highlighted with orange border
- Connect overlay when no calendars are linked

### Settings Page (`/settings.html`)
Manage connected calendars:
- View connected Google or Apple calendars
- Select which calendars to include in availability calculations
- Disconnect and reconnect accounts
- See last sync status

## API Endpoints

### Public Endpoints
- `GET /health` - Health check
- `GET /auth/google/start` - Initiate Google OAuth flow
- `GET /auth/google/callback` - OAuth callback handler
- `POST /auth/caldav/setup` - Setup Apple Calendar via CalDAV
- `POST /household/logout` - Clear user session

### Authenticated Endpoints
- `GET /api/availability` - Fetch heat map data
- `GET /api/user/info` - Get current user information
- `GET /api/user/calendars` - List user's connected calendars
- `GET /api/calendars/list` - List available calendars for selection
- `POST /api/calendars/select` - Update calendar selection
- `POST /api/manual-sync` - Trigger immediate sync (requires `{ "userId": "uuid" }`)

## Deployment

### Via GitHub Actions
Connect this repo to Cloudflare Workers by adding two GitHub secrets:
- `CLOUDFLARE_API_TOKEN` - Worker deploy token with `Account · Workers Scripts = Edit`
- `CLOUDFLARE_ACCOUNT_ID` - Your Cloudflare account ID (visible in dashboard or via `wrangler whoami`)

On every push to `main`, `.github/workflows/deploy.yml` installs dependencies and runs `wrangler deploy`.

You can also trigger deployment manually through the GitHub UI (`Actions → Deploy Worker → Run workflow`).

### Manual Deployment
```bash
npm run deploy
```

## How It Works

### Data Flow
1. **Authentication**: Users connect their calendar (Google or Apple)
2. **Initial Sync**: App fetches free/busy data for the next 28 days
3. **Nightly Updates**: Cron trigger (5:00 UTC) refreshes all user calendars
4. **Availability Calculation**: For each day, determines if 6-10pm window is free
5. **Aggregation**: Counts how many users are free each evening
6. **Display**: Heat map shows aggregated counts with color gradient

### Database Schema
- `users` - User accounts with provider info and encrypted tokens
- `user_calendars` - Selected calendars per user (supports multi-calendar)
- `freebusy_windows` - Raw busy time blocks from calendar providers
- `daily_availability` - Per-user evening availability flags
- `daily_summary` - Aggregated daily counts (what the UI displays)
- `sync_runs` - Sync job history and error tracking

### Privacy & Security
- OAuth refresh tokens are encrypted before storage
- Only free/busy data is fetched (no event titles or details)
- Aggregated counts are shown (individual schedules not exposed)
- Session cookies expire after 30 days
- Localhost development bypasses authentication for convenience

## Architecture

- **Backend**: Cloudflare Workers with D1 database
- **Frontend**: Static HTML/CSS/JS served via Workers Assets
- **Providers**: Abstracted provider system (Google, CalDAV)
- **Sync**: Scheduled via Cloudflare Cron Triggers
- **Timezone**: Configurable (defaults to Europe/London)
- **Horizon**: 28 days rolling window
