# House Availability App

Early scaffolding for the Cloudflare-based house availability heat map described in `SPEC.md`.

## Prerequisites
- Cloudflare account with access to Workers, D1, and Cron Triggers.
- Node.js 20+ for local development tooling.
- `wrangler` CLI (installed via `npm install` in this repository).

## Initial Setup
1. Run `npm install` to install the dev tooling (Wrangler, TypeScript, Prettier, Workers types).
2. Create a D1 database named `house_availability` and note its id.
3. Update `wrangler.toml`:
   - Replace `database_id = "TBD"` with the id from step 2.
   - Configure any additional bindings (KV, secrets) as they become necessary.
4. Add required secrets either by creating a local `.dev.vars` file or using Wrangler’s `secret put` command:
   ```ini
   # .dev.vars (not checked into git)
   GOOGLE_CLIENT_ID=...
  GOOGLE_CLIENT_SECRET=...
  GOOGLE_REDIRECT_URI=http://127.0.0.1:8787/auth/google/callback
  APP_BASE_URL=http://127.0.0.1:8788/
  HOUSE_TIMEZONE=Europe/London
  HOUSEHOLD_SECRET=super-secret-passphrase
  ```
  Wrangler automatically loads `.dev.vars` when you run `wrangler dev`, mimicking the production secrets.

### Household Guard Rails
- The Worker now requires a shared household passphrase before serving the Google connect flow or API endpoints.
- Visit `/household/login`, enter the passphrase once per device, and the Worker issues a 30-day session cookie.
- To clear access manually, send a `POST` request to `/household/logout` (or use `fetch('/household/logout', { method: 'POST' })`).

## Managing the Database
- Run migrations with `npx wrangler d1 migrations apply house_availability` to apply the SQL files under `migrations/`.
- Add new migration files using the `migrations/NNNN_description.sql` naming pattern so Wrangler keeps them in order.
- Inspect data locally via `npx wrangler d1 execute house_availability --local --command "SELECT * FROM users LIMIT 5;"`.

## Google OAuth Setup
- Create an OAuth client in Google Cloud Console (Web application type) with the redirect URI matching `GOOGLE_REDIRECT_URI`.
- When building the authorize link, include scopes `openid email profile https://www.googleapis.com/auth/calendar.readonly`, and set `access_type=offline` plus `prompt=consent` so Google returns a refresh token.
- Point the authorize link at `/auth/google/callback` on this Worker (e.g., `https://<worker>.workers.dev/auth/google/callback`).

## Deployment via GitHub Actions
- Connect this repo to Cloudflare Workers by adding two GitHub secrets:
  - `CLOUDFLARE_API_TOKEN`: Worker deploy token with `Account · Workers Scripts = Edit`. You can generate this from the Cloudflare dashboard.
  - `CLOUDFLARE_ACCOUNT_ID`: The Cloudflare account id (visible in the dashboard or via `wrangler whoami`).
- On every push to `main`, `.github/workflows/deploy.yml` installs dependencies and runs `wrangler deploy`.
- You can also trigger the workflow manually through the GitHub UI (`Actions → Deploy Worker → Run workflow`).

## Development Commands
- `npm run dev` — run the Worker locally with `wrangler dev`.
- `npm run deploy` — deploy the Worker to Cloudflare (ensure bindings and secrets are configured first).
- `npm run check` — type-check the TypeScript sources.
- `npm run fmt` — format the project with Prettier.

## Next Steps
- Add household authentication/guard rails before exposing the connect page and manual sync endpoint.
- Build an admin control that invokes `POST /api/manual-sync` so trusted users can trigger immediate refreshes.
- Enhance the dashboard heat map with legend toggles, per-person filters, and kiosk-friendly layout tweaks.
- Layer in testing (unit for overlap logic, integration for sync flows) and monitoring around `sync_runs`.

### Manual Sync (API stub)
- `POST /api/manual-sync` with JSON `{ "userId": "uuid" }` queues a background sync for that user using the stored refresh token. Add authentication before exposing this in production.

## Cloudflare Pages
- Static assets live under `pages/`; deploy them via Cloudflare Pages and route the domain so `/auth/google/start` hits the Worker while `/` serves the static HTML.
- `pages/index.html` provides a minimal “Connect with Google” UI and surfaces success/error feedback based on the `status` query string. For local dev it auto-swaps the form action to the Worker port (8787).
- `pages/dashboard.html` consumes `/api/availability` and renders a simple heat map using an inline palette so you can preview the data before building a richer SPA. During local dev it points the fetch at port 8787 automatically.
