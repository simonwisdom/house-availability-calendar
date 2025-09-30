# Testing Guide: Multi-Provider Calendar Support

## Server Status
✅ Local dev server running at: http://localhost:52095
✅ Database migrations applied
✅ Worker running with both Google and CalDAV providers

---

## Testing Checklist

### 1. **Test Health Check**
```bash
curl http://localhost:52095/health
```
Expected: `{"ok":true,"message":"house-availability worker alive"}`

### 2. **Test Household Login**
Open browser: http://localhost:52095/household/login

- Enter your household passphrase (from `.dev.vars` → `HOUSEHOLD_SECRET`)
- Should redirect to dashboard
- Verify session cookie is set

### 3. **Test Google Calendar Flow (Backward Compatibility)**

**From Dashboard:**
1. Open http://localhost:8788/ (Pages dev server)
2. Should see "Connect Google Calendar" button if no data
3. Click "Connect Google Calendar"
4. Should redirect to Google OAuth
5. After auth, should redirect back and trigger sync

**Via API:**
```bash
# Start OAuth flow
curl http://localhost:52095/auth/google/start
```

### 4. **Test Apple Calendar Setup (New Feature)**

**Via UI:**
1. Open http://localhost:8788/
2. Click "Connect Apple Calendar" button
3. Form should appear with:
   - Name field
   - Apple ID Email field
   - App-Specific Password field
   - Link to Apple support docs

**Generate Test App-Specific Password:**
1. Go to https://appleid.apple.com
2. Sign in with your Apple ID
3. Navigate to "Sign-In and Security" → "App-Specific Passwords"
4. Generate new password
5. Copy the password (format: xxxx-xxxx-xxxx-xxxx)

**Submit Form:**
- Name: Your Name
- Email: your@icloud.com
- Password: [app-specific password]
- Click "Connect Calendar"

**Via API (for testing):**
```bash
curl -X POST http://localhost:52095/auth/caldav/setup \
  -H "Content-Type: application/json" \
  -d '{
    "displayName": "Test User",
    "email": "test@icloud.com",
    "password": "xxxx-xxxx-xxxx-xxxx"
  }'
```

Expected response: `{"ok":true,"redirectUrl":"..."}`

### 5. **Verify Database State**

**Check users table:**
```bash
npx wrangler d1 execute house_availability --local \
  --command "SELECT id, email, provider, calendar_id, caldav_url FROM users"
```

Should see:
- Google users: `provider='google'`, `caldav_url=NULL`
- CalDAV users: `provider='caldav'`, `caldav_url='https://caldav.icloud.com'`

**Check sync runs:**
```bash
npx wrangler d1 execute house_availability --local \
  --command "SELECT * FROM sync_runs ORDER BY started_at DESC LIMIT 5"
```

### 6. **Test Manual Sync**

**For Google user:**
```bash
curl -X POST http://localhost:52095/api/manual-sync \
  -H "Content-Type: application/json" \
  -d '{"userId": "<USER_ID_FROM_DB>"}'
```

**For CalDAV user:**
```bash
curl -X POST http://localhost:52095/api/manual-sync \
  -H "Content-Type: application/json" \
  -d '{"userId": "<USER_ID_FROM_DB>"}'
```

Expected: `{"ok":true,"queued":true}`

### 7. **Check Sync Results**

**View freebusy windows:**
```bash
npx wrangler d1 execute house_availability --local \
  --command "SELECT user_id, source, start_at, end_at FROM freebusy_windows LIMIT 10"
```

Should see:
- Google users: `source='google-freebusy'`
- CalDAV users: `source='caldav-freebusy'`

**View availability:**
```bash
npx wrangler d1 execute house_availability --local \
  --command "SELECT * FROM daily_availability ORDER BY date DESC LIMIT 10"
```

### 8. **Test API Availability Endpoint**

```bash
curl http://localhost:52095/api/availability | jq
```

Should return:
```json
{
  "timezone": "Europe/London",
  "days": [
    {"date": "2025-09-30", "freeCount": 0},
    ...
  ],
  "lastUpdatedIso": "2025-09-30T..."
}
```

### 9. **Frontend Testing**

**Open Pages dev server:**
```bash
# In another terminal:
npx wrangler pages dev pages --port 8788
```

Then visit: http://localhost:8788/

**Test scenarios:**
1. **No users connected**: Should show blurred placeholder + "Connect" overlay
2. **Users connected**: Should show heat map with real data
3. **Provider selection**: Click Apple button → form appears
4. **Form validation**: Try submitting empty form → should show required errors
5. **Back navigation**: Click "← Back to provider selection" → returns to buttons

### 10. **Error Handling Tests**

**Invalid CalDAV credentials:**
```bash
curl -X POST http://localhost:52095/auth/caldav/setup \
  -H "Content-Type: application/json" \
  -d '{
    "displayName": "Test",
    "email": "test@icloud.com",
    "password": "wrong-password"
  }'
```

Check sync_runs for error messages.

**Missing required fields:**
```bash
curl -X POST http://localhost:52095/auth/caldav/setup \
  -H "Content-Type: application/json" \
  -d '{}'
```

Expected: `{"ok":false,"error":"Email and password are required"}`

---

## Debugging Tips

### View Worker Logs
Logs appear in the terminal where `npm run dev` is running.

### Inspect Database
```bash
# Open interactive SQL shell
npx wrangler d1 execute house_availability --local --command "SELECT * FROM users"

# Check sync errors
npx wrangler d1 execute house_availability --local \
  --command "SELECT * FROM sync_runs WHERE status='error' ORDER BY started_at DESC"
```

### Test CalDAV Server Detection
The system auto-detects CalDAV URLs:
- `test@icloud.com` → `https://caldav.icloud.com`
- `test@gmail.com` → `https://www.google.com/calendar/dav`
- `test@outlook.com` → `https://outlook.office365.com`

### Common Issues

**CalDAV sync fails:**
- Verify app-specific password is correct
- Check caldav_url in database
- Look for error in sync_runs table

**Google OAuth fails:**
- Check `.dev.vars` has correct CLIENT_ID/SECRET
- Verify REDIRECT_URI matches OAuth app settings

**No data showing:**
- Check sync_runs table for successful syncs
- Verify daily_availability has records
- Check browser console for API errors

---

## Production Testing

When ready to deploy:

1. **Apply migration to production:**
```bash
npx wrangler d1 migrations apply house_availability --remote
```

2. **Deploy Worker:**
```bash
npm run deploy
```

3. **Deploy Pages:**
```bash
npx wrangler pages deploy pages
```

4. **Test production endpoints:**
- https://house-availability.simonwisdom.workers.dev/health
- Your Pages domain dashboard

---

## Quick Manual Test Script

Save this as `test-providers.sh`:

```bash
#!/bin/bash

echo "Testing Apple Calendar Setup..."
curl -X POST http://localhost:52095/auth/caldav/setup \
  -H "Content-Type: application/json" \
  -d '{
    "displayName": "Test User",
    "email": "test@icloud.com",
    "password": "test-password"
  }' | jq

echo "\nChecking users..."
npx wrangler d1 execute house_availability --local \
  --command "SELECT email, provider FROM users"

echo "\nDone!"
```

Run with: `chmod +x test-providers.sh && ./test-providers.sh`