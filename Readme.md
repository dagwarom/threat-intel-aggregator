# Threat Intel Aggregator

Threat Intel Aggregator is a one-stop dashboard for checking indicators of compromise (IOCs) against multiple threat-intelligence providers and showing current cybersecurity news.

## Features

- IOC lookup for IP addresses, domains, URLs, MD5, SHA1, and SHA256 hashes
- VirusTotal, AbuseIPDB, and AlienVault OTX enrichment
- Combined risk score based on provider results
- Cybersecurity news feed
- React dashboard UI
- Flask API backend suitable for Render deployment

## Project Structure

```text
backend/
  app.py
  requirements.txt
  .env.example
frontend/frontend/
  package.json
  public/
  src/
Readme.md
```

The active backend is `backend/`.

The active frontend is `frontend/frontend/`. The outer `frontend/` files and root `App.js` appear to be older duplicate files and should be cleaned up only after confirming they are not used by Render or any local workflow.

## Backend Setup

```bash
cd backend
pip install -r requirements.txt
python app.py
```

Create a local `.env` file from `.env.example`:

```env
VT_API_KEY=
ABUSEIPDB_API_KEY=
OTX_API_KEY=
ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000
FLASK_DEBUG=1
```

Do not commit `.env`.

## Frontend Setup

```bash
cd frontend/frontend
npm install
npm start
```

For local development, set:

```env
REACT_APP_API_BASE_URL=http://127.0.0.1:5000
```

For production, set `REACT_APP_API_BASE_URL` to the deployed backend URL.

## Render Deployment

### Backend service

- Root Directory: `backend`
- Build Command: `pip install -r requirements.txt`
- Start Command: `gunicorn app:app`

Required environment variables:

```text
VT_API_KEY
ABUSEIPDB_API_KEY
OTX_API_KEY
ALLOWED_ORIGINS=https://your-frontend-service.onrender.com
FLASK_DEBUG=0
```

Optional environment variables:

```text
REQUEST_TIMEOUT=15
NEWS_CACHE_SECONDS=600
RATELIMIT_STORAGE_URI=memory://
```

For production scale-out, use a shared rate-limit store instead of `memory://`.

### Frontend service

- Root Directory: `frontend/frontend`
- Build Command: `npm install && npm run build`
- Publish Directory: `build`

Required environment variable:

```text
REACT_APP_API_BASE_URL=https://your-backend-service.onrender.com
```

## Security Notes

- API keys are loaded only from environment variables.
- CORS is restricted by `ALLOWED_ORIGINS`.
- `/check` is rate-limited to reduce API quota abuse.
- External API calls use request timeouts.
- Raw provider exceptions are logged server-side and not returned to users.
- News responses are cached with a TTL to avoid repeated RSS fetches.

## Dependency Notes

The active frontend currently uses Create React App through `react-scripts`. CRA has several vulnerable transitive development dependencies. The safer long-term path is migrating the active frontend to Vite. That migration is intentionally not included in this production-hardening pass because it is a larger tooling change and could affect deployment behavior.
