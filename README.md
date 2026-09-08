# Threat Intel Aggregator

Threat Intel Aggregator is a one-stop dashboard for IOC triage, live threat enrichment, and DFIR log review. The app combines a React frontend with a Flask backend so analysts can scan indicators, review threat feeds, and generate exportable reports from the same workflow.

## What It Does

- IOC scanning for IPs, domains, URLs, emails, and hashes.
- Multi-source enrichment from VirusTotal, AbuseIPDB, AlienVault OTX, MalwareBazaar, and ThreatFox.
- Live threat feed aggregation from configured public intelligence sources.
- News feed aggregation for current security reporting.
- DFIR log analysis for uploaded Windows Security event data.
- USB forensic summaries and suspicious activity detection.
- MITRE ATT&CK reference mapping for common event IDs.
- Export of IOC and DFIR outputs to CSV and PDF.

## Repository Layout

- `backend/` contains the Flask API and enrichment logic.
- `frontend/frontend/` contains the React dashboard UI.
- `scripts/Export-SecurityLogs.ps1` is the helper script for exporting Windows Security logs for DFIR review.

## Requirements

- Node.js 18+ or another recent LTS release.
- Python 3.10+.
- npm for the React app.
- Optional API keys for third-party intelligence providers.

## Setup

### Backend

1. Open a terminal in `backend`.
2. Create and activate a virtual environment if you want an isolated Python install.
3. Install dependencies with `pip install -r requirements.txt`.
4. Add the required API keys to your environment if you want provider enrichment.
5. Run the API with `python app.py`.

### Frontend

1. Open a terminal in `frontend/frontend`.
2. Install dependencies with `npm install`.
3. Start the dashboard with `npm start`.

The frontend expects the backend at `http://127.0.0.1:5000` by default. You can override that with `REACT_APP_API_BASE_URL`.

## Environment Variables

Backend:

- `VT_API_KEY` for VirusTotal.
- `ABUSEIPDB_API_KEY` for AbuseIPDB.
- `OTX_API_KEY` for AlienVault OTX.
- `MALWAREBAZAAR_AUTH_KEY` for MalwareBazaar.
- `THREATFOX_AUTH_KEY` for ThreatFox.
- `URLHAUS_AUTH_KEY` for URLhaus.
- `ALLOWED_ORIGINS` for CORS allow-list.
- `REQUEST_TIMEOUT` for outbound request timeout in seconds.
- `NEWS_CACHE_SECONDS` for news and IOC feed caching.
- `RATELIMIT_STORAGE_URI` for rate limit storage.
- `PORT` for the Flask server port.
- `FLASK_DEBUG` to enable debug mode when set to `1`.

Frontend:

- `REACT_APP_API_BASE_URL` to point the UI to a custom backend URL.

## Main Features

### IOC Triage

Paste an indicator into the scan panel to enrich it across supported providers. The result includes verdict, severity, score, confidence, provider breakdown, and analyst guidance.

### Live Threat Context

The dashboard aggregates live indicators and lets you inspect extracted IOCs and feed items side by side.

### DFIR Log Analyzer

Upload or review Windows Security logs to generate findings, timeline summaries, suspicious clusters, USB forensic context, and exportable reports.

### Reporting

Both IOC and DFIR workflows support CSV and PDF export so findings can be shared or archived.

## Backend API

- `POST /check` scans one IOC and returns enrichment, scoring, and verdict data.
- `GET /news` returns the aggregated security news feed.
- `GET /ioc-feed` returns live IOC feed items plus source health.
- `GET /` returns a simple API status response.

## Notes

- If one provider key is missing, the scan still runs with the available sources.
- Rate limiting and caching are already enabled in the backend.
- The frontend and backend are designed to run locally first, then be deployed separately if needed.