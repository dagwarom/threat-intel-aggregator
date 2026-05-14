# Backend Service

This directory contains the Flask API for Threat Intel Aggregator. It powers IOC lookups, live feed aggregation, and security news retrieval for the dashboard.

## Features

- IOC type detection for IPs, domains, URLs, hashes, and emails.
- Parallel enrichment across configured threat intelligence providers.
- Risk scoring, verdict generation, and provider breakdown output.
- Aggregated security news feed with caching.
- Aggregated IOC feed with source status tracking.
- CORS support for the frontend dashboard.
- Basic request rate limiting.

## Requirements

- Python 3.10+.
- Packages listed in `requirements.txt`.
- Optional provider API keys for external lookups.

## Installation

1. Create and activate a virtual environment.
2. Install dependencies with `pip install -r requirements.txt`.
3. Configure the environment variables listed below.
4. Start the API with `python app.py`.

## Environment Variables

- `VT_API_KEY` for VirusTotal.
- `ABUSEIPDB_API_KEY` for AbuseIPDB.
- `OTX_API_KEY` for AlienVault OTX.
- `MALWAREBAZAAR_AUTH_KEY` for MalwareBazaar.
- `THREATFOX_AUTH_KEY` for ThreatFox.
- `URLHAUS_AUTH_KEY` for URLhaus.
- `ALLOWED_ORIGINS` for the frontend CORS allow-list.
- `REQUEST_TIMEOUT` for outbound HTTP timeout in seconds.
- `NEWS_CACHE_SECONDS` for caching news and IOC feeds.
- `RATELIMIT_STORAGE_URI` for the limiter storage backend.
- `PORT` for the server port.
- `FLASK_DEBUG` set to `1` to run in debug mode.

## API Endpoints

- `POST /check` accepts `{ "ioc": "..." }` and returns scan results.
- `GET /news` returns aggregated cyber news articles.
- `GET /ioc-feed` returns live IOC feed items and source health.
- `GET /` returns the API health response.

## Example

```bash
curl -X POST http://127.0.0.1:5000/check ^
  -H "Content-Type: application/json" ^
  -d "{\"ioc\":\"8.8.8.8\"}"
```

## Notes

- Missing provider keys do not break the service; the API returns the sources that are available.
- Rate limiting and caching are already configured in code.
- If you change the frontend origin, update `ALLOWED_ORIGINS` accordingly.