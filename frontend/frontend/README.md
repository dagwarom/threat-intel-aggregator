# Frontend Dashboard

This directory contains the React user interface for Threat Intel Aggregator. It provides IOC triage, live indicator review, DFIR log analysis, and export tools in a single dashboard.

## Features

- IOC scan input with verdict, severity, score, and provider details.
- Live and extracted indicator panels with load-more controls.
- Security news and IOC feed visibility.
- DFIR log analyzer module for Windows Security log evidence.
- USB forensic summary and suspicious activity review.
- MITRE ATT&CK reference panel for common event mappings.
- CSV and PDF report exports for IOC and DFIR workflows.
- Top-level status bar with scan count, verdict, feed source count, and system time.

## Requirements

- Node.js 18+ or another recent LTS release.
- npm.
- A running backend API, defaulting to `http://127.0.0.1:5000`.

## Installation

1. Install dependencies with `npm install`.
2. Start the app with `npm start`.
3. Build a production bundle with `npm run build`.

Set `REACT_APP_API_BASE_URL` if the backend is not running on the default local URL.

## Available Scripts

- `npm start` runs the dashboard in development mode.
- `npm test` starts the React test runner.
- `npm run build` creates a production build.
- `npm run eject` exposes the underlying Create React App configuration.

## Usage

1. Start the backend API.
2. Start this frontend app.
3. Scan an IOC or review imported evidence in the DFIR tab.

The dashboard is designed for local analyst workflows first, but the build output can be deployed to any static hosting platform that can reach the backend API.