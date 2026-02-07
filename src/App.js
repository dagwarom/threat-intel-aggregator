// src/App.js
import React, { useState, useEffect } from "react";

const API_BASE = "https://threat-intel-aggregator.onrender.com";

function App() {
  const [ioc, setIoc] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [news, setNews] = useState([]);

  useEffect(() => {
    fetch(`${API_BASE}/news`)
      .then((res) => res.json())
      .then((data) => setNews(data))
      .catch(() =>
        setNews([{ title: "Failed to load news", link: "#", source: "error" }])
      );
  }, []);

  const handleCheck = async () => {
    if (!ioc) return;
    setLoading(true);
    setResult(null);
    try {
      const res = await fetch(`${API_BASE}/check`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ioc }),
      });
      const data = await res.json();
      setResult(res.ok ? data : { error: "Backend error", detail: data });
    } catch (err) {
      setResult({ error: "Server not reachable", detail: err.message });
    }
    setLoading(false);
  };

  return (
    <div className="app-shell">

      {/* MAIN CONTENT */}
      <div className="main-layout">

        {/* LEFT PANEL */}
        <div className="panel">
          <div className="header">
            <img src="/logo.png" alt="Logo" />
            <div>
              <h1>Threat Intel Aggregator</h1>
              <h2>One Stop Dashboard</h2>
            </div>
          </div>

          <h3>Enter IP, Domain, URL or Hash</h3>

          <div className="input-row">
            <input
              value={ioc}
              onChange={(e) => setIoc(e.target.value)}
              placeholder="Enter IOC"
            />
            <button onClick={handleCheck} disabled={loading}>
              {loading ? "Checking..." : "Check"}
            </button>
          </div>

          {result && !result.error && (
            <div className="result">
              <span className={`badge ${result.combined_risk}`}>
                {result.combined_risk}
              </span>

              {result.virustotal && (
                <div className="card">
                  <h4>VirusTotal</h4>
                  <p>Malicious: {result.virustotal.malicious}</p>
                  <p>Suspicious: {result.virustotal.suspicious}</p>
                  <p>Harmless: {result.virustotal.harmless}</p>
                </div>
              )}

              {result.abuseipdb && (
                <div className="card">
                  <h4>AbuseIPDB</h4>
                  <p>Reports: {result.abuseipdb.reports || "N/A"}</p>
                </div>
              )}

              {result.otx && (
                <div className="card">
                  <h4>AlienVault OTX</h4>
                  <p>Pulses: {result.otx.pulse_count}</p>
                </div>
              )}
            </div>
          )}

          {result?.error && (
            <pre className="error">{JSON.stringify(result, null, 2)}</pre>
          )}
        </div>

        {/* RIGHT PANEL */}
        <div className="side">
          <h3>Cybersecurity News</h3>
          <ul>
            {news.map((n, i) => (
              <li key={i}>
                <a href={n.link} target="_blank" rel="noreferrer">
                  {n.title}
                </a>
              </li>
            ))}
          </ul>
        </div>

      </div>

      {/* FOOTER (ALWAYS LAST) */}
      <footer className="footer">
        © 2026 All Rights Reserved | Threat Intel Aggregator by Omsai Dagwar
      </footer>

    </div>
  );
}

export default App;
