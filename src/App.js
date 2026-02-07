// src/App.js
import React, { useState, useEffect } from "react";
import "./App.css"; // Make sure your CSS is imported

const API_BASE = "https://threat-intel-aggregator.onrender.com";

function App() {
  const [ioc, setIoc] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [news, setNews] = useState([]);

  // ✅ Fetch Cyber News (LIVE backend)
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

      if (!res.ok) {
        setResult({ error: "Backend error", detail: data });
      } else {
        setResult(data);
      }
    } catch (err) {
      setResult({ error: "Server not reachable", detail: err.message });
    }
    setLoading(false);
  };

  return (
    <div className="app-shell">
      {/* 🟢 MAIN CONTENT WRAPPER: This pushes the footer down */}
      <div className="main-content">
        
        {/* -------- Left Panel -------- */}
        <div className="panel">
          <div className="header-flex" style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: "10px" }}>
            <img src="/logo.png" alt="Logo" style={{ height: "90px" }} />
            <div>
              <h1 style={{ margin: 0, fontSize: "38px" }}>Threat Intel Aggregator</h1>
              <h2 style={{ margin: 0 }}>One Stop Dashboard</h2>
            </div>
          </div>

          <h2 className="sub-title">Enter IP, Domain, URL or Hash to investigate</h2>
          
          <div className="terminal">
            <div className="input-row">
              <input
                type="text"
                placeholder="Enter IOC here..."
                value={ioc}
                onChange={(e) => setIoc(e.target.value)}
                className="input"
                style={{ fontSize: "18px", padding: "12px" }}
              />
              <button onClick={handleCheck} disabled={loading} className="btn">
                {loading ? "Checking..." : "Check"}
              </button>
            </div>
          </div>

          {/* -------- Results Section -------- */}
          {result && !result.error && (
            <div className="result">
              <span className={`badge risk-${result.combined_risk || "Low"}`}>
                {result.combined_risk || "Unknown"}
              </span>

              {result.virustotal && (
                <div className="result-card">
                  <h2>🛡 VirusTotal</h2>
                  <p><strong>ASN:</strong> {result.virustotal.asn || "N/A"}</p>
                  <p><strong>Country:</strong> {result.virustotal.country || "N/A"}</p>
                  <p><strong>Malicious:</strong> {result.virustotal.malicious}</p>
                  <p><strong>Suspicious:</strong> {result.virustotal.suspicious}</p>
                  <p><strong>Harmless:</strong> {result.virustotal.harmless}</p>
                </div>
              )}

              {result.abuseipdb && (
                <div className="result-card">
                  <h2>🚨 AbuseIPDB</h2>
                  {result.abuseipdb.reports ? (
                    <>
                      <p><strong>Reports:</strong> {result.abuseipdb.reports}</p>
                      <p><strong>Confidence:</strong> {result.abuseipdb.abuseConfidence}%</p>
                      <p><strong>ISP:</strong> {result.abuseipdb.isp}</p>
                      <p><strong>Country:</strong> {result.abuseipdb.country}</p>
                    </>
                  ) : (
                    <p>No Data</p>
                  )}
                </div>
              )}

              {result.otx && (
                <div className="result-card">
                  <h2>👽 AlienVault OTX</h2>
                  <p><strong>Pulses:</strong> {result.otx.pulse_count}</p>
                  <p><strong>Families:</strong> {result.otx.malware_families?.length
                    ? result.otx.malware_families.join(", ")
                    : "N/A"}
                  </p>
                </div>
              )}
            </div>
          )}

          {result?.error && (
            <div className="result">
              <span className="badge risk-High">Error</span>
              <pre>{JSON.stringify(result, null, 2)}</pre>
            </div>
          )}
        </div>

        {/* -------- Right Panel -------- */}
        <div className="side">
          <h1>📰 Cybersecurity News</h1>
          <div className="news-ticker">
            <ul>
              {news.map((item, i) => (
                <li key={i}>
                  <a href={item.link} target="_blank" rel="noreferrer">
                    <strong>[{item.source}]</strong> {item.title}
                  </a>
                </li>
              ))}
            </ul>
          </div>

          <h1>🖥️ Quick Links</h1>
          <div className="small-links">
            <a href="https://exchange.xforce.ibmcloud.com/" target="_blank" rel="noreferrer">IBM X-Force</a><br />
            <a href="https://www.shodan.io/" target="_blank" rel="noreferrer">Shodan</a><br />
            <a href="https://talosintelligence.com/" target="_blank" rel="noreferrer">Cisco Talos</a><br />
            <a href="https://www.cert-in.org.in/" target="_blank" rel="noreferrer">Indian CERT</a>
          </div>
        </div>
      </div>

      {/* 🔵 FOOTER: Will now stay at the bottom */}
      <footer className="footer">
        ©️ 2026 All Rights Reserved | Threat Intel Aggregator by Omsai Dagwar
      </footer>
    </div>
  );
}

export default App;