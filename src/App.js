// src/App.js
import React, { useState, useEffect } from "react";

function App() {
  const [ioc, setIoc] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [news, setNews] = useState([]);

  // ✅ Fetch Cyber News
  useEffect(() => {
    fetch("http://127.0.0.1:5000/news")
      .then((res) => res.json())
      .then((data) => setNews(data))
      .catch(() => setNews([{ title: "Failed to load news", link: "#" }]));
  }, []);

  const handleCheck = async () => {
    if (!ioc) return;
    setLoading(true);
    setResult(null);
    try {
      const res = await fetch("http://127.0.0.1:5000/check", {
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
      {/* -------- Left Panel -------- */}
      <div className="panel">
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "12px",
            marginBottom: "10px",
          }}
        >
          <img src="/logo.png" alt="Logo" style={{ height: "90px" }} />
          <div>
            <h1 style={{ margin: 0, fontSize: "38px" }}>
              Threat Intel Aggregator
            </h1>
            <h2 style={{ margin: 0 }}>One Stop Dashboard</h2>
          </div>
        </div>

        <h2>Enter IP, Domain, URL or Hash to investigate</h2>
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
            {/* ---- Overall Risk Badge ---- */}
            <span className={`badge risk-${result.combined_risk || "Low"}`}>
              {result.combined_risk || "Unknown"}
            </span>

            {/* ---- VIRUSTOTAL CARD ---- */}
            {result.virustotal && (
              <div className="result-card">
                <h2>🛡 VirusTotal</h2>
                <p>
                  <strong>ASN:</strong> {result.virustotal.asn || "N/A"}
                </p>
                <p>
                  <strong>Country:</strong> {result.virustotal.country || "N/A"}
                </p>
                <p>
                  <strong>Malicious:</strong> {result.virustotal.malicious}
                </p>
                <p>
                  <strong>Suspicious:</strong> {result.virustotal.suspicious}
                </p>
                <p>
                  <strong>Harmless:</strong> {result.virustotal.harmless}
                </p>

                {/* ✅ Vendor detections list */}
                {result.virustotal.vendors && (
                  <div className="vendor-table">
                    <h3>🔎 Vendor Detections</h3>
                    <table>
                      <thead>
                        <tr>
                          <th>Vendor</th>
                          <th>Result</th>
                        </tr>
                      </thead>
                      <tbody>
                        {Object.entries(result.virustotal.vendors).map(
                          ([vendor, res], i) => (
                            <tr key={i}>
                              <td>{vendor}</td>
                              <td className={`vendor-${res}`}>{res}</td>
                            </tr>
                          )
                        )}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}

            {/* ---- ABUSEIPDB CARD ---- */}
            {result.abuseipdb && (
              <div className="result-card">
                <h2>🚨 AbuseIPDB</h2>
                {result.abuseipdb.reports ? (
                  <>
                    <p>
                      <strong>Reports:</strong> {result.abuseipdb.reports}
                    </p>
                    <p>
                      <strong>Confidence of Abuse:</strong>{" "}
                      {result.abuseipdb.abuseConfidence}%
                    </p>
                    <p>
                      <strong>ISP:</strong> {result.abuseipdb.isp}
                    </p>
                    <p>
                      <strong>Country:</strong> {result.abuseipdb.country}
                    </p>
                  </>
                ) : (
                  <p>No Data</p>
                )}
              </div>
            )}

            {/* ---- OTX CARD ---- */}
            {result.otx && (
              <div className="result-card">
                <h2>👽 AlienVault OTX</h2>
                <p>
                  <strong>Pulses:</strong> {result.otx.pulse_count}
                </p>
                <p>
                  <strong>Families:</strong>{" "}
                  {result.otx.malware_families?.length > 0
                    ? result.otx.malware_families.join(", ")
                    : "N/A"}
                </p>
              </div>
            )}
          </div>
        )}

        {/* Error Message */}
        {result?.error && (
          <div className="result">
            <span className="badge risk-High">Error</span>
            <div className="pretty">
              <pre>{JSON.stringify(result, null, 2)}</pre>
            </div>
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

        <h1>🌐 Live Threat Feeds</h1>
        <div className="terminal small">
          <p>Malicious IP: 185.220.101.5</p>
          <p>Domain flagged: shady-example.com</p>
          <p>Hash: eicar_test_file</p>
        </div>

        <h1>🖥️ Quick Links</h1>
        <div className="small">
          <a
            href="https://exchange.xforce.ibmcloud.com/"
            target="_blank"
            rel="noreferrer"
          >
            IBM X-Force
          </a>
          <br />
          <a href="https://www.shodan.io/" target="_blank" rel="noreferrer">
            Shodan
          </a>
          <br />
          <a
            href="https://talosintelligence.com/"
            target="_blank"
            rel="noreferrer"
          >
            Cisco Talos
          </a>
          <br />
          <a
            href="https://www.cert-in.org.in/"
            target="_blank"
            rel="noreferrer"
          >
            Indian CERT
          </a>
        </div>

        <h1>🧠 SOC Tips</h1>
        <div className="small">
          <p>🔍 Detect beaconing traffic via unusual DNS patterns.</p>
          <p>📂 Always decode suspicious Base64 strings in logs.</p>
          <p>
            🛡️ Cross-check IOCs across multiple sources (VT, OTX, AbuseIPDB).
          </p>
        </div>
      </div>

      {/* -------- Footer -------- */}
      <footer className="footer">
        © 2026 All Rights Reserved | Threat Intel Aggregator by Omsai Dagwar
      </footer>
    </div>
  );
}

export default App;
