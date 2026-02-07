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
      .then(res => res.json())
      .then(setNews)
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
      setResult(await res.json());
    } catch {
      setResult({ error: "Backend not reachable" });
    }
    setLoading(false);
  };

  return (
    <div className="app-shell">
      {/* MAIN CONTENT */}
      <main className="content">
        <div className="panel">
          <h1>Threat Intel Aggregator</h1>
          <h2>One Stop Dashboard</h2>

          <input
            placeholder="Enter IOC"
            value={ioc}
            onChange={e => setIoc(e.target.value)}
          />
          <button onClick={handleCheck}>
            {loading ? "Checking..." : "Check"}
          </button>

          <h2>Cybersecurity News</h2>
          <ul>
            {news.map((n, i) => (
              <li key={i}>{n.title}</li>
            ))}
          </ul>
        </div>
      </main>

      {/* FOOTER */}
      <footer className="footer">
        © 2026 All Rights Reserved | Threat Intel Aggregator by Omsai Dagwar
      </footer>
    </div>
  );
}

export default App;
