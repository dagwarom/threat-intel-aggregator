import React, { useEffect, useState } from "react";
import "./TopStatsBar.css";

function TopStatsBar({ scansToday, lastVerdict, feedSources }) {
  const [systemTime, setSystemTime] = useState(() => new Date());

  useEffect(() => {
    const timer = window.setInterval(() => {
      setSystemTime(new Date());
    }, 1000);

    return () => window.clearInterval(timer);
  }, []);

  const stats = [
    { label: "Scans Today", value: scansToday },
    { label: "Last Verdict", value: lastVerdict },
    { label: "Feed Sources", value: feedSources || 0 },
    {
      label: "System Time",
      value: systemTime.toLocaleString("en-IN", {
        dateStyle: "medium",
        timeStyle: "medium",
      }),
    },
  ];

  return (
    <section className="top-stats-bar" aria-label="Top statistics">
      {stats.map((item) => (
        <div className="top-stat-card" key={item.label}>
          <span>{item.label}</span>
          <strong>{item.value}</strong>
        </div>
      ))}
    </section>
  );
}

export default TopStatsBar;
