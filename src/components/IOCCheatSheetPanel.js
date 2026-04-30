import React, { useEffect, useMemo, useState } from "react";
import "./IOCCheatSheetPanel.css";

const INITIAL_VISIBLE_COUNT = 5;
const LOAD_MORE_STEP = 5;

function formatSeverityLabel(severity) {
  if (!severity) return "Low";
  return `${severity.charAt(0).toUpperCase()}${severity.slice(1)}`;
}

function IOCCheatSheetPanel({
  extractedIndicators,
  liveIndicators,
  loading,
  onAnalyze,
  sourceStatus,
}) {
  const [visibleExtractedCount, setVisibleExtractedCount] = useState(INITIAL_VISIBLE_COUNT);
  const [visibleLiveCount, setVisibleLiveCount] = useState(INITIAL_VISIBLE_COUNT);

  const visibleExtracted = useMemo(
    () => extractedIndicators.slice(0, visibleExtractedCount),
    [extractedIndicators, visibleExtractedCount]
  );
  const visibleLive = useMemo(
    () => liveIndicators.slice(0, visibleLiveCount),
    [liveIndicators, visibleLiveCount]
  );

  useEffect(() => {
    setVisibleExtractedCount((count) => Math.min(Math.max(INITIAL_VISIBLE_COUNT, count), Math.max(INITIAL_VISIBLE_COUNT, extractedIndicators.length || INITIAL_VISIBLE_COUNT)));
  }, [extractedIndicators.length]);

  useEffect(() => {
    setVisibleLiveCount((count) => Math.min(Math.max(INITIAL_VISIBLE_COUNT, count), Math.max(INITIAL_VISIBLE_COUNT, liveIndicators.length || INITIAL_VISIBLE_COUNT)));
  }, [liveIndicators.length]);

  const canLoadMoreExtracted = visibleExtractedCount < extractedIndicators.length;
  const canCollapseExtracted = extractedIndicators.length > INITIAL_VISIBLE_COUNT && visibleExtractedCount > INITIAL_VISIBLE_COUNT;
  const canLoadMoreLive = visibleLiveCount < liveIndicators.length;
  const canCollapseLive = liveIndicators.length > INITIAL_VISIBLE_COUNT && visibleLiveCount > INITIAL_VISIBLE_COUNT;

  return (
    <section className="reference-panel" aria-labelledby="ioc-cheat-sheet-title">
      <p className="eyebrow">Threat Enrichment</p>
      <h2 id="ioc-cheat-sheet-title">Live &amp; Extracted Indicators</h2>

      <div className="indicator-section">
        <div className="indicator-section-header">
          <h3>Extracted Indicators</h3>
          <span className="dataset-pill">{extractedIndicators.length} detected</span>
        </div>

        {extractedIndicators.length ? (
          <>
            <p className="indicator-count">
              Showing {visibleExtracted.length} of {extractedIndicators.length} indicators
            </p>
            <div className="dynamic-indicator-list">
              {visibleExtracted.map((item) => (
              <article className="dynamic-indicator-card" key={`${item.type}-${item.value}`}>
                <div className="dynamic-indicator-copy">
                  <span>{item.type}</span>
                  <strong>{item.value}</strong>
                  <p>{item.sources?.[0] || `${item.count} log observation(s) extracted from uploaded events.`}</p>
                </div>
                <div className="dynamic-indicator-actions">
                  <span className="severity-chip medium">Extracted</span>
                  <button className="btn secondary" onClick={() => onAnalyze(item.value)} type="button">
                    Analyze
                  </button>
                </div>
              </article>
              ))}
            </div>
            {(canLoadMoreExtracted || canCollapseExtracted) && (
              <div className="indicator-controls">
                {canLoadMoreExtracted && (
                  <button
                    className="btn secondary"
                    onClick={() =>
                      setVisibleExtractedCount((count) =>
                        Math.min(count + LOAD_MORE_STEP, extractedIndicators.length)
                      )
                    }
                    type="button"
                  >
                    Load More
                  </button>
                )}
                {canCollapseExtracted && (
                  <button
                    className="btn tertiary"
                    onClick={() => setVisibleExtractedCount(INITIAL_VISIBLE_COUNT)}
                    type="button"
                  >
                    Show Less
                  </button>
                )}
              </div>
            )}
          </>
        ) : (
          <div className="empty-state">
            <p>Upload Windows Security logs to extract IPs, domains, URLs, emails, and hashes for enrichment.</p>
          </div>
        )}
      </div>

      <div className="indicator-section">
        <div className="indicator-section-header">
          <h3>Live Threat Feed</h3>
          <span className="dataset-pill">{liveIndicators.length} live items</span>
        </div>

        {loading ? (
          <div className="empty-state">
            <p>Fetching live indicators from configured threat intelligence sources.</p>
          </div>
        ) : liveIndicators.length ? (
          <>
            <p className="indicator-count">
              Showing {visibleLive.length} of {liveIndicators.length} indicators
            </p>
            <div className="dynamic-indicator-list">
              {visibleLive.map((item) => (
              <article className="dynamic-indicator-card" key={`${item.source}-${item.type}-${item.indicator}`}>
                <div className="dynamic-indicator-copy">
                  <span>{item.type}</span>
                  <strong>{item.indicator}</strong>
                  <p>{item.description}</p>
                  <small>{item.source}</small>
                </div>
                <div className="dynamic-indicator-actions">
                  <span className={`severity-chip ${item.severity}`}>{formatSeverityLabel(item.severity)}</span>
                  <button className="btn secondary" onClick={() => onAnalyze(item.indicator)} type="button">
                    Analyze
                  </button>
                </div>
              </article>
              ))}
            </div>
            {(canLoadMoreLive || canCollapseLive) && (
              <div className="indicator-controls">
                {canLoadMoreLive && (
                  <button
                    className="btn secondary"
                    onClick={() =>
                      setVisibleLiveCount((count) =>
                        Math.min(count + LOAD_MORE_STEP, liveIndicators.length)
                      )
                    }
                    type="button"
                  >
                    Load More
                  </button>
                )}
                {canCollapseLive && (
                  <button
                    className="btn tertiary"
                    onClick={() => setVisibleLiveCount(INITIAL_VISIBLE_COUNT)}
                    type="button"
                  >
                    Show Less
                  </button>
                )}
              </div>
            )}
          </>
        ) : (
          <div className="empty-state">
            <p>No live indicators are available right now from the configured feeds.</p>
          </div>
        )}
      </div>

      <div className="source-status-list" aria-label="IOC source status">
        {(sourceStatus || []).map((source) => (
          <div className="source-status-item" key={source.name}>
            <strong>{source.name}</strong>
            <span>{source.status === "ok" ? `${source.count || 0} item(s)` : source.message || "Unavailable"}</span>
          </div>
        ))}
      </div>
    </section>
  );
}

export default IOCCheatSheetPanel;
