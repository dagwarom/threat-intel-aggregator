import React, { useEffect, useMemo, useState } from "react";
import "./App.css";
import { checkIOC, getIOCFeed, getNews } from "./api";
import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";
import TopStatsBar from "./components/TopStatsBar";
import IOCCheatSheetPanel from "./components/IOCCheatSheetPanel";
import MitreAttackPanel from "./components/MitreAttackPanel";

const WATCHED_EVENTS = {
  failedLogons: new Set(["4625"]),
  successfulLogons: new Set(["4624"]),
  lockouts: new Set(["4740"]),
  privilegeEvents: new Set(["4672"]),
};

const WORKFLOW_STEPS = [
  "Run Script",
  "Choose Date Range",
  "Export CSV",
  "Upload to Dashboard",
  "Review Findings",
];

const TABS = [
  { id: "scan", label: "Scan" },
  { id: "logs", label: "DFIR Log Analyzer Module", shortLabel: "DFIR Logs" },
];

const SAMPLE_EXPORT_COMMAND =
  'powershell -ExecutionPolicy Bypass -File .\\scripts\\Export-SecurityLogs.ps1 -Start "2026-04-01" -End "2026-04-23" -OutFile .\\security-audit.csv';

const EMAIL_PATTERN = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;
const URL_PATTERN = /\bhttps?:\/\/[^\s"'<>]+/gi;
const HASH_PATTERN = /\b(?:[A-F0-9]{32}|[A-F0-9]{40}|[A-F0-9]{64})\b/gi;
const IPV4_PATTERN = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const DOMAIN_PATTERN = /\b(?!(?:\d+\.){3}\d+\b)(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,24}\b/gi;
const HIGH_RISK_EVENT_IDS = new Set(["4625", "4672", "4740"]);

function padNumber(value) {
  return String(value).padStart(2, "0");
}

function formatReportTimestamp(date = new Date()) {
  return `${date.getFullYear()}${padNumber(date.getMonth() + 1)}${padNumber(date.getDate())}-${padNumber(date.getHours())}${padNumber(date.getMinutes())}`;
}

function formatReportDateTime(date = new Date()) {
  return date.toLocaleString();
}

function escapeCsvValue(value) {
  const text = value === null || value === undefined ? "" : String(value);
  if (/[",\r\n]/.test(text)) {
    return `"${text.replace(/"/g, '""')}"`;
  }
  return text;
}

function buildCsvContent(rows) {
  return rows.map((row) => row.map(escapeCsvValue).join(",")).join("\r\n");
}

function downloadBlob(filename, blob) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

function downloadCsv(filename, rows) {
  downloadBlob(filename, new Blob([buildCsvContent(rows)], { type: "text/csv;charset=utf-8" }));
}

function drawReportHeader(doc, title, generatedAt) {
  doc.setTextColor(15, 23, 42);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(18);
  doc.text(title, 14, 16);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(10);
  doc.text(`Generated ${generatedAt}`, 14, 24);
}

function drawKeyValueTable(doc, rows, startY) {
  autoTable(doc, {
    startY,
    head: [["Field", "Value"]],
    body: rows,
    theme: "grid",
    margin: { left: 14, right: 14 },
    styles: { fontSize: 9, cellPadding: 3, textColor: [31, 41, 55] },
    headStyles: { fillColor: [15, 23, 42], textColor: [255, 255, 255] },
    alternateRowStyles: { fillColor: [248, 250, 252] },
  });
  return doc.lastAutoTable.finalY + 8;
}

function drawTableSection(doc, title, head, body, startY) {
  doc.setFont("helvetica", "bold");
  doc.setFontSize(12);
  doc.text(title, 14, startY);
  autoTable(doc, {
    startY: startY + 4,
    head,
    body,
    theme: "grid",
    margin: { left: 14, right: 14 },
    styles: { fontSize: 9, cellPadding: 3, textColor: [31, 41, 55] },
    headStyles: { fillColor: [15, 23, 42], textColor: [255, 255, 255] },
    alternateRowStyles: { fillColor: [248, 250, 252] },
  });
  return doc.lastAutoTable.finalY + 8;
}

function drawListSection(doc, title, items, startY) {
  if (!items.length) {
    return startY;
  }

  doc.setFont("helvetica", "bold");
  doc.setFontSize(12);
  doc.text(title, 14, startY);
  autoTable(doc, {
    startY: startY + 4,
    body: items.map((item) => [item]),
    theme: "grid",
    margin: { left: 14, right: 14 },
    styles: { fontSize: 9, cellPadding: 3, textColor: [31, 41, 55] },
    columnStyles: { 0: { cellWidth: "auto" } },
  });
  return doc.lastAutoTable.finalY + 8;
}

function buildDfirAdvisory(analysis) {
  const advisory = [];
  const findingTitles = analysis.findings.map((finding) => finding.title.toLowerCase());

  if (findingTitles.some((title) => title.includes("brute force") || title.includes("failed authentication"))) {
    advisory.push("Repeated failed logons were detected. Review the source IP or hostname, confirm whether brute-force attempts are present, validate the affected account, and enforce a password reset if required.");
  }

  if (findingTitles.some((title) => title.includes("lockout"))) {
    advisory.push("Account lockouts were observed. Correlate them with failed logons and user activity, and verify whether the pattern is user error or attack activity.");
  }

  if (findingTitles.some((title) => title.includes("privilege"))) {
    advisory.push("Privilege events were observed. Verify the administrative activity, confirm change tickets, and check for unauthorized privilege use.");
  }

  if (findingTitles.some((title) => title.includes("authentication imbalance"))) {
    advisory.push("The authentication balance is unusual. Validate login time, source system, and user behavior against the expected baseline.");
  }

  if (analysis.riskLevel === "High" || analysis.riskLevel === "Critical") {
    advisory.push("High-risk findings should be escalated to a senior analyst for validation before final closure.");
  }

  if (!advisory.length && analysis.summary.totalEvents) {
    advisory.push("No high-signal pattern was triggered, but the imported time window should still be validated against host and identity context before closure.");
  }

  return advisory;
}

function buildDfirCsvRows(analysis) {
  const rows = [
    ["Section", "Field", "Value", "Details", "Severity", "Recommendation"],
    ["Metadata", "Report Title", "Windows Security Log Analysis Report", "", "", ""],
    ["Metadata", "Generated", formatReportDateTime(), "", "", ""],
    ["Summary", "Total Events", analysis.summary.totalEvents, "", "", ""],
    ["Summary", "Failed Logons", analysis.summary.failedLogons, "", "", ""],
    ["Summary", "Successful Logons", analysis.summary.successfulLogons, "", "", ""],
    ["Summary", "Account Lockouts", analysis.summary.lockouts, "", "", ""],
    ["Summary", "Privilege Events", analysis.summary.privilegeEvents, "", "", ""],
    ["Summary", "Risk Level", analysis.riskLevel, "", analysis.riskLevel.toLowerCase(), ""],
  ];

  analysis.executiveSummary.forEach((item, index) => {
    rows.push(["Executive Summary", `Point ${index + 1}`, item, "", "", ""]);
  });

  analysis.findingsSummary.forEach((item) => {
    rows.push(["Findings Summary", item.title, item.detail, "", item.severity, ""]);
  });

  analysis.findings.forEach((finding) => {
    rows.push(["Suspicious Finding", finding.title, finding.evidence, finding.recommendation, finding.severity, finding.confidence]);
  });

  analysis.topEvents.forEach((item) => {
    rows.push(["Risk Indicator", `Event ${item.id}`, item.count, "High-frequency event ID", HIGH_RISK_EVENT_IDS.has(item.id) ? "high" : "medium", "Review event context"]);
  });

  analysis.timelineRows.forEach((item) => {
    rows.push(["Timeline", item.day, item.count, "Daily event total", "low", "Correlate with user and host activity"]);
  });

  buildDfirAdvisory(analysis).forEach((item, index) => {
    rows.push(["Analyst Advisory", `Advisory ${index + 1}`, item, "", analysis.riskLevel.toLowerCase(), ""]);
  });

  analysis.recommendations.forEach((item, index) => {
    rows.push(["Recommended Next Action", `Action ${index + 1}`, item, "", analysis.riskLevel.toLowerCase(), ""]);
  });

  return rows;
}

function exportDfirCsv(analysis) {
  if (!analysis?.summary?.totalEvents) {
    window.alert("No data to export");
    return;
  }
  downloadCsv(`dfir-log-analysis-report-${formatReportTimestamp()}.csv`, buildDfirCsvRows(analysis));
}

function exportDfirPdf(analysis) {
  if (!analysis?.summary?.totalEvents) {
    window.alert("No data to export");
    return;
  }
  const doc = new jsPDF();
  const generatedAt = formatReportDateTime();

  drawReportHeader(doc, "Windows Security Log Analysis Report", generatedAt);
  let cursorY = 30;

  cursorY = drawKeyValueTable(doc, [
    ["Total Events", String(analysis.summary.totalEvents)],
    ["Failed Logons", String(analysis.summary.failedLogons)],
    ["Successful Logons", String(analysis.summary.successfulLogons)],
    ["Account Lockouts", String(analysis.summary.lockouts)],
    ["Privilege Events", String(analysis.summary.privilegeEvents)],
    ["Risk Level", analysis.riskLevel],
  ], cursorY);

  cursorY = drawListSection(doc, "Executive Summary", analysis.executiveSummary.length ? analysis.executiveSummary : ["No executive summary was generated for the current dataset."], cursorY);

  cursorY = drawTableSection(doc, "Suspicious Findings", [["Severity", "Title", "Evidence", "Recommendation", "Confidence"]], analysis.findings.length
    ? analysis.findings.map((finding) => [formatSeverityLabel(finding.severity), finding.title, finding.evidence, finding.recommendation, finding.confidence])
    : [["Low", "No structured findings generated", "The current ruleset did not trigger a suspicious finding.", "Maintain normal log review procedures.", "low confidence"]], cursorY);

  cursorY = drawTableSection(doc, "Findings Summary", [["Title", "Severity", "Detail"]], analysis.findingsSummary.map((item) => [item.title, formatSeverityLabel(item.severity), item.detail]), cursorY);

  const riskRows = [
    ...analysis.topEvents.map((item) => [`Event ${item.id}`, `${item.count} occurrences`, HIGH_RISK_EVENT_IDS.has(item.id) ? "High-risk event ID" : "Frequent event ID"]),
    ...analysis.timelineRows.map((item) => [item.day, `${item.count} events`, "Timeline observation"]),
  ];
  cursorY = drawTableSection(doc, "Risk Indicators", [["Indicator", "Value", "Context"]], riskRows.length ? riskRows : [["No dominant risk indicator", "None", "No clear escalation pattern was observed"]], cursorY);

  cursorY = drawListSection(doc, "Analyst Advisory", buildDfirAdvisory(analysis), cursorY);
  drawListSection(doc, "Recommended Next Actions", analysis.recommendations.length ? analysis.recommendations : ["Validate the imported date range and review the event set before closure."], cursorY);

  doc.save(`dfir-log-analysis-report-${formatReportTimestamp()}.pdf`);
}

function buildIocAdvisory(scanResult) {
  const verdict = (scanResult?.verdict || "").toLowerCase();

  if (verdict === "malicious") {
    return [
      "Block the IOC in firewall, proxy, and EDR controls where applicable.",
      "Search the IOC across SIEM, EDR, DNS, proxy, and email logs.",
      "Identify affected endpoints and users.",
      "Escalate to the incident response team.",
      "Preserve evidence before containment actions are finalized.",
    ];
  }

  if (verdict === "suspicious") {
    return [
      "Monitor and enrich the IOC with additional providers.",
      "Correlate the indicator with internal logs and telemetry.",
      "Validate the evidence with a senior analyst.",
      "Apply a temporary watchlist if needed.",
    ];
  }

  return [
    "No immediate containment is required.",
    "Keep the result for audit and documentation purposes.",
    "Recheck the IOC if new evidence appears.",
  ];
}

function getIocRecommendedActions(scanResult) {
  const verdict = (scanResult?.verdict || scanResult?.combined_risk || "").toLowerCase();

  if (verdict === "malicious") {
    return [
      "Block the IOC in firewall, proxy, and EDR controls where applicable.",
      "Search the IOC across SIEM, EDR, DNS, proxy, and email logs.",
      "Identify affected endpoints and users.",
      "Escalate to the incident response team.",
      "Preserve evidence before containment actions are finalized.",
    ];
  }

  if (verdict === "suspicious") {
    return [
      "Monitor and enrich the IOC with additional providers.",
      "Correlate the indicator with internal logs and telemetry.",
      "Validate the evidence with a senior analyst.",
      "Apply a temporary watchlist if needed.",
    ];
  }

  return [
    "No immediate containment is required.",
    "Keep the result for audit and documentation purposes.",
    "Recheck the IOC if new evidence appears.",
  ];
}

function buildIocCsvRows(scanResult) {
  const rows = [
    ["Section", "Field", "Value", "Details", "Severity", "Recommendation"],
    ["Metadata", "Report Title", "IOC Scan Report", "", "", ""],
    ["Metadata", "Generated", formatReportDateTime(), "", "", ""],
    ["Summary", "Indicator Value", scanResult.ioc || "", "", "", ""],
    ["Summary", "Indicator Type", scanResult.type || "", "", "", ""],
    ["Summary", "Verdict", scanResult.verdict || scanResult.combined_risk || "", "", scanResult.severity?.toLowerCase() || "low", ""],
    ["Summary", "Severity", scanResult.severity || "", "", scanResult.severity?.toLowerCase() || "low", ""],
    ["Summary", "Score", scanResult.score ?? "", "", "", ""],
    ["Summary", "Confidence", `${scanResult.confidence ?? 0}%`, "", "", ""],
  ];

  getProviderRows(scanResult).forEach((row) => {
    rows.push(["Provider Result", row.label, String(row.value), "Provider-backed enrichment result", scanResult.severity?.toLowerCase() || "low", "Review in context"]);
  });

  scanResult.provider_breakdown?.forEach((item) => {
    rows.push(["Provider Breakdown", item.provider, item.score, "Score contribution", scanResult.severity?.toLowerCase() || "low", ""]);
  });

  if (scanResult.highlighted_intelligence?.malware_family) {
    rows.push(["Threat Intelligence Context", "Malware Family", scanResult.highlighted_intelligence.malware_family, "Highlighted intelligence", scanResult.severity?.toLowerCase() || "low", ""]);
  }
  if (scanResult.highlighted_intelligence?.tags?.length > 0) {
    rows.push(["Threat Intelligence Context", "Tags", formatList(scanResult.highlighted_intelligence.tags), "Highlighted intelligence", scanResult.severity?.toLowerCase() || "low", ""]);
  }
  if (scanResult.highlighted_intelligence?.threat_types?.length > 0) {
    rows.push(["Threat Intelligence Context", "Threat Types", formatList(scanResult.highlighted_intelligence.threat_types), "Highlighted intelligence", scanResult.severity?.toLowerCase() || "low", ""]);
  }

  (scanResult.explanations || []).forEach((item, index) => {
    rows.push(["Risk Indicators", `Explanation ${index + 1}`, item, "Verdict reasoning", scanResult.severity?.toLowerCase() || "low", ""]);
  });

  buildIocAdvisory(scanResult).forEach((item, index) => {
    rows.push(["Analyst Advisory", `Advisory ${index + 1}`, item, "", scanResult.severity?.toLowerCase() || "low", ""]);
  });

  getIocRecommendedActions(scanResult).forEach((item, index) => {
    rows.push(["Recommended Response Action", `Action ${index + 1}`, item, "", scanResult.severity?.toLowerCase() || "low", ""]);
  });

  return rows;
}

function exportIocCsv(scanResult) {
  if (!scanResult) {
    window.alert("No data to export");
    return;
  }
  downloadCsv(`ioc-scan-report-${formatReportTimestamp()}.csv`, buildIocCsvRows(scanResult));
}

function exportIocPdf(scanResult) {
  if (!scanResult) {
    window.alert("No data to export");
    return;
  }
  const doc = new jsPDF();
  const generatedAt = formatReportDateTime();

  drawReportHeader(doc, "IOC Scan Report", generatedAt);
  let cursorY = 30;

  cursorY = drawKeyValueTable(doc, [
    ["Indicator Value", scanResult.ioc || ""],
    ["Indicator Type", scanResult.type || ""],
    ["Verdict", scanResult.verdict || scanResult.combined_risk || ""],
    ["Severity", scanResult.severity || ""],
    ["Score", String(scanResult.score ?? 0)],
    ["Confidence", `${scanResult.confidence ?? 0}%`],
  ], cursorY);

  cursorY = drawTableSection(doc, "Provider Results", [["Provider", "Value"]], getProviderRows(scanResult).map((row) => [row.label, String(row.value)]), cursorY);

  const intelRows = [
    ...(scanResult.provider_breakdown || []).map((item) => [item.provider, String(item.score), "Provider contribution"]),
    ...(scanResult.highlighted_intelligence?.malware_family ? [["Malware Family", scanResult.highlighted_intelligence.malware_family, "Highlighted intelligence"]] : []),
    ...(scanResult.highlighted_intelligence?.tags?.length ? [["Tags", formatList(scanResult.highlighted_intelligence.tags), "Highlighted intelligence"]] : []),
    ...(scanResult.highlighted_intelligence?.threat_types?.length ? [["Threat Types", formatList(scanResult.highlighted_intelligence.threat_types), "Highlighted intelligence"]] : []),
  ];
  cursorY = drawTableSection(doc, "Threat Intelligence Context", [["Context", "Value", "Notes"]], intelRows.length ? intelRows : [["No additional context", "Not available", "Provider coverage may be limited by IOC type"]], cursorY);

  cursorY = drawListSection(doc, "Risk Indicators", (scanResult.explanations || []).length ? scanResult.explanations : ["No strong provider-backed threat signals were observed for this indicator."], cursorY);
  cursorY = drawListSection(doc, "Analyst Advisory", buildIocAdvisory(scanResult), cursorY);
  drawListSection(doc, "Recommended Response Actions", getIocRecommendedActions(scanResult), cursorY);

  doc.save(`ioc-scan-report-${formatReportTimestamp()}.pdf`);
}

function getProviderValue(providerKey, providerData) {
  if (!providerData) return "Unavailable";
  if (providerData.error) return providerData.error;
  if (providerData.message) return providerData.message;

  if (providerKey === "virustotal") return providerData.malicious ?? 0;
  if (providerKey === "abuseipdb") return providerData.abuseConfidence ?? 0;
  if (providerKey === "otx") return providerData.summary || `${providerData.pulse_count ?? 0} pulse match(es)`;
  if (providerKey === "malwarebazaar") return providerData.summary || providerData.malware_family || "No data found";
  if (providerKey === "threatfox") return providerData.summary || `${providerData.mapping_count ?? 0} IOC mapping(s)`;
  return "Unavailable";
}

function getProviderRows(scanResult) {
  const support = scanResult?.provider_support || {};

  return [
    {
      key: "virustotal",
      label: support.virustotal?.label || "VirusTotal malicious",
      supported: !!support.virustotal?.supported,
      value: getProviderValue("virustotal", scanResult?.virustotal),
    },
    {
      key: "abuseipdb",
      label: support.abuseipdb?.label || "AbuseIPDB score",
      supported: !!support.abuseipdb?.supported,
      value: getProviderValue("abuseipdb", scanResult?.abuseipdb),
    },
    {
      key: "otx",
      label: support.otx?.label || "OTX hits",
      supported: !!support.otx?.supported,
      value: getProviderValue("otx", scanResult?.otx),
    },
    {
      key: "malwarebazaar",
      label: support.malwarebazaar?.label || "Malware Family",
      supported: !!support.malwarebazaar?.supported,
      value: getProviderValue("malwarebazaar", scanResult?.malwarebazaar),
    },
    {
      key: "threatfox",
      label: support.threatfox?.label || "IOC Mapping",
      supported: !!support.threatfox?.supported,
      value: getProviderValue("threatfox", scanResult?.threatfox),
    },
  ].filter((row) => row.supported);
}

function formatList(values) {
  return values && values.length ? values.join(", ") : "";
}

function parseCsv(text) {
  const rows = [];
  let row = [];
  let value = "";
  let quoted = false;

  for (let i = 0; i < text.length; i += 1) {
    const char = text[i];
    const next = text[i + 1];

    if (char === '"' && quoted && next === '"') {
      value += '"';
      i += 1;
    } else if (char === '"') {
      quoted = !quoted;
    } else if (char === "," && !quoted) {
      row.push(value);
      value = "";
    } else if ((char === "\n" || char === "\r") && !quoted) {
      if (char === "\r" && next === "\n") i += 1;
      row.push(value);
      if (row.some((cell) => cell.trim() !== "")) rows.push(row);
      row = [];
      value = "";
    } else {
      value += char;
    }
  }

  row.push(value);
  if (row.some((cell) => cell.trim() !== "")) rows.push(row);
  if (rows.length < 2) return [];

  const headers = rows[0].map((header) => header.trim());
  return rows.slice(1).map((cells) =>
    headers.reduce((record, header, index) => {
      record[header] = cells[index]?.trim() || "";
      return record;
    }, {})
  );
}

function readField(record, names) {
  const keys = Object.keys(record);
  const target = names.map((name) => name.toLowerCase());
  const key = keys.find((candidate) => target.includes(candidate.toLowerCase()));
  return key ? record[key] : "";
}

function getEventId(record) {
  return readField(record, ["Id", "EventID", "Event Id", "EventIdentifier"]).trim();
}

function getTimestamp(record) {
  return readField(record, ["TimeCreated", "Time Generated", "Date", "Timestamp"]);
}

function getMessage(record) {
  return readField(record, ["Message", "RenderedDescription"]);
}

function extractActor(event) {
  const message = getMessage(event);
  const accountMatch = message.match(/Account Name:\s+([^\r\n]+)/i);
  const workstationMatch = message.match(/Workstation Name:\s+([^\r\n]+)/i);
  const sourceMatch = message.match(/Source Network Address:\s+([^\r\n]+)/i);

  return [
    accountMatch?.[1]?.trim(),
    workstationMatch?.[1]?.trim(),
    sourceMatch?.[1]?.trim(),
    readField(event, ["MachineName", "Computer"]),
  ].find((value) => value && value !== "-" && value.toLowerCase() !== "anonymous logon") || "Unknown";
}

function getMinuteBucket(event) {
  const timestamp = getTimestamp(event);
  return timestamp ? timestamp.slice(0, 16) : "Unknown";
}

function isValidIPv4(candidate) {
  const parts = candidate.split(".");
  return parts.length === 4 && parts.every((part) => {
    const value = Number(part);
    return Number.isInteger(value) && value >= 0 && value <= 255;
  });
}

function getHashType(value) {
  if (value.length === 32) return "md5";
  if (value.length === 40) return "sha1";
  if (value.length === 64) return "sha256";
  return "hash";
}

function normalizeIndicatorValue(value) {
  return value.trim().replace(/[),.;]+$/, "");
}

function addIndicator(store, type, rawValue, source) {
  const value = normalizeIndicatorValue(rawValue);
  if (!value) return;

  const key = `${type}:${value.toLowerCase()}`;
  const current = store.get(key) || { type, value, count: 0, sources: new Set() };
  current.count += 1;
  current.sources.add(source);
  store.set(key, current);
}

function extractIndicators(events) {
  const indicators = new Map();

  events.forEach((event) => {
    const message = getMessage(event);
    if (!message) return;

    const timestamp = getTimestamp(event) || "Unknown time";
    const source = `${timestamp} | Event ${getEventId(event) || "Unknown"}`;

    const urls = message.match(URL_PATTERN) || [];
    urls.forEach((url) => addIndicator(indicators, "url", url, source));

    const emails = message.match(EMAIL_PATTERN) || [];
    emails.forEach((email) => addIndicator(indicators, "email", email, source));

    const hashes = message.match(HASH_PATTERN) || [];
    hashes.forEach((hash) => addIndicator(indicators, getHashType(hash), hash, source));

    const ips = message.match(IPV4_PATTERN) || [];
    ips
      .filter((ip) => isValidIPv4(ip))
      .forEach((ip) => addIndicator(indicators, "ip", ip, source));

    const domains = message.match(DOMAIN_PATTERN) || [];
    domains
      .filter((domain) =>
        !emails.some((email) => email.toLowerCase().endsWith(`@${domain.toLowerCase()}`)) &&
        !urls.some((url) => url.toLowerCase().includes(domain.toLowerCase()))
      )
      .forEach((domain) => addIndicator(indicators, "domain", domain, source));
  });

  return [...indicators.values()]
    .map((indicator) => ({
      ...indicator,
      sources: [...indicator.sources].slice(0, 3),
    }))
    .sort((a, b) => b.count - a.count || a.value.localeCompare(b.value))
    .slice(0, 16);
}

function getRiskLevel(findings) {
  const criticalCount = findings.filter((finding) => finding.severity === "critical").length;
  const highCount = findings.filter((finding) => finding.severity === "high").length;
  const mediumCount = findings.filter((finding) => finding.severity === "medium").length;

  if (criticalCount > 0 || (highCount > 0 && mediumCount >= 2)) {
    return "Critical";
  }
  if (highCount > 0 || mediumCount >= 3) {
    return "High";
  }
  if (mediumCount > 0) {
    return "Medium";
  }
  return "Low";
}

function formatSeverityLabel(severity) {
  if (severity === "info") return "Informational";
  return `${severity.charAt(0).toUpperCase()}${severity.slice(1)} Risk`;
}

function getConfidenceFromScore(score) {
  if (score >= 61) return "high confidence";
  if (score >= 31) return "medium confidence";
  return "low confidence";
}

function getDetectionStatus(analysis, titleFragment, emptyMessage, activeMessage) {
  const match = analysis.findings.find((finding) =>
    finding.title.toLowerCase().includes(titleFragment.toLowerCase())
  );

  if (!analysis.summary.totalEvents) {
    return { severity: "low", message: emptyMessage };
  }

  if (!match) {
    return { severity: "low", message: "No suspicious activity detected. Routine review still recommended." };
  }

  return {
    severity: match.severity === "critical" ? "high" : match.severity,
    message: activeMessage(match),
  };
}

function analyzeEvents(events) {
  const summary = {
    totalEvents: events.length,
    failedLogons: 0,
    successfulLogons: 0,
    lockouts: 0,
    privilegeEvents: 0,
  };
  const eventCounts = {};
  const timeline = {};
  const failedByActorMinute = {};
  const failedByActor = {};
  const lockoutByActor = {};
  const privilegeByActor = {};

  events.forEach((event) => {
    const id = getEventId(event);
    const timestamp = getTimestamp(event);
    const day = timestamp ? timestamp.slice(0, 10) : "Unknown";
    const actor = extractActor(event);

    eventCounts[id || "Unknown"] = (eventCounts[id || "Unknown"] || 0) + 1;
    timeline[day] = (timeline[day] || 0) + 1;

    if (WATCHED_EVENTS.failedLogons.has(id)) {
      summary.failedLogons += 1;
      const key = `${actor}|${getMinuteBucket(event)}`;
      failedByActorMinute[key] = (failedByActorMinute[key] || 0) + 1;
      failedByActor[actor] = (failedByActor[actor] || 0) + 1;
    }
    if (WATCHED_EVENTS.successfulLogons.has(id)) summary.successfulLogons += 1;
    if (WATCHED_EVENTS.lockouts.has(id)) {
      summary.lockouts += 1;
      const key = actor;
      lockoutByActor[key] = (lockoutByActor[key] || 0) + 1;
    }
    if (WATCHED_EVENTS.privilegeEvents.has(id)) {
      summary.privilegeEvents += 1;
      privilegeByActor[actor] = (privilegeByActor[actor] || 0) + 1;
    }
  });

  const findings = [];
  const bruteForce = Object.entries(failedByActorMinute).sort((a, b) => b[1] - a[1])[0];
  const repeatedFailedActor = Object.entries(failedByActor).sort((a, b) => b[1] - a[1])[0];
  const lockoutSpike = Object.entries(lockoutByActor).sort((a, b) => b[1] - a[1])[0];
  const privilegeSpike = Object.entries(privilegeByActor).sort((a, b) => b[1] - a[1])[0];
  const failedRatio = summary.successfulLogons
    ? summary.failedLogons / Math.max(summary.successfulLogons, 1)
    : summary.failedLogons > 0 ? summary.failedLogons : 0;
  const topEvents = Object.entries(eventCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([id, count]) => ({ id, count }));
  const highRiskEventIds = topEvents.filter((item) => HIGH_RISK_EVENT_IDS.has(item.id));

  const pushFinding = (severity, title, evidence, recommendation, category, confidence) => {
    findings.push({ severity, title, evidence, recommendation, category, confidence });
  };

  if (bruteForce && bruteForce[1] >= 5) {
    pushFinding(
      bruteForce[1] >= 8 ? "critical" : "high",
      "Brute force pattern indicators",
      `${bruteForce[1]} failed logon events were observed for ${bruteForce[0].split("|")[0]} within a short time window.`,
      "Review the affected account, source system, and surrounding timestamps for possible password spraying or brute force activity.",
      "Brute Force Indicators",
      bruteForce[1] >= 8 ? "high confidence" : "medium confidence"
    );
  }
  if (repeatedFailedActor && repeatedFailedActor[1] >= 4) {
    pushFinding(
      "medium",
      "Repeated failed authentication activity",
      `${repeatedFailedActor[1]} failed logon events were linked to ${repeatedFailedActor[0]}.`,
      "Validate whether the failed authentication activity was expected and confirm the originating host or source network path.",
      "Authentication Trends",
      "medium confidence"
    );
  }
  if (lockoutSpike && lockoutSpike[1] >= 3) {
    pushFinding(
      "high",
      "Account lockout spike",
      `${lockoutSpike[1]} lockout events were observed for ${lockoutSpike[0]}.`,
      "Validate lockout causes, review password reset activity, and correlate the timeline with failed logon bursts.",
      "Lockout Activity",
      "medium confidence"
    );
  } else if (summary.lockouts > 0) {
    pushFinding(
      "medium",
      "Account lockout activity detected",
      `${summary.lockouts} account lockout events were observed in the uploaded dataset.`,
      "Review affected users and source systems to determine whether the lockouts map to expected password changes or suspicious authentication attempts.",
      "Lockout Activity",
      "low confidence"
    );
  }
  if (summary.privilegeEvents > 0) {
    pushFinding(
      summary.privilegeEvents >= 5 ? "high" : "medium",
      "Privileged activity requires review",
      `${summary.privilegeEvents} special privilege events were observed${privilegeSpike ? `, with ${privilegeSpike[1]} linked to ${privilegeSpike[0]}` : ""}.`,
      "Review privileged logons and confirm whether the activity was authorized maintenance, administration, or an unusual access pattern.",
      "Privilege Activity",
      summary.privilegeEvents >= 5 ? "medium confidence" : "low confidence"
    );
  }
  if (failedRatio >= 3 && summary.failedLogons >= 6) {
    pushFinding(
      failedRatio >= 6 ? "high" : "medium",
      "Unusual authentication imbalance",
      `Failed logons are ${failedRatio.toFixed(1)}x successful logons in this dataset.`,
      "Correlate suspicious timestamps with endpoint or network telemetry to determine whether the imbalance reflects misconfiguration, automation failure, or possible hostile activity.",
      "Authentication Trends",
      failedRatio >= 6 ? "medium confidence" : "low confidence"
    );
  }
  if (highRiskEventIds.length) {
    pushFinding(
      highRiskEventIds.some((item) => item.count >= 5) ? "medium" : "info",
      "High-risk event IDs observed",
      highRiskEventIds.map((item) => `Event ${item.id}: ${item.count}`).join(" | "),
      "Review the highest-frequency event IDs first and compare them with expected administrative or authentication behavior.",
      "High-Risk Event IDs",
      "low confidence"
    );
  }
  if (!findings.length && events.length) {
    pushFinding(
      "info",
      "No major suspicious pattern triggered",
      "The current findings engine did not observe a high-signal combination of failed logons, lockout spikes, or unusual privilege activity.",
      "Maintain normal log review procedures and confirm that the exported date range covers the activity window of interest.",
      "Authentication Trends",
      "low confidence"
    );
  }

  const timelineRows = Object.entries(timeline)
    .sort(([a], [b]) => a.localeCompare(b))
    .slice(-8)
    .map(([day, count]) => ({ day, count }));

  const riskLevel = getRiskLevel(findings);
  const findingsSummary = [
    {
      title: "Brute Force Indicators",
      severity: bruteForce && bruteForce[1] >= 5 ? (bruteForce[1] >= 8 ? "critical" : "high") : "low",
      detail: bruteForce && bruteForce[1] >= 5
        ? `${bruteForce[1]} failed attempts for ${bruteForce[0].split("|")[0]}.`
        : "No concentrated brute force pattern exceeded the alert threshold.",
    },
    {
      title: "Privilege Activity",
      severity: summary.privilegeEvents >= 5 ? "high" : summary.privilegeEvents > 0 ? "medium" : "low",
      detail: summary.privilegeEvents
        ? `${summary.privilegeEvents} privileged events detected.`
        : "No privileged activity was observed in the reviewed dataset.",
    },
    {
      title: "Lockout Activity",
      severity: summary.lockouts >= 3 ? "high" : summary.lockouts > 0 ? "medium" : "low",
      detail: summary.lockouts
        ? `${summary.lockouts} account lockout events require verification.`
        : "No account lockout spike was detected.",
    },
    {
      title: "Authentication Trends",
      severity: failedRatio >= 6 ? "high" : failedRatio >= 3 ? "medium" : "low",
      detail: summary.failedLogons
        ? `${summary.failedLogons} failed vs ${summary.successfulLogons} successful logons.`
        : "Authentication activity remained balanced in the imported rows.",
    },
    {
      title: "High-Risk Event IDs",
      severity: highRiskEventIds.length ? "medium" : "low",
      detail: highRiskEventIds.length
        ? highRiskEventIds.map((item) => `${item.id} (${item.count})`).join(", ")
        : "No monitored high-risk event IDs were dominant in the top event set.",
    },
  ];

  const recommendations = [...new Set(findings.map((finding) => finding.recommendation))];
  if (events.length && !recommendations.length) {
    recommendations.push(
      "Confirm whether the reviewed time window and exported host scope are sufficient before finalizing the incident narrative."
    );
  }
  if (events.length) {
    recommendations.push(
      "These findings should be validated against endpoint, identity, and network telemetry before any final incident conclusion is reached."
    );
  }

  const extractedIndicators = extractIndicators(events);
  const highRiskObserved = findings.some((finding) => ["critical", "high"].includes(finding.severity));
  const executiveSummary = events.length
    ? [
      `${summary.totalEvents} event(s) were analyzed across the imported Windows Security log dataset.`,
      highRiskObserved
        ? `${findings.filter((finding) => ["critical", "high"].includes(finding.severity)).length} high-risk indicator(s) were observed and should be prioritized for analyst review.`
        : "No high-risk indicator pattern reached the current escalation threshold.",
      findings.length
        ? `${findings.length} investigation finding(s) were generated from authentication, privilege, and lockout activity patterns.`
        : "No structured findings were generated by the current ruleset.",
      highRiskObserved || riskLevel === "Medium"
        ? "Analyst review is recommended before closing the investigation."
        : "Routine validation is still recommended to confirm the observed activity is authorized.",
    ]
    : [];

  return {
    summary,
    findings,
    findingsSummary,
    topEvents,
    timelineRows,
    extractedIndicators,
    recommendations,
    executiveSummary,
    riskLevel,
  };
}

function App() {
  const [activeTab, setActiveTab] = useState("scan");
  const [ioc, setIoc] = useState("");
  const [scanResult, setScanResult] = useState(null);
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgressMessage, setScanProgressMessage] = useState("Scanning indicator...");
  const [scanProgressDetail, setScanProgressDetail] = useState("Checking threat intelligence providers...");
  const [scanError, setScanError] = useState("");
  const [fileName, setFileName] = useState("");
  const [events, setEvents] = useState([]);
  const [uploadError, setUploadError] = useState("");
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [news, setNews] = useState([]);
  const [selectedIndicator, setSelectedIndicator] = useState(null);
  const [hubResult, setHubResult] = useState(null);
  const [hubLoading, setHubLoading] = useState(false);
  const [hubError, setHubError] = useState("");
  const [scansToday, setScansToday] = useState(0);
  const [liveIndicators, setLiveIndicators] = useState([]);
  const [iocFeedSources, setIocFeedSources] = useState([]);
  const [iocFeedLoading, setIocFeedLoading] = useState(true);

  const analysis = useMemo(() => analyzeEvents(events), [events]);
  const analysisResult = analysis.summary.totalEvents ? analysis : null;
  const bruteForceStatus = useMemo(
    () =>
      getDetectionStatus(
        analysis,
        "Brute force",
        "Upload a CSV to evaluate repeated failed logons and possible brute force behavior.",
        () => "Possible brute force pattern observed. Review recommended."
      ),
    [analysis]
  );
  const lockoutStatus = useMemo(
    () =>
      getDetectionStatus(
        analysis,
        "lockout",
        "Upload a CSV to review account lockout frequency and spike conditions.",
        () => "Lockout activity observed. Review recommended."
      ),
    [analysis]
  );
  const privilegeStatus = useMemo(
    () =>
      getDetectionStatus(
        analysis,
        "Privileged activity",
        "Upload a CSV to review privileged logons and special rights assignments.",
        () => "Privileged activity requires review."
      ),
    [analysis]
  );
  const feedSources = useMemo(
    () =>
      new Set(
        news
          .map((item) => item.source)
          .filter((source) => source && source !== "Notice")
      ).size,
    [news]
  );
  const lastVerdict = scanResult?.verdict || "Awaiting scan";

  useEffect(() => {
    getNews()
      .then((data) => setNews(data))
      .catch(() =>
        setNews([{ title: "Feed temporarily unavailable", link: "#", source: "Notice" }])
      );
  }, []);

  useEffect(() => {
    getIOCFeed()
      .then((data) => {
        setLiveIndicators(data.items || []);
        setIocFeedSources(data.sources || []);
      })
      .catch(() => {
        setLiveIndicators([]);
        setIocFeedSources([
          { name: "Threat Intel Feed", status: "error", message: "IOC sources temporarily unavailable" },
        ]);
      })
      .finally(() => setIocFeedLoading(false));
  }, []);

  useEffect(() => {
    if (!events.length) {
      setIsAnalyzing(false);
      return undefined;
    }

    const timer = window.setTimeout(() => setIsAnalyzing(false), 650);
    return () => window.clearTimeout(timer);
  }, [events]);

  const performScan = async (target) => {
    if (!target.trim()) return;
    setIsScanning(true);
    setScanProgressMessage("Scanning indicator...");
    setScanProgressDetail("Checking VirusTotal, AbuseIPDB, OTX, MalwareBazaar, ThreatFox...");
    setScanError("");
    setScanResult(null);

    const progressTimer = window.setTimeout(() => {
      setScanProgressMessage("Scanning indicator...");
      setScanProgressDetail("Checking VirusTotal, AbuseIPDB, OTX, MalwareBazaar, ThreatFox...");
    }, 450);

    try {
      const data = await checkIOC(target.trim());
      setScanResult(data);
      setScansToday((value) => value + 1);
    } catch (err) {
      setScanError(err.detail?.error || err.message || "Scan failed.");
    } finally {
      window.clearTimeout(progressTimer);
      setIsScanning(false);
    }
  };

  const handleScan = async () => performScan(ioc);

  const handleAnalyzeIndicator = async (value) => {
    setActiveTab("scan");
    setIoc(value);
    await performScan(value);
  };

  const handleCsvUpload = async (event) => {
    const file = event.target.files?.[0];
    setUploadError("");
    setSelectedIndicator(null);
    setHubResult(null);
    setHubError("");
    setIsAnalyzing(true);
    if (!file) return;
    if (!file.name.toLowerCase().endsWith(".csv")) {
      setFileName("");
      setEvents([]);
      setUploadError("Upload a CSV exported from the Windows Security log script.");
      setIsAnalyzing(false);
      return;
    }

    const parsed = parseCsv(await file.text());
    if (!parsed.length) {
      setFileName(file.name);
      setEvents([]);
      setUploadError("No readable event rows were found in this CSV.");
      setIsAnalyzing(false);
      return;
    }

    setFileName(file.name);
    setEvents(parsed);
  };

  const handleOpenAnalyzerHub = async (indicator) => {
    setSelectedIndicator(indicator);
    setHubLoading(true);
    setHubError("");
    setHubResult(null);

    try {
      const data = await checkIOC(indicator.value);
      setHubResult(data);
    } catch (err) {
      setHubError(err.detail?.error || err.message || "Analyzer Hub could not enrich this indicator.");
    } finally {
      setHubLoading(false);
    }
  };

  return (
    <div className="app-shell">
      <header className="app-header">
        <div className="header-flex">
          <img src="/logo.png" alt="Threat Intel Aggregator" className="app-logo" />
          <div className="brand-copy">
            <p className="eyebrow">Mini SOC + DFIR Dashboard</p>
            <h1 className="brand-title">Threat Intel Aggregator</h1>
            <h2 className="brand-subtitle">
              Threat scanning with embedded intelligence and Windows Security log analysis.
            </h2>
          </div>
        </div>

        <nav className="tabs" aria-label="Threat Intel Aggregator modules">
          {TABS.map((tab) => (
            <button
              className={activeTab === tab.id ? "tab active" : "tab"}
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              type="button"
            >
              <span className="tab-label-desktop">{tab.label}</span>
              <span className="tab-label-mobile">{tab.shortLabel || tab.label}</span>
            </button>
          ))}
          <div className="status-pill live-pill" aria-label="System live status">
            <span className="status-dot" />
            <strong>LIVE</strong>
          </div>
        </nav>
      </header>

      <TopStatsBar
        feedSources={feedSources}
        lastVerdict={lastVerdict}
        scansToday={scansToday}
      />

      <main className="main-content">
        {activeTab === "scan" && (
          <>
            <section className="panel logs-hero-panel">
              <p className="eyebrow">Threat Scan Module</p>
              <h1>Analyze IP, Domain, URL, Hash, or Email</h1>
              <p className="section-copy">
                Submit an indicator to generate a verdict, severity score, and provider-backed context when available.
              </p>

              <div className="terminal">
                <div className="input-row">
                  <input
                    className="input"
                    onChange={(event) => setIoc(event.target.value)}
                    placeholder="8.8.8.8, example.com, https://site, hash, or user@example.com"
                    type="text"
                    value={ioc}
                  />
                  <button className="btn" disabled={isScanning} onClick={handleScan} type="button">
                    {isScanning ? "Scanning..." : "Scan"}
                  </button>
                </div>
              </div>

              {isScanning && (
                <div className="loading-box scan-loading-panel" aria-live="polite">
                  <span className="loading-spinner" aria-hidden="true" />
                  <div>
                    <strong>{scanProgressMessage}</strong>
                    <p>{scanProgressDetail}</p>
                  </div>
                </div>
              )}

              {scanError && <p className="status-message status-warning">{scanError}</p>}

              {scanResult && !isScanning && (
                <div className="scan-result">
                  <div className={`verdict-card ${scanResult.verdict?.toLowerCase()}`}>
                    <span>Verdict</span>
                    <strong>{scanResult.verdict || scanResult.combined_risk}</strong>
                    <span className={`severity-badge ${scanResult.severity?.toLowerCase()}`}>
                      {scanResult.severity?.toUpperCase() || "LOW"}
                    </span>
                    <div className="score-bar" aria-label={`Score ${scanResult.score || 0} out of 100`}>
                      <span style={{ width: `${Math.min(scanResult.score || 0, 100)}%` }} />
                    </div>
                    <p>Severity: {scanResult.severity || scanResult.combined_risk}</p>
                    <p>Score: {scanResult.score ?? "N/A"}</p>
                    <p>Confidence: {scanResult.confidence ?? 0}%</p>
                  </div>

                  <div className="result-card">
                    <h2>Provider Results</h2>
                    <div className="event-row"><span>Indicator Type</span><strong>{scanResult.type}</strong></div>
                    {getProviderRows(scanResult).map((row) => (
                      <div className="event-row" key={row.key}>
                        <span>{row.label}</span>
                        <strong>{row.value}</strong>
                      </div>
                    ))}
                    {scanResult.highlighted_intelligence?.malware_family && (
                      <div className="event-row">
                        <span>Malware Family</span>
                        <strong>{scanResult.highlighted_intelligence.malware_family}</strong>
                      </div>
                    )}
                    {scanResult.highlighted_intelligence?.tags?.length > 0 && (
                      <div className="event-row">
                        <span>Tags</span>
                        <strong>{formatList(scanResult.highlighted_intelligence.tags)}</strong>
                      </div>
                    )}
                    {scanResult.highlighted_intelligence?.threat_types?.length > 0 && (
                      <div className="event-row">
                        <span>Threat Type</span>
                        <strong>{formatList(scanResult.highlighted_intelligence.threat_types)}</strong>
                      </div>
                    )}
                    <p className="provider-note">Provider availability depends on IOC type.</p>
                    {!!scanResult.provider_breakdown?.length && (
                      <div className="provider-breakdown">
                        <h3>Provider Contribution Breakdown</h3>
                        {scanResult.provider_breakdown.map((item) => (
                          <div className="event-row" key={item.provider}>
                            <span>{item.provider}</span>
                            <strong>{item.score}</strong>
                          </div>
                        ))}
                      </div>
                    )}
                    {!!scanResult.explanations?.length && (
                      <div className="provider-breakdown">
                        <h3>Why This Verdict</h3>
                        {scanResult.explanations.map((item) => (
                          <p className="provider-note explanation-item" key={item}>{item}</p>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              )}

              {scanResult && !isScanning && (
                <div className="report-actions report-actions-inline">
                  <button className="btn secondary" onClick={() => exportIocPdf(scanResult)} type="button">
                    Download PDF
                  </button>
                  <button className="btn secondary" onClick={() => exportIocCsv(scanResult)} type="button">
                    Download CSV
                  </button>
                </div>
              )}

              {!isScanning && !scanResult && <p className="report-note">Run a scan to enable PDF and CSV exports.</p>}
            </section>

            <section className="side full-width-panel">
              <h1>Risk Indicators</h1>
              <div className="focus-list">
                <span>Malicious or suspicious provider detections</span>
                <span>High AbuseIPDB confidence for IP addresses</span>
                <span>OTX pulse matches for IPs and domains</span>
                <span>Email indicators are format-validated and prepared for enrichment</span>
              </div>
            </section>

            <section className="side full-width-panel">
              <div className="intel-card full-width-intel-card">
                <h1>Threat Intel Feed</h1>
                <div className="compact-feed">
                  <div className={news.length > 3 ? "compact-feed-track live" : "compact-feed-track"}>
                    {news.map((item, index) => (
                      <a className="feed-item compact" href={item.link} key={`${item.title}-${index}`} rel="noreferrer" target="_blank">
                        <span>{item.source || "Notice"}</span>
                        <strong>{item.title || "Feed temporarily unavailable"}</strong>
                        <small>{item.published || item.time || "Latest"}</small>
                      </a>
                    ))}
                    {news.length > 3 && news.map((item, index) => (
                      <a className="feed-item compact ghost" href={item.link} key={`loop-${item.title}-${index}`} rel="noreferrer" target="_blank">
                        <span>{item.source || "Notice"}</span>
                        <strong>{item.title || "Feed temporarily unavailable"}</strong>
                        <small>{item.published || item.time || "Latest"}</small>
                      </a>
                    ))}
                  </div>
                </div>
              </div>
            </section>

            <section className="support-panels scan-support-panels" aria-label="Threat intel quick reference">
              <IOCCheatSheetPanel
                extractedIndicators={analysis.extractedIndicators}
                liveIndicators={liveIndicators}
                loading={iocFeedLoading}
                onAnalyze={handleAnalyzeIndicator}
                sourceStatus={iocFeedSources}
              />
              <MitreAttackPanel />
            </section>
          </>
        )}

        {activeTab === "logs" && (
          <>
            <section className="panel logs-hero-panel">
              <p className="eyebrow">DFIR Log Analyzer Module</p>
              <h1>Windows Security Log CSV Analysis</h1>
              <p className="hero-copy">
                Run the local PowerShell exporter with a custom date range, then import the generated CSV for audit observations,
                suspicious activity, and risk indicators.
              </p>
              <div className="command-panel">
                <span>Example local export command</span>
                <code>{SAMPLE_EXPORT_COMMAND}</code>
              </div>
            </section>

            <section className="logs-top-grid">
              <div className="logs-left-stack">
                <section className="panel import-panel logs-upload-panel">
                  <div>
                    <p className="eyebrow">CSV Import</p>
                    <h1>Upload Exported Security Events</h1>
                    <p className="section-copy">
                      Expected CSV fields include TimeCreated, Id, LevelDisplayName, and Message.
                    </p>
                  </div>
                  <label className="upload-zone">
                    <input accept=".csv,text/csv" onChange={handleCsvUpload} type="file" />
                    <span>{fileName || "Choose Windows Security log CSV"}</span>
                    <strong>Import CSV</strong>
                  </label>
                  {uploadError && <p className="status-message status-warning">{uploadError}</p>}
                  {!uploadError && fileName && (
                    <p className="status-message">Loaded {events.length} event row(s) from {fileName}.</p>
                  )}

                  <div className="import-workflow">
                    <div>
                      <p className="eyebrow">Audit Workflow</p>
                      <h2>Review Flow</h2>
                    </div>
                    <div className="workflow-list">
                      {WORKFLOW_STEPS.map((step, index) => (
                        <div className="workflow-step" key={step}>
                          <span>{String(index + 1).padStart(2, "0")}</span>
                          <p>{step}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                </section>

                <section className="panel analysis-panel logs-top-findings">
                  <div className="section-heading">
                    <div>
                      <p className="eyebrow">Analysis Dashboard</p>
                      <h1>Security Findings</h1>
                    </div>
                    <span className="dataset-pill">
                      {events.length ? `${events.length} events loaded` : "Awaiting CSV"}
                    </span>
                  </div>

                  {isAnalyzing && (
                    <div className="loading-box dfir-loading-panel" aria-live="polite">
                      <span className="loading-spinner" aria-hidden="true" />
                      <div>
                        <strong>Logs scanning in progress...</strong>
                        <p>Analyzing Windows Security Events...</p>
                      </div>
                    </div>
                  )}

                  {!isAnalyzing && (
                    <div className="metric-grid">
                      <div className="metric-card"><span>Total Events</span><strong>{analysis.summary.totalEvents}</strong></div>
                      <div className="metric-card warning"><span>Failed Logons</span><strong>{analysis.summary.failedLogons}</strong></div>
                      <div className="metric-card"><span>Successful Logons</span><strong>{analysis.summary.successfulLogons}</strong></div>
                      <div className="metric-card warning"><span>Account Lockouts</span><strong>{analysis.summary.lockouts}</strong></div>
                      <div className="metric-card"><span>Privilege Events</span><strong>{analysis.summary.privilegeEvents}</strong></div>
                    </div>
                  )}
                </section>
              </div>

              <section className="side insights-panel">
                <p className="eyebrow">DFIR Context</p>
                <h1>Investigation Insights</h1>

                {!events.length ? (
                  <>
                    <p className="section-copy">
                      This module helps review uploaded Windows Security logs for authentication anomalies,
                      lockout patterns, privileged access activity, and investigation leads that may require analyst follow-up.
                    </p>

                    <div className="insight-list">
                      <div className="insight-card">
                        <strong>4625</strong>
                        <span>Failed Logon</span>
                      </div>
                      <div className="insight-card">
                        <strong>4624</strong>
                        <span>Successful Logon</span>
                      </div>
                      <div className="insight-card">
                        <strong>4740</strong>
                        <span>Account Lockout</span>
                      </div>
                      <div className="insight-card">
                        <strong>4672</strong>
                        <span>Privileged Logon</span>
                      </div>
                    </div>

                    <div className="guidance-stack">
                      <div className="guidance-item">
                        <strong>Repeated failed logons</strong>
                        <p>May indicate brute force or password spraying when clustered around the same user or host.</p>
                      </div>
                      <div className="guidance-item">
                        <strong>Lockout spikes</strong>
                        <p>Can reflect a possible attack or widespread credential mismatch and should be correlated with source systems.</p>
                      </div>
                      <div className="guidance-item">
                        <strong>Privileged events</strong>
                        <p>Require review to confirm the access was expected and authorized for the time window under investigation.</p>
                      </div>
                    </div>
                  </>
                ) : (
                  <>
                    <p className="section-copy">
                      Detection Summary updates after CSV import and reflects the current findings engine output for this dataset.
                    </p>

                    <div className="guidance-stack">
                      <div className={`guidance-item status-card ${bruteForceStatus.severity}`}>
                        <strong>Brute force detection</strong>
                        <p>{bruteForceStatus.message}</p>
                      </div>
                      <div className={`guidance-item status-card ${lockoutStatus.severity}`}>
                        <strong>Lockout activity</strong>
                        <p>{lockoutStatus.message}</p>
                      </div>
                      <div className={`guidance-item status-card ${privilegeStatus.severity}`}>
                        <strong>Privilege activity</strong>
                        <p>{privilegeStatus.message}</p>
                      </div>
                    </div>
                  </>
                )}
              </section>
            </section>

            <section className="logs-bottom-stack">
              <div className="section-heading">
                <div>
                  <p className="eyebrow">Expanded Review</p>
                  <h1>Executive Summary and Findings</h1>
                </div>
              </div>

              <div className="report-grid">
                <div className="result-card">
                  <h2>Executive Summary</h2>
                  {!isAnalyzing && analysis.executiveSummary.length ? (
                    <div className="summary-list">
                      {analysis.executiveSummary.map((item) => (
                        <p key={item}>{item}</p>
                      ))}
                    </div>
                  ) : (
                    <p>{isAnalyzing ? "Analyzing Windows Security Events..." : "Upload a CSV to generate an executive summary for the reviewed log set."}</p>
                  )}
                </div>

                <div className={`result-card risk-panel ${analysis.riskLevel.toLowerCase()}`}>
                  <h2>Risk Assessment</h2>
                  <div className="risk-pill-wrap">
                    <span className={`severity-badge ${analysis.riskLevel.toLowerCase()}`}>
                      {analysis.riskLevel}
                    </span>
                  </div>
                  <p>
                    {analysis.summary.totalEvents
                      ? analysis.riskLevel === "Critical"
                        ? "Multiple high-signal event patterns were observed. Escalated validation by an incident responder is recommended."
                        : analysis.riskLevel === "High"
                          ? "Suspicious activity observed. Prioritize analyst review of authentication, lockout, and privilege timelines."
                          : analysis.riskLevel === "Medium"
                            ? "Moderate risk indicators were observed and should be validated against host and identity context."
                            : "No strong escalation pattern was observed, but the dataset should still be reviewed for business context."
                      : "Risk status is generated after a CSV is uploaded."}
                  </p>
                </div>
              </div>

              <div className="summary-card-grid">
                <div className="subsection-header">
                  <p className="eyebrow">Findings Summary</p>
                  <h2>Investigation Pattern Overview</h2>
                </div>
                {analysis.findingsSummary.map((item) => (
                  <div className={`summary-card ${item.severity}`} key={item.title}>
                    <span className={`severity-badge ${item.severity}`}>{item.title}</span>
                    <p>{item.detail}</p>
                  </div>
                ))}
              </div>

              <div className="finding-grid">
                <div className="result-card">
                  <h2>Findings</h2>
                  {analysis.findings.length ? analysis.findings.map((finding) => (
                    <div className={`finding ${finding.severity}`} key={finding.title}>
                      <span className={`severity-badge ${finding.severity}`}>
                        {formatSeverityLabel(finding.severity)}
                      </span>
                      <strong>{finding.title}</strong>
                      <p>{finding.evidence}</p>
                      <small>{finding.confidence}</small>
                      <p>{finding.recommendation}</p>
                    </div>
                  )) : <p>Import a CSV to generate security findings.</p>}
                </div>
                <div className="result-card">
                  <h2>High-Frequency Event IDs</h2>
                  {!isAnalyzing && analysis.topEvents.length ? analysis.topEvents.map((item) => (
                    <div className="event-row" key={item.id}>
                      <span>Event {item.id}</span>
                      <strong>{item.count}</strong>
                    </div>
                  )) : <p>{isAnalyzing ? "Analyzing Windows Security Events..." : "No event distribution available yet."}</p>}
                </div>
                <div className="result-card timeline-card">
                  <h2>Timeline Summary</h2>
                  {!isAnalyzing && analysis.timelineRows.length ? analysis.timelineRows.map((item) => (
                    <div className="event-row" key={item.day}>
                      <span>{item.day}</span>
                      <strong>{item.count}</strong>
                    </div>
                  )) : <p>{isAnalyzing ? "Logs scanning in progress..." : "Upload a CSV to populate event activity by day."}</p>}
                </div>
              </div>

              {analysisResult && !isAnalyzing && (
                <div className="report-actions report-actions-inline">
                  <button className="btn secondary" onClick={() => exportDfirPdf(analysisResult)} type="button">
                    Download PDF
                  </button>
                  <button className="btn secondary" onClick={() => exportDfirCsv(analysisResult)} type="button">
                    Download CSV
                  </button>
                </div>
              )}

              <div className="enrichment-grid">
                <div className="result-card">
                  <div className="section-heading compact">
                    <div>
                      <p className="eyebrow">Threat Enrichment</p>
                      <h2>Extracted Indicators</h2>
                    </div>
                    <span className="dataset-pill">
                      {analysis.extractedIndicators.length
                        ? `${analysis.extractedIndicators.length} indicators`
                        : "No indicators"}
                    </span>
                  </div>

                  {analysis.extractedIndicators.length ? (
                    <div className="indicator-list">
                      {analysis.extractedIndicators.map((indicator) => (
                        <div className="indicator-card" key={`${indicator.type}-${indicator.value}`}>
                          <div className="indicator-meta">
                            <span className="indicator-type">{indicator.type}</span>
                            <strong>{indicator.value}</strong>
                            <small>{indicator.count} observation(s)</small>
                          </div>
                          <button
                            className="btn secondary"
                            onClick={() => handleOpenAnalyzerHub(indicator)}
                            type="button"
                          >
                            Send to Analyzer Hub
                          </button>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p>No extractable IPs, URLs, domains, hashes, or emails were detected in the current log messages.</p>
                  )}
                </div>

                <div className="result-card">
                  <div className="section-heading compact">
                    <div>
                      <p className="eyebrow">Analyzer Hub</p>
                      <h2>Indicator Review</h2>
                    </div>
                    <span className="dataset-pill">
                      {selectedIndicator ? selectedIndicator.type : "Awaiting selection"}
                    </span>
                  </div>

                  {!selectedIndicator && (
                    <p>Select an extracted indicator to open it in the Analyzer Hub and review enrichment results.</p>
                  )}

                  {selectedIndicator && (
                    <div className="hub-stack">
                      <div className="indicator-meta selected">
                        <span className="indicator-type">{selectedIndicator.type}</span>
                        <strong>{selectedIndicator.value}</strong>
                        <small>
                          Observed {selectedIndicator.count} time(s). Requires analyst validation before any final conclusion.
                        </small>
                      </div>

                      {hubLoading && <p className="status-message">Analyzer Hub is enriching the selected indicator.</p>}
                      {hubError && <p className="status-message status-warning">{hubError}</p>}

                      {hubResult && (
                        <div className="hub-result">
                          <div className={`verdict-card ${hubResult.verdict?.toLowerCase()}`}>
                            <span>Hub Verdict</span>
                            <strong>{hubResult.verdict}</strong>
                            <div className="score-bar" aria-label={`Score ${hubResult.score || 0} out of 100`}>
                              <span style={{ width: `${Math.min(hubResult.score || 0, 100)}%` }} />
                            </div>
                            <p>Severity: {hubResult.severity}</p>
                            <p>Score: {hubResult.score ?? "N/A"}</p>
                          </div>

                          <div className="detail-panel">
                            <h2>Enrichment Summary</h2>
                            <div className="event-row"><span>Indicator Type</span><strong>{hubResult.type}</strong></div>
                            <div className="event-row"><span>VirusTotal malicious</span><strong>{hubResult.virustotal?.malicious ?? "N/A"}</strong></div>
                            <div className="event-row"><span>AbuseIPDB score</span><strong>{hubResult.abuseipdb?.abuseConfidence ?? "N/A"}</strong></div>
                            <div className="event-row"><span>OTX hits</span><strong>{hubResult.otx?.pulse_count ?? "N/A"}</strong></div>
                          </div>

                          <div className="detail-panel">
                            <h2>Analyst Guidance</h2>
                            <p>
                              Enrichment confidence: {getConfidenceFromScore(hubResult.score || 0)} based on the current
                              provider-backed score and available supporting signals.
                            </p>
                            <p>
                              Suspicious indicators found in exported logs should be correlated with authentication timelines,
                              endpoint telemetry, and change activity before being treated as confirmed malicious activity.
                            </p>
                            <p>
                              Possible malicious activity may be present, but the confidence level should be validated by a
                              senior analyst or incident responder.
                            </p>
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>

              <div className="report-grid">
                <div className="result-card">
                  <h2>Recommendation Section</h2>
                  {analysis.recommendations.length ? (
                    <div className="recommendation-list">
                      {analysis.recommendations.map((item) => (
                        <p key={item}>{item}</p>
                      ))}
                    </div>
                  ) : (
                    <p>Recommendations will appear after event findings are generated.</p>
                  )}
                </div>

                <div className="result-card review-note">
                  <h2>Senior Review Note</h2>
                    <p>
                      These findings should be reviewed and validated by a senior analyst before final incident conclusion.
                    </p>
                  </div>
              </div>
            </section>
          </>
        )}
      </main>

      <footer className="footer">
        <span className="footer-copy">2026 All Rights Reserved | Threat Intel Aggregator by Omsai Dagwar</span>
        <div className="footer-status-group" aria-label="System footer status">
          {["SYS", "NET", "DB"].map((item) => (
            <span className="status-pill footer-status-pill" key={item}>
              <span className="status-dot" />
              <strong>{item}</strong>
            </span>
          ))}
        </div>
      </footer>
    </div>
  );
}

export default App;
