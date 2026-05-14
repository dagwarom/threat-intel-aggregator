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
const INDUSTRY_OPTIONS = ["Banking", "Aviation", "Healthcare", "Logistics", "Manufacturing"];
const COUNTRY_OPTIONS = ["India", "United States", "United Kingdom", "European Union", "Singapore", "UAE", "Global / Other"];
const COMPLIANCE_OPTIONS = [
  { value: "country", label: "Use country-specific compliance" },
  { value: "global", label: "Use global compliance baseline" },
  { value: "both", label: "Use both country-specific and global compliance" },
];
const FINAL_VERDICT_OPTIONS = [
  "Likely Compromise Detected",
  "Suspicious Activity Observed",
  "No High-Confidence Compromise Detected",
  "Insufficient Evidence for Final Determination",
];
const DEFAULT_ASSESSMENT_PROFILE = {
  clientCompanyName: "",
  analystName: "",
  assessmentDate: new Date().toISOString().slice(0, 10),
  industry: "Banking",
  country: "India",
  complianceMode: "both",
};
const DEFAULT_INVESTIGATION_NOTES = {
  investigationSummary: "",
  analystObservations: "",
  scopeLimitation: "",
  finalVerdict: "Insufficient Evidence for Final Determination",
  recommendedNextSteps: "",
};
const GLOBAL_FRAMEWORKS = [
  "ISO/IEC 27001",
  "NIST Cybersecurity Framework",
  "CIS Controls",
  "MITRE ATT&CK",
  "GDPR where data privacy applies",
];
const INDUSTRY_FRAMEWORKS = {
  Banking: {
    global: ["PCI DSS", "SWIFT CSP"],
    countries: {
      India: ["RBI Cyber Security Framework", "DPDP Act", "CERT-In Directions 2022"],
      "United States": ["FFIEC", "PCI DSS"],
    },
  },
  Healthcare: {
    global: ["ISO 27799"],
    countries: {
      India: ["DPDP Act", "DISHA / DPDP Act context", "CERT-In Directions 2022"],
      "United States": ["HIPAA"],
      "European Union": ["GDPR"],
    },
  },
  Aviation: {
    global: ["ICAO Cybersecurity Guidance", "IATA Security Standards"],
    countries: {},
  },
  Logistics: {
    global: ["Supply chain security controls", "GDPR / DPDP where customer data applies"],
    countries: {},
  },
  Manufacturing: {
    global: ["IEC 62443", "MITRE ATT&CK for ICS where applicable"],
    countries: {},
  },
};
const COUNTRY_FRAMEWORKS = {
  India: [
    "DPDP Act",
    "Indian IT Act 2000",
    "CERT-In Directions 2022",
    "SEBI Cybersecurity & Cyber Resilience Framework where applicable",
    "IRDAI Cybersecurity Guidelines for insurance-related environments",
    "NCIIPC guidance for critical infrastructure where applicable",
  ],
  "United States": ["NIST CSF", "Federal / sector-specific cyber reporting obligations"],
  "United Kingdom": ["UK GDPR", "NCSC incident handling guidance"],
  "European Union": ["GDPR", "NIS2 / regional cyber resilience obligations"],
  Singapore: ["Cybersecurity Act of Singapore", "PDPA"],
  UAE: ["UAE Information Assurance Standards", "UAE PDPL"],
  "Global / Other": [],
};
const INITIAL_TIMELINE_VISIBLE = 10;
const TIMELINE_PAGE_SIZE = 10;
const INITIAL_FINDINGS_VISIBLE = 4;
const INITIAL_EVENT_GROUP_VISIBLE = 3;
const IMPORTANT_EVENT_IDS = {
  "4624": "Successful Logon",
  "4625": "Failed Logon",
  "4634": "Logoff",
  "4648": "Explicit Credential Use",
  "4672": "Special Privileges Assigned",
  "4688": "Process Creation",
  "4697": "Service Installed",
  "4720": "User Account Created",
  "4728": "Added to Security-Enabled Global Group",
  "4732": "Added to Local Group",
  "4740": "Account Lockout",
  "7045": "New Service Installed",
  "4104": "PowerShell Script Block Logging",
  "4103": "PowerShell Module Logging",
};

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

function ensurePdfSpace(doc, cursorY, requiredHeight = 24) {
  const pageHeight = doc.internal.pageSize.getHeight();
  if (cursorY + requiredHeight <= pageHeight - 16) {
    return cursorY;
  }
  doc.addPage();
  return 18;
}

function formatPdfLabelValue(label, value) {
  return `${label}: ${value || "-"}`;
}

function formatPdfHash(hashValue) {
  if (!hashValue) return "Not generated";
  if (hashValue.length <= 36) return hashValue;
  return `${hashValue.slice(0, 32)}\n${hashValue.slice(32)}`;
}

function drawEvidenceIntegritySection(doc, evidenceFiles, chainOfCustodyNotes, startY) {
  let cursorY = ensurePdfSpace(doc, startY, 28);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(12);
  doc.setTextColor(15, 23, 42);
  doc.text("Evidence Integrity & Chain of Custody", 14, cursorY);
  cursorY += 6;

  if (!evidenceFiles.length) {
    doc.setFont("helvetica", "normal");
    doc.setFontSize(9);
    doc.text("No evidence files were imported for integrity review.", 14, cursorY);
    return cursorY + 8;
  }

  evidenceFiles.forEach((file, index) => {
    cursorY = ensurePdfSpace(doc, cursorY, 56);
    autoTable(doc, {
      startY: cursorY,
      body: [
        [formatPdfLabelValue("File", file.name)],
        [formatPdfLabelValue("Source Log", file.logSource)],
        [formatPdfLabelValue("Size", file.sizeLabel)],
        [formatPdfLabelValue("SHA256", formatPdfHash(file.sha256Hash))],
        [formatPdfLabelValue("Import Time", file.importTimestamp || "-")],
        [formatPdfLabelValue("Status", file.integrityStatus || "Pending")],
      ],
      theme: "grid",
      margin: { left: 14, right: 14 },
      styles: {
        fontSize: 7,
        cellPadding: 2.5,
        textColor: [31, 41, 55],
        overflow: "linebreak",
        valign: "middle",
      },
      alternateRowStyles: { fillColor: [248, 250, 252] },
      tableLineColor: [203, 213, 225],
      tableLineWidth: 0.1,
      columnStyles: { 0: { cellWidth: "auto" } },
      didParseCell: (data) => {
        if (data.section === "body" && data.row.index === 3) {
          data.cell.styles.font = "courier";
          data.cell.styles.fontSize = 7;
        }
      },
    });
    cursorY = doc.lastAutoTable.finalY + 4;

    if (index < evidenceFiles.length - 1) {
      doc.setDrawColor(226, 232, 240);
      doc.line(14, cursorY, doc.internal.pageSize.getWidth() - 14, cursorY);
      cursorY += 5;
    }
  });

  return drawListSection(
    doc,
    "Chain of Custody Notes",
    [chainOfCustodyNotes || "No chain of custody notes recorded in this session."],
    cursorY + 2
  );
}

async function generateFileSha256(file) {
  const buffer = await file.arrayBuffer();
  const digest = await window.crypto.subtle.digest("SHA-256", buffer);
  return Array.from(new Uint8Array(digest)).map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function getFileTypeLabel(file) {
  if (file.type) return file.type;
  const extension = file.name.split(".").pop()?.toLowerCase();
  return extension ? `${extension.toUpperCase()} file` : "Unknown";
}

function buildDfirAdvisory(analysis, complianceContext) {
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

  if (complianceContext?.indiaContext) {
    advisory.push("Consider whether any confirmed incident pattern triggers CERT-In reporting or India-specific escalation obligations within prescribed timelines.");
  }

  if (!advisory.length && analysis.summary.totalEvents) {
    advisory.push("No high-signal pattern was triggered, but the imported time window should still be validated against host and identity context before closure.");
  }

  return advisory;
}

function buildDfirCsvRows(analysis, profile, complianceContext, evidenceFiles, chainOfCustodyNotes, investigationNotes) {
  const frameworkText = complianceContext.frameworks.join(" | ");
  const rows = [
    ["Section", "Client Company Name", "Industry", "Country", "Compliance Framework", "Finding Title", "Severity", "Event ID", "Source File", "User", "IP Address", "Timestamp", "Description", "Recommendation"],
    ["Assessment Profile", profile.clientCompanyName, profile.industry, profile.country, frameworkText, "", "", "", "", "", "", profile.assessmentDate, `Analyst: ${profile.analystName}`, profile.complianceMode],
    ["Executive Summary", profile.clientCompanyName, profile.industry, profile.country, frameworkText, "Risk Level", analysis.riskLevel, "", "", "", "", "", `${analysis.summary.totalEvents} event(s) analyzed`, "Assessment generated from imported Windows event evidence"],
  ];

  analysis.executiveSummary.forEach((item, index) => {
    rows.push(["Executive Summary", profile.clientCompanyName, profile.industry, profile.country, frameworkText, `Point ${index + 1}`, analysis.riskLevel, "", "", "", "", "", item, ""]);
  });

  evidenceFiles.forEach((file) => {
    rows.push(["Evidence File", profile.clientCompanyName, profile.industry, profile.country, frameworkText, file.logSource, file.importStatus, "", file.name, "", "", "", `${file.sizeLabel}${file.dateRange ? ` | ${file.dateRange}` : ""}`, "Imported evidence reference"]);
  });

  evidenceFiles.forEach((file) => {
    rows.push([
      "Evidence Integrity",
      profile.clientCompanyName,
      profile.industry,
      profile.country,
      frameworkText,
      file.logSource,
      file.integrityStatus || "Pending",
      "",
      file.name,
      file.analystName || profile.analystName,
      "",
      file.importTimestamp || "",
      `SHA256: ${file.sha256Hash || "Not generated"} | Size: ${file.sizeLabel} | Type: ${file.fileTypeLabel || "Unknown"}`,
      chainOfCustodyNotes || "No chain of custody notes recorded in this session.",
    ]);
  });

  rows.push([
    "Investigation Notes",
    profile.clientCompanyName,
    profile.industry,
    profile.country,
    frameworkText,
    "Final Verdict",
    investigationNotes.finalVerdict,
    "",
    "",
    profile.analystName,
    "",
    profile.assessmentDate,
    investigationNotes.investigationSummary || "No investigation summary recorded.",
    investigationNotes.recommendedNextSteps || "No recommended next steps recorded.",
  ]);
  rows.push([
    "Investigation Notes",
    profile.clientCompanyName,
    profile.industry,
    profile.country,
    frameworkText,
    "Analyst Observations",
    analysis.riskLevel,
    "",
    "",
    profile.analystName,
    "",
    "",
    investigationNotes.analystObservations || "No analyst observations recorded.",
    "",
  ]);
  rows.push([
    "Investigation Notes",
    profile.clientCompanyName,
    profile.industry,
    profile.country,
    frameworkText,
    "Scope Limitation",
    "Informational",
    "",
    "",
    profile.analystName,
    "",
    "",
    investigationNotes.scopeLimitation || "No scope limitation recorded.",
    "",
  ]);

  analysis.findings.forEach((finding) => {
    rows.push([
      "Key Finding",
      profile.clientCompanyName,
      profile.industry,
      profile.country,
      finding.complianceImpact,
      finding.title,
      formatSeverityLabel(finding.severity),
      finding.eventId,
      finding.sourceFile,
      finding.user,
      finding.ipAddress,
      finding.timestamp,
      finding.evidence,
      finding.recommendation,
    ]);
  });

  analysis.immediateAttention.forEach((finding) => {
    rows.push([
      "Immediate Attention Required",
      profile.clientCompanyName,
      profile.industry,
      profile.country,
      finding.complianceImpact,
      finding.title,
      formatSeverityLabel(finding.severity),
      finding.eventId,
      finding.sourceFile,
      finding.user,
      finding.ipAddress,
      finding.timestamp,
      finding.evidence,
      finding.recommendedAction,
    ]);
  });

  analysis.findingsSummary.forEach((item) => {
    rows.push(["Findings Summary", profile.clientCompanyName, profile.industry, profile.country, frameworkText, item.title, formatSeverityLabel(item.severity), "", "", "", "", "", item.detail, ""]);
  });

  analysis.topEvents.forEach((item) => {
    rows.push(["Event ID Summary", profile.clientCompanyName, profile.industry, profile.country, frameworkText, IMPORTANT_EVENT_IDS[item.id] || `Event ${item.id}`, HIGH_RISK_EVENT_IDS.has(item.id) ? "High" : "Medium", item.id, "", "", "", "", `${item.count} occurrence(s)`, "Review event context"]);
  });

  analysis.timelineSummary.forEach((item) => {
    rows.push(["Timeline Summary", profile.clientCompanyName, profile.industry, profile.country, frameworkText, item.label, item.severity, "", "", "", "", "", item.value, item.detail]);
  });

  analysis.attackSequenceHighlights.forEach((item) => {
    rows.push(["Attack Sequence Highlight", profile.clientCompanyName, profile.industry, profile.country, item.complianceImpact || frameworkText, item.title, item.severity, item.eventIds.join(" -> "), item.sourceFile || "", item.user || "", item.ipAddress || "", item.window, item.detail, item.recommendation]);
  });

  analysis.suspiciousClusters.forEach((item) => {
    rows.push(["Suspicious Event Cluster", profile.clientCompanyName, profile.industry, profile.country, item.complianceImpact || frameworkText, item.title, item.severity, item.eventIds.join(", "), item.sourceFile || "", item.user || "", item.ipAddress || "", item.window, item.detail, item.recommendation]);
  });

  analysis.timeline.forEach((item) => {
    rows.push(["Chronological Event", profile.clientCompanyName, profile.industry, profile.country, frameworkText, item.category, item.severity, item.eventId, item.sourceFile, item.user, item.ipAddress, item.timestamp, item.message || item.processName || IMPORTANT_EVENT_IDS[item.eventId] || "Timeline event", "Timeline reference"]);
  });

  rows.push([
    "USB Forensic Summary",
    profile.clientCompanyName,
    profile.industry,
    profile.country,
    frameworkText,
    "USB Evidence Overview",
    analysis.usbForensics.summary.totalUsbDevices ? "Medium" : "Low",
    "",
    "",
    "",
    "",
    "",
    `Devices: ${analysis.usbForensics.summary.totalUsbDevices} | Unique Serials: ${analysis.usbForensics.summary.uniqueUsbSerialNumbers} | Recent Connections: ${analysis.usbForensics.summary.recentlyConnectedDevices} | Install Events: ${analysis.usbForensics.summary.usbInstallEvents} | Mounted: ${analysis.usbForensics.summary.mountedDeviceCount}`,
    "Review removable media activity in user and timeline context.",
  ]);

  analysis.usbForensics.artifacts.forEach((item) => {
    rows.push([
      "USB Device Artifact",
      profile.clientCompanyName,
      profile.industry,
      profile.country,
      frameworkText,
      item.deviceName,
      item.connectionState === "connected" ? "Medium" : "Low",
      item.eventId,
      item.sourceFile,
      "",
      "",
      item.timestamp,
      `Friendly Name: ${item.friendlyName || "-"} | VID: ${item.vendorId || "-"} | PID: ${item.productId || "-"} | Serial: ${item.serialNumber || "-"} | Device Class: ${item.deviceClass || "-"} | Drive: ${item.driveLetter || "-"} | Registry: ${item.registryPath || "-"}`,
      item.disconnectTimestamp || item.installStatus || "USB forensic reference",
    ]);
  });

  analysis.usbForensics.suspiciousUsbActivity.forEach((item) => {
    rows.push([
      "Suspicious USB Activity",
      profile.clientCompanyName,
      profile.industry,
      profile.country,
      frameworkText,
      item.title,
      item.severity,
      "",
      "",
      "",
      "",
      "",
      item.detail,
      "Validate removable media usage against host scope, custody, and authentication activity.",
    ]);
  });

  analysis.suspiciousActivity.forEach((item) => {
    rows.push(["Suspicious Activity", profile.clientCompanyName, profile.industry, profile.country, item.complianceImpact || frameworkText, item.label, item.severity, item.eventId || "", item.sourceFile || "", item.user || "", item.ipAddress || "", item.timestamp || "", item.detail, item.recommendation || ""]);
  });

  buildDfirAdvisory(analysis, complianceContext).forEach((item, index) => {
    rows.push(["Analyst Advisory", profile.clientCompanyName, profile.industry, profile.country, frameworkText, `Advisory ${index + 1}`, analysis.riskLevel, "", "", "", "", "", item, ""]);
  });

  analysis.recommendations.forEach((item, index) => {
    rows.push(["Recommendation", profile.clientCompanyName, profile.industry, profile.country, frameworkText, `Action ${index + 1}`, analysis.riskLevel, "", "", "", "", "", item, item]);
  });

  return rows;
}

function exportDfirCsv(analysis, profile, complianceContext, evidenceFiles, chainOfCustodyNotes, investigationNotes) {
  if (!analysis?.summary?.totalEvents) {
    window.alert("No data to export");
    return;
  }
  downloadCsv(`dfir-log-analysis-report-${formatReportTimestamp()}.csv`, buildDfirCsvRows(analysis, profile, complianceContext, evidenceFiles, chainOfCustodyNotes, investigationNotes));
}

function exportDfirPdf(analysis, profile, complianceContext, evidenceFiles, chainOfCustodyNotes, investigationNotes) {
  if (!analysis?.summary?.totalEvents) {
    window.alert("No data to export");
    return;
  }
  const doc = new jsPDF();
  const generatedAt = formatReportDateTime();

  drawReportHeader(doc, getAssessmentTitle(profile), generatedAt);
  let cursorY = 30;

  cursorY = drawKeyValueTable(doc, [
    ["Client Company Name", profile.clientCompanyName || "Not provided"],
    ["Analyst Name", profile.analystName || "Not provided"],
    ["Assessment Date", profile.assessmentDate || generatedAt],
    ["Industry", profile.industry],
    ["Country", profile.country],
    ["Compliance Mode", COMPLIANCE_OPTIONS.find((item) => item.value === profile.complianceMode)?.label || profile.complianceMode],
    ["Applicable Frameworks", complianceContext.frameworks.join(", ") || "Not mapped"],
    ["Total Events", String(analysis.summary.totalEvents)],
    ["Failed Logons", String(analysis.summary.failedLogons)],
    ["Successful Logons", String(analysis.summary.successfulLogons)],
    ["Account Lockouts", String(analysis.summary.lockouts)],
    ["Privilege Events", String(analysis.summary.privilegeEvents)],
    ["Risk Level", analysis.riskLevel],
  ], cursorY);

  cursorY = drawListSection(doc, "Client Assessment Profile", [
    `Client Company Name: ${profile.clientCompanyName || "Not provided"}`,
    `Analyst Name: ${profile.analystName || "Not provided"}`,
    `Industry: ${profile.industry}`,
    `Country: ${profile.country}`,
    `Compliance Mode: ${COMPLIANCE_OPTIONS.find((item) => item.value === profile.complianceMode)?.label || profile.complianceMode}`,
  ], cursorY);

  cursorY = drawListSection(doc, "Compliance Context", [
    `Applicable Frameworks: ${complianceContext.frameworks.join(", ") || "Not mapped"}`,
    complianceContext.whyItApplies,
    ...complianceContext.rationale,
  ], cursorY);

  if (complianceContext.indiaContext) {
    cursorY = drawListSection(doc, "India Compliance Context", [
      `Applicable Indian regulations: ${complianceContext.indiaContext.regulations.join(", ")}`,
      ...complianceContext.indiaContext.reporting,
      ...complianceContext.indiaContext.dataProtection,
    ], cursorY);
  }

  cursorY = drawTableSection(doc, "Evidence Files Imported", [["File", "Source", "Size", "Date Range", "Status"]], evidenceFiles.length
    ? evidenceFiles.map((file) => [file.name, file.logSource, file.sizeLabel, file.dateRange || "Not inferred", file.importStatus])
    : [["No evidence files imported", "", "", "", "Pending"]], cursorY);

  cursorY = drawListSection(doc, "Evidence Integrity Summary", [
    "This section records file-level integrity metadata for imported evidence and supports auditability of the assessment workflow.",
    `Total Evidence Files: ${evidenceFiles.length}`,
    `Hashes Generated: ${evidenceFiles.filter((file) => !!file.sha256Hash).length}`,
    "Hash Algorithm: SHA256",
    "Hash Generation: Web Crypto API",
    `Analyst: ${profile.analystName || "Not provided"}`,
    `Client: ${profile.clientCompanyName || "Not provided"}`,
  ], cursorY);

  cursorY = drawEvidenceIntegritySection(doc, evidenceFiles, chainOfCustodyNotes, cursorY);

  cursorY = drawListSection(doc, "Executive Summary", analysis.executiveSummary.length ? analysis.executiveSummary : ["No executive summary was generated for the current dataset."], cursorY);

  cursorY = drawTableSection(doc, "Key Findings", [["Severity", "Title", "Event ID", "Evidence", "Recommendation"]], analysis.findings.length
    ? analysis.findings.map((finding) => [formatSeverityLabel(finding.severity), finding.title, finding.eventId, finding.evidence, finding.recommendation])
    : [["Low", "No high-risk indicators detected in the imported evidence.", "", "The current ruleset did not trigger an immediate escalation finding.", "Maintain normal review procedures."]], cursorY);

  cursorY = drawTableSection(doc, "Immediate Attention Required", [["Severity", "Title", "User", "IP", "Source File", "Compliance Impact"]], analysis.immediateAttention.length
    ? analysis.immediateAttention.map((finding) => [formatSeverityLabel(finding.severity), finding.title, finding.user || "-", finding.ipAddress || "-", finding.sourceFile || "-", finding.complianceImpact])
    : [["Low", "No high-risk indicators detected in the imported evidence.", "-", "-", "-", "Continue standard evidence review."]], cursorY);

  cursorY = drawTableSection(doc, "Findings Summary", [["Title", "Severity", "Detail"]], analysis.findingsSummary.map((item) => [item.title, formatSeverityLabel(item.severity), item.detail]), cursorY);

  cursorY = drawKeyValueTable(doc, [
    ["Critical Findings", String(analysis.riskScoreSummary.critical)],
    ["High Findings", String(analysis.riskScoreSummary.high)],
    ["Medium Findings", String(analysis.riskScoreSummary.medium)],
    ["Low Findings", String(analysis.riskScoreSummary.low)],
  ], cursorY);

  const riskRows = [
    ...analysis.topEvents.map((item) => [`Event ${item.id}`, `${item.count} occurrences`, HIGH_RISK_EVENT_IDS.has(item.id) ? "High-risk event ID" : "Frequent event ID"]),
    ...analysis.timelineRows.map((item) => [item.day, `${item.count} events`, "Timeline observation"]),
  ];
  cursorY = drawTableSection(doc, "Risk Indicators", [["Indicator", "Value", "Context"]], riskRows.length ? riskRows : [["No dominant risk indicator", "None", "No clear escalation pattern was observed"]], cursorY);

  cursorY = drawTableSection(doc, "Forensic Timeline Summary", [["Metric", "Severity", "Detail"]], analysis.timelineSummary.length
    ? analysis.timelineSummary.map((item) => [item.label, item.severity, item.detail])
    : [["Timeline pending", "Low", "Import evidence to generate timeline reconstruction"]], cursorY);

  cursorY = drawTableSection(doc, "USB Forensic Summary", [["Metric", "Value", "Detail"]], analysis.usbForensics.summary.totalUsbDevices
    ? [
      ["Total USB Devices", String(analysis.usbForensics.summary.totalUsbDevices), "Structured USB forensic artifacts parsed from imported evidence"],
      ["Unique USB Serial Numbers", String(analysis.usbForensics.summary.uniqueUsbSerialNumbers), "Distinct USB serial values observed"],
      ["Recently Connected Devices", String(analysis.usbForensics.summary.recentlyConnectedDevices), "USB connection timestamps identified"],
      ["USB Install Events", String(analysis.usbForensics.summary.usbInstallEvents), "Install or driver-related USB activity observed"],
      ["Mounted Device Count", String(analysis.usbForensics.summary.mountedDeviceCount), "Drive or mounted-device mappings identified"],
    ]
    : [["USB Forensics", "0", "No structured USB forensic artifacts identified in the imported evidence."]], cursorY);

  cursorY = drawTableSection(doc, "USB Device Table", [["Device", "VID:PID", "Serial", "Drive", "Timestamp", "Source File"]], analysis.usbForensics.artifacts.length
    ? analysis.usbForensics.artifacts.slice(0, 50).map((item) => [item.deviceName, `${item.vendorId || "-"}:${item.productId || "-"}`, item.serialNumber || "-", item.driveLetter || "-", item.timestamp || "-", item.sourceFile])
    : [["No USB evidence", "-", "-", "-", "-", "-"]], cursorY);

  cursorY = drawTableSection(doc, "Suspicious USB Activity", [["Severity", "Title", "Detail"]], analysis.usbForensics.suspiciousUsbActivity.length
    ? analysis.usbForensics.suspiciousUsbActivity.map((item) => [item.severity, item.title, item.detail])
    : [["Low", "No structured USB forensic artifacts identified in the imported evidence.", "USB evidence did not produce a suspicious removable media pattern."]], cursorY);

  cursorY = drawTableSection(doc, "Suspicious Event Clusters", [["Severity", "Title", "Window", "Sequence", "Detail"]], analysis.suspiciousClusters.length
    ? analysis.suspiciousClusters.map((item) => [item.severity, item.title, item.window, item.eventIds.join(" -> "), item.detail])
    : [["Low", "No high-confidence attack sequence identified in the imported evidence.", "-", "-", "Continue manual review of the unified timeline."]], cursorY);

  cursorY = drawTableSection(doc, "Attack Sequence Highlights", [["Severity", "Title", "Sequence", "Recommendation"]], analysis.attackSequenceHighlights.length
    ? analysis.attackSequenceHighlights.map((item) => [item.severity, item.title, item.eventIds.join(" -> "), item.recommendation])
    : [["Low", "No high-confidence attack sequence identified in the imported evidence.", "-", "Continue standard DFIR validation."]], cursorY);

  cursorY = drawTableSection(doc, "Chronological Event Timeline", [["Timestamp", "Event ID", "Category", "Severity", "User", "IP", "Source File"]], analysis.timeline.length
    ? analysis.timeline.slice(0, 50).map((item) => [item.timestamp, item.eventId, item.category, item.severity, item.user || "-", item.ipAddress || "-", item.sourceFile])
    : [["No timeline events", "-", "-", "-", "-", "-", "-"]], cursorY);

  cursorY = drawTableSection(doc, "Suspicious IP / User Activity", [["Type", "Value", "Detail"]], analysis.suspiciousActivity.length
    ? analysis.suspiciousActivity.map((item) => [item.label, item.ipAddress || item.user || item.hostname || "-", item.detail])
    : [["No suspicious activity summary", "-", "No suspicious IP or user activity summary was generated."]], cursorY);

  cursorY = drawListSection(doc, "Investigation Notes & Final Verdict", [
    `Final Verdict: ${investigationNotes.finalVerdict || "Insufficient Evidence for Final Determination"}`,
    `Investigation Summary: ${investigationNotes.investigationSummary || "No investigation summary recorded."}`,
    `Analyst Observations: ${investigationNotes.analystObservations || "No analyst observations recorded."}`,
    `Scope Limitation: ${investigationNotes.scopeLimitation || "No scope limitation recorded."}`,
    `Recommended Next Steps: ${investigationNotes.recommendedNextSteps || "No recommended next steps recorded."}`,
  ], cursorY);

  cursorY = drawListSection(doc, "Analyst Advisory", buildDfirAdvisory(analysis, complianceContext), cursorY);
  cursorY = drawListSection(doc, "Recommendations", analysis.recommendations.length ? analysis.recommendations : ["Validate the imported date range and review the event set before closure."], cursorY);
  drawListSection(doc, "Appendix: Raw Evidence References", evidenceFiles.map((file) => `${file.name} | ${file.logSource} | ${file.sizeLabel}${file.dateRange ? ` | ${file.dateRange}` : ""}`), cursorY);

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

function formatBytes(size) {
  if (!Number.isFinite(size) || size <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  let value = size;
  let index = 0;
  while (value >= 1024 && index < units.length - 1) {
    value /= 1024;
    index += 1;
  }
  return `${value.toFixed(value >= 10 || index === 0 ? 0 : 1)} ${units[index]}`;
}

function inferLogSource(fileName) {
  const name = fileName.toLowerCase();
  if (name.includes("security")) return "Security Event Log Raw CSV";
  if (name.includes("system")) return "System Event Log Raw CSV";
  if (name.includes("application")) return "Application Event Log Raw CSV";
  if (name.includes("powershell")) return "Microsoft-Windows-PowerShell Operational Raw CSV";
  return "Imported Windows Event Evidence";
}

function extractDateRangeFromFileName(fileName) {
  const match = fileName.match(/(20\d{2}[-_]\d{2}[-_]\d{2}).*?(20\d{2}[-_]\d{2}[-_]\d{2})/i);
  if (!match) return "";
  return `${match[1].replace(/_/g, "-")} to ${match[2].replace(/_/g, "-")}`;
}

function getAssessmentTitle(profile) {
  return profile.clientCompanyName
    ? `${profile.clientCompanyName} DFIR Log Assessment`
    : "DFIR Log Assessment";
}

function buildComplianceContext(profile) {
  const includeCountry = profile.complianceMode === "country" || profile.complianceMode === "both";
  const includeGlobal = profile.complianceMode === "global" || profile.complianceMode === "both";
  const industryConfig = INDUSTRY_FRAMEWORKS[profile.industry] || { global: [], countries: {} };
  const frameworks = [];
  const rationale = [];

  if (includeCountry && COUNTRY_FRAMEWORKS[profile.country]?.length) {
    frameworks.push(...COUNTRY_FRAMEWORKS[profile.country]);
    rationale.push(`${profile.country} reporting and data handling expectations are prioritized for this assessment.`);
  }
  if (includeCountry && industryConfig.countries?.[profile.country]?.length) {
    frameworks.push(...industryConfig.countries[profile.country]);
    rationale.push(`${profile.industry} sector guidance for ${profile.country} is included because the evidence comes from a regulated environment.`);
  }
  if (includeGlobal) {
    frameworks.push(...GLOBAL_FRAMEWORKS);
    rationale.push("Global control baselines are included to support cross-region DFIR and governance reporting.");
    frameworks.push(...industryConfig.global);
  }

  const dedupedFrameworks = [...new Set(frameworks)];
  const indiaContext = profile.country === "India"
    ? {
        regulations: [
          "DPDP Act",
          "Indian IT Act 2000",
          "CERT-In Directions 2022",
          ...(profile.industry === "Banking" ? ["RBI Cyber Security Framework"] : []),
          ...(profile.industry === "Banking" ? ["SEBI Cybersecurity & Cyber Resilience Framework where applicable"] : []),
          ...(profile.industry === "Healthcare" ? ["DISHA / DPDP Act context"] : []),
          "NCIIPC guidance for critical infrastructure where applicable",
        ],
        reporting: [
          "Certain cybersecurity incidents may require reporting to CERT-In within prescribed timelines.",
          "Incident handling should consider Indian reporting, evidence retention, and escalation expectations.",
        ],
        dataProtection: [
          "Personal data handling should be reviewed against DPDP obligations and need-to-know access controls.",
          "Consider regional data residency and regulatory disclosure expectations before external sharing.",
        ],
      }
    : null;

  return {
    frameworks: dedupedFrameworks,
    rationale: [...new Set(rationale)],
    whyItApplies: `${profile.industry} operations in ${profile.country} require DFIR reporting aligned to the chosen compliance mode.`,
    indiaContext,
  };
}

function mapComplianceImpact(category, context) {
  const frameworks = context.frameworks || [];
  const matched = frameworks.filter((framework) => {
    const value = framework.toLowerCase();
    if (category === "powershell" || category === "execution") {
      return value.includes("mitre") || value.includes("nist") || value.includes("cis") || value.includes("iec 62443");
    }
    if (category === "identity" || category === "authentication") {
      return value.includes("iso") || value.includes("nist") || value.includes("pci") || value.includes("hipaa") || value.includes("rbi") || value.includes("ffiec");
    }
    if (category === "privacy") {
      return value.includes("gdpr") || value.includes("dpdp");
    }
    if (category === "reporting") {
      return value.includes("cert-in") || value.includes("it act") || value.includes("nis2");
    }
    return value.includes("iso") || value.includes("nist") || value.includes("cis");
  });
  return matched.length ? matched.slice(0, 4).join(", ") : "General control and incident response review required.";
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

function annotateRecord(record, fileMeta) {
  return {
    ...record,
    __sourceFile: fileMeta.name,
    __sourceType: fileMeta.logSource,
    __fileSize: fileMeta.size,
    __dateRange: fileMeta.dateRange,
  };
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

function getHostname(record) {
  return (
    readField(record, ["MachineName", "Computer", "Hostname", "Host"]) ||
    getMessage(record).match(/Computer Name:\s+([^\r\n]+)/i)?.[1] ||
    "Unknown"
  ).trim();
}

function getUserName(record) {
  const message = getMessage(record);
  return (
    readField(record, ["User", "AccountName", "TargetUserName"]) ||
    message.match(/TargetUserName:\s+([^\r\n]+)/i)?.[1] ||
    message.match(/Account Name:\s+([^\r\n]+)/i)?.[1] ||
    "Unknown"
  ).trim();
}

function getSourceIp(record) {
  const message = getMessage(record);
  const match =
    message.match(/Source Network Address:\s+([^\r\n]+)/i) ||
    message.match(/Client Address:\s+([^\r\n]+)/i) ||
    message.match(/Source Address:\s+([^\r\n]+)/i);
  const ip = (readField(record, ["IpAddress", "SourceIp", "ClientIP"]) || match?.[1] || "").trim();
  return isValidIPv4(ip) ? ip : "";
}

function getLogonType(record) {
  const value =
    readField(record, ["LogonType"]) ||
    getMessage(record).match(/Logon Type:\s+([^\r\n]+)/i)?.[1] ||
    "";
  return value.trim();
}

function isRemoteLogon(record) {
  return ["3", "10"].includes(getLogonType(record));
}

function getProcessName(record) {
  const message = getMessage(record);
  return (
    readField(record, ["NewProcessName", "ProcessName", "Image"]) ||
    message.match(/New Process Name:\s+([^\r\n]+)/i)?.[1] ||
    message.match(/Process Name:\s+([^\r\n]+)/i)?.[1] ||
    ""
  ).trim();
}

function isSuspiciousProcess(processName) {
  const value = processName.toLowerCase();
  return ["powershell", "cmd.exe", "wscript", "cscript", "rundll32", "mshta", "psexec"].some((item) => value.includes(item));
}

function hasEncodedPowerShell(message) {
  const value = message.toLowerCase();
  return value.includes("-enc") || value.includes("-encodedcommand") || value.includes("frombase64string") || value.includes("iex ");
}

function parseEventDate(timestamp) {
  if (!timestamp) return null;
  const normalized = timestamp.replace(/\//g, "-");
  const date = new Date(normalized);
  return Number.isNaN(date.getTime()) ? null : date;
}

function isUsbEvidenceRecord(record) {
  const sourceFile = (record.__sourceFile || "").toLowerCase();
  const sourceType = (record.__sourceType || "").toLowerCase();
  const sourceLog = (readField(record, ["SourceLog", "LogName"]) || "").toLowerCase();
  const registryPath = (readField(record, ["RegistryPath"]) || "").toLowerCase();
  const message = getMessage(record).toLowerCase();
  const eventId = getEventId(record);

  return sourceFile.includes("usb") ||
    sourceType.includes("usb") ||
    sourceLog.includes("driverframeworks") ||
    sourceLog.includes("usermode") ||
    registryPath.includes("usbstor") ||
    registryPath.includes("\\usb") ||
    !!readField(record, ["VendorId", "ProductId", "SerialNumber", "DriveLetter", "DeviceInstanceId"]) ||
    ["2003", "2004", "2006", "2010", "2100", "2101", "2102", "2105", "2106", "400", "410", "6416"].includes(eventId) ||
    message.includes("usbstor") ||
    message.includes("usb");
}

function extractUsbDeviceName(record) {
  return (
    readField(record, ["DeviceName", "FriendlyName", "DeviceDesc", "DeviceInstanceId", "EntryName"]) ||
    getMessage(record).match(/Device Name:\s+([^\r\n]+)/i)?.[1] ||
    getMessage(record).match(/Friendly Name:\s+([^\r\n]+)/i)?.[1] ||
    "Unknown USB Device"
  ).trim();
}

function extractUsbFriendlyName(record) {
  return (
    readField(record, ["FriendlyName", "DeviceName", "DeviceDesc"]) ||
    getMessage(record).match(/Friendly Name:\s+([^\r\n]+)/i)?.[1] ||
    ""
  ).trim();
}

function extractUsbIdentifiers(record) {
  const combined = [
    readField(record, ["VendorId", "ProductId", "SerialNumber", "DeviceInstanceId", "RegistryPath", "RawLine", "DeviceMapping"]),
    getMessage(record),
  ].join(" ");

  const vendorMatch = combined.match(/VID[_-]?([0-9A-F]{4})/i);
  const productMatch = combined.match(/PID[_-]?([0-9A-F]{4})/i);
  const serialMatch = combined.match(/(?:USBSTOR\\|\\)([A-Z0-9&_-]{6,})/i);

  return {
    vendorId: (readField(record, ["VendorId"]) || vendorMatch?.[1] || "").trim(),
    productId: (readField(record, ["ProductId"]) || productMatch?.[1] || "").trim(),
    serialNumber: (readField(record, ["SerialNumber"]) || serialMatch?.[1] || "").trim(),
  };
}

function extractUsbConnectionState(record) {
  const eventId = getEventId(record);
  const sourceFile = (record.__sourceFile || "").toLowerCase();
  const message = getMessage(record).toLowerCase();

  if (["2003", "2100", "2101", "2102", "6416", "400"].includes(eventId) || sourceFile.includes("usbstor")) {
    return "connected";
  }
  if (["2004", "2006", "2105", "2106", "410"].includes(eventId) || message.includes("disconnect")) {
    return "disconnected";
  }
  return "";
}

function extractUsbArtifacts(events) {
  const artifacts = events
    .filter((record) => isUsbEvidenceRecord(record))
    .map((record, index) => {
      const identifiers = extractUsbIdentifiers(record);
      const timestamp = getTimestamp(record) || readField(record, ["ImportTime", "Timestamp"]);
      const connectionState = extractUsbConnectionState(record);
      const eventId = getEventId(record);
      const sourceFile = record.__sourceFile || "Imported evidence";
      const deviceName = extractUsbDeviceName(record);
      const friendlyName = extractUsbFriendlyName(record);
      const driveLetter = readField(record, ["DriveLetter"]) || readField(record, ["EntryName"]);
      const registryPath = readField(record, ["RegistryPath"]);
      const deviceClass = readField(record, ["DeviceClass", "SourceLog", "LogName"]) || (sourceFile.toLowerCase().includes("mounted") ? "Mounted Device" : "USB Activity");
      const installStatus = readField(record, ["InstallStatus"]);

      return {
        id: `${sourceFile}-${eventId}-${timestamp || index}-${identifiers.serialNumber || deviceName}`,
        sourceFile,
        timestamp,
        parsedDate: parseEventDate(timestamp),
        eventId,
        deviceName,
        friendlyName,
        vendorId: identifiers.vendorId,
        productId: identifiers.productId,
        serialNumber: identifiers.serialNumber,
        deviceClass,
        driveLetter: driveLetter.trim(),
        connectionTimestamp: connectionState === "connected" ? timestamp : "",
        disconnectTimestamp: connectionState === "disconnected" ? timestamp : "",
        registryPath,
        installStatus,
        connectionState,
        rawMessage: getMessage(record),
      };
    });

  const serialSet = new Set(artifacts.map((item) => item.serialNumber).filter(Boolean));
  const recentConnections = artifacts.filter((item) => item.connectionTimestamp).length;
  const installEvents = artifacts.filter((item) => ["2003", "2100", "2101", "6416", "400"].includes(item.eventId) || item.installStatus).length;
  const mountedDeviceCount = artifacts.filter((item) => item.driveLetter || item.deviceClass.toLowerCase().includes("mounted")).length;
  const reconnectCounts = artifacts.reduce((accumulator, item) => {
    const key = item.serialNumber || item.deviceName;
    if (!key) return accumulator;
    accumulator[key] = (accumulator[key] || 0) + 1;
    return accumulator;
  }, {});

  const suspiciousUsbActivity = [];
  Object.entries(reconnectCounts).forEach(([key, count]) => {
    if (count >= 3) {
      suspiciousUsbActivity.push({
        title: "Repeated reconnect activity",
        severity: count >= 5 ? "High" : "Medium",
        detail: `${key} appeared ${count} time(s) across imported USB evidence.`,
      });
    }
  });
  if (artifacts.some((item) => item.deviceName.toLowerCase().includes("unknown"))) {
    suspiciousUsbActivity.push({
      title: "Unknown USB device names observed",
      severity: "Medium",
      detail: "At least one imported USB artifact did not resolve to a recognizable device name.",
    });
  }

  return {
    artifacts,
    summary: {
      totalUsbDevices: artifacts.length,
      uniqueUsbSerialNumbers: serialSet.size,
      recentlyConnectedDevices: recentConnections,
      usbInstallEvents: installEvents,
      mountedDeviceCount,
    },
    suspiciousUsbActivity,
  };
}

function getEventCategory(eventId, event) {
  if (isUsbEvidenceRecord(event)) return "USB Activity";
  if (["4624", "4625", "4634", "4648", "4740"].includes(eventId)) return "Authentication";
  if (["4672"].includes(eventId)) return "Privilege Escalation";
  if (["4697", "7045"].includes(eventId)) return "Service Activity";
  if (["4103", "4104"].includes(eventId)) return "PowerShell Activity";
  if (["4720", "4728", "4732"].includes(eventId)) return "User Management";
  if (["4688"].includes(eventId)) return "Process Execution";
  if (isRemoteLogon(event)) return "Remote Access";
  return "Persistence";
}

function getTimelineSeverity(eventId, event) {
  const message = getMessage(event);
  if (isUsbEvidenceRecord(event)) {
    if (["6416", "2100", "2101", "2102"].includes(eventId)) return "Medium";
    if ((extractUsbDeviceName(event) || "").toLowerCase().includes("unknown")) return "Medium";
    return "Low";
  }
  if (hasEncodedPowerShell(message)) return "Critical";
  if (["4672", "4697", "7045", "4104"].includes(eventId)) return "High";
  if (["4625", "4648", "4688", "4720", "4728", "4732", "4740", "4103"].includes(eventId)) return "Medium";
  return "Low";
}

function normalizeTimelineEvent(event) {
  const eventId = getEventId(event) || "Unknown";
  const timestamp = getTimestamp(event) || "Unknown";
  const parsedDate = parseEventDate(timestamp);
  const usbDeviceName = isUsbEvidenceRecord(event) ? extractUsbDeviceName(event) : "";
  const usbMessage = isUsbEvidenceRecord(event) ? `${usbDeviceName}${readField(event, ["DriveLetter"]) ? ` | Drive ${readField(event, ["DriveLetter"])}` : ""}${readField(event, ["RegistryPath"]) ? ` | ${readField(event, ["RegistryPath"])}` : ""}` : getMessage(event);
  return {
    timestamp,
    parsedDate,
    eventId,
    user: getUserName(event),
    ipAddress: getSourceIp(event),
    hostname: isUsbEvidenceRecord(event) ? (readField(event, ["DriveLetter", "DeviceClass", "SourceLog"]) || getHostname(event)) : getHostname(event),
    message: usbMessage,
    processName: isUsbEvidenceRecord(event) ? usbDeviceName : getProcessName(event),
    severity: getTimelineSeverity(eventId, event),
    category: getEventCategory(eventId, event),
    sourceFile: event.__sourceFile || "Imported evidence",
    deviceName: usbDeviceName,
    raw: event,
  };
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

function analyzeEvents(events, evidenceFiles, profile, complianceContext) {
  const summary = {
    totalEvents: events.length,
    failedLogons: 0,
    successfulLogons: 0,
    logoffs: 0,
    lockouts: 0,
    privilegeEvents: 0,
    explicitCredentialUse: 0,
    processCreations: 0,
    serviceInstallations: 0,
    powershellIndicators: 0,
    userChanges: 0,
    remoteLogons: 0,
  };
  const eventCounts = {};
  const timelineBuckets = {};
  const failedByActorMinute = {};
  const failedByActor = {};
  const failedByIp = {};
  const lockoutByActor = {};
  const privilegeByActor = {};
  const successByActor = {};
  const suspiciousIps = {};
  const adminHosts = {};
  const sourceFileCounts = {};
  const processActivity = {};

  const pushFinding = (severity, title, evidence, recommendation, category, confidence, meta = {}) => {
    findings.push({
      severity,
      title,
      evidence,
      recommendation,
      category,
      confidence,
      eventId: meta.eventId || "",
      sourceFile: meta.sourceFile || "",
      user: meta.user || "",
      ipAddress: meta.ipAddress || "",
      hostname: meta.hostname || "",
      timestamp: meta.timestamp || "",
      recommendedAction: meta.recommendedAction || recommendation,
      complianceImpact: meta.complianceImpact || mapComplianceImpact(meta.complianceCategory || category.toLowerCase(), complianceContext),
    });
  };

  const findings = [];
  events.forEach((event) => {
    const id = getEventId(event);
    const timestamp = getTimestamp(event);
    const day = timestamp ? timestamp.slice(0, 10) : "Unknown";
    const actor = extractActor(event);
    const user = getUserName(event);
    const ipAddress = getSourceIp(event);
    const hostname = getHostname(event);
    const message = getMessage(event);
    const processName = getProcessName(event);
    const sourceFile = event.__sourceFile || "Imported evidence";

    eventCounts[id || "Unknown"] = (eventCounts[id || "Unknown"] || 0) + 1;
    timelineBuckets[day] = (timelineBuckets[day] || 0) + 1;
    sourceFileCounts[sourceFile] = (sourceFileCounts[sourceFile] || 0) + 1;

    if (id === "4634") summary.logoffs += 1;
    if (id === "4648") summary.explicitCredentialUse += 1;
    if (id === "4688") summary.processCreations += 1;
    if (id === "4697" || id === "7045") summary.serviceInstallations += 1;
    if (id === "4103" || id === "4104") summary.powershellIndicators += 1;
    if (id === "4720" || id === "4728" || id === "4732") summary.userChanges += 1;
    if (isRemoteLogon(event)) summary.remoteLogons += 1;

    if (WATCHED_EVENTS.failedLogons.has(id)) {
      summary.failedLogons += 1;
      const key = `${actor}|${getMinuteBucket(event)}`;
      failedByActorMinute[key] = (failedByActorMinute[key] || 0) + 1;
      failedByActor[actor] = (failedByActor[actor] || 0) + 1;
      if (ipAddress) {
        failedByIp[ipAddress] = (failedByIp[ipAddress] || 0) + 1;
        suspiciousIps[ipAddress] = (suspiciousIps[ipAddress] || 0) + 1;
      }
      if (processName && isSuspiciousProcess(processName)) {
        processActivity[processName] = (processActivity[processName] || 0) + 1;
      }
    }
    if (WATCHED_EVENTS.successfulLogons.has(id)) {
      summary.successfulLogons += 1;
      successByActor[actor] = (successByActor[actor] || 0) + 1;
      if (ipAddress) suspiciousIps[ipAddress] = (suspiciousIps[ipAddress] || 0) + 1;
    }
    if (WATCHED_EVENTS.lockouts.has(id)) {
      summary.lockouts += 1;
      const key = actor;
      lockoutByActor[key] = (lockoutByActor[key] || 0) + 1;
    }
    if (WATCHED_EVENTS.privilegeEvents.has(id)) {
      summary.privilegeEvents += 1;
      privilegeByActor[actor] = (privilegeByActor[actor] || 0) + 1;
      adminHosts[hostname] = (adminHosts[hostname] || 0) + 1;
    }
    if ((id === "4688" || id === "4103" || id === "4104") && (message || processName)) {
      if ((processName && isSuspiciousProcess(processName)) || message.toLowerCase().includes("powershell")) {
        summary.powershellIndicators += 1;
      }
      if (processName) {
        processActivity[processName] = (processActivity[processName] || 0) + 1;
      }
    }
  });

  const bruteForce = Object.entries(failedByActorMinute).sort((a, b) => b[1] - a[1])[0];
  const repeatedFailedActor = Object.entries(failedByActor).sort((a, b) => b[1] - a[1])[0];
  const repeatedSourceIp = Object.entries(failedByIp).sort((a, b) => b[1] - a[1])[0];
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
  const timeline = events
    .map((event) => normalizeTimelineEvent(event))
    .sort((a, b) => {
      if (!a.parsedDate && !b.parsedDate) return 0;
      if (!a.parsedDate) return 1;
      if (!b.parsedDate) return -1;
      return a.parsedDate - b.parsedDate;
    });
  const firstById = (eventId) => events.find((event) => getEventId(event) === eventId);
  const firstPowerShellEvent = events.find((event) => ["4103", "4104", "4688"].includes(getEventId(event)) && (getMessage(event).toLowerCase().includes("powershell") || isSuspiciousProcess(getProcessName(event))));
  const firstEncodedPowerShell = events.find((event) => hasEncodedPowerShell(getMessage(event)));
  const firstServiceInstall = events.find((event) => ["4697", "7045"].includes(getEventId(event)));
  const firstPrivilege = events.find((event) => getEventId(event) === "4672");
  const firstRemote = events.find((event) => ["4624", "4625"].includes(getEventId(event)) && isRemoteLogon(event));
  const firstUserChange = events.find((event) => ["4720", "4728", "4732"].includes(getEventId(event)));

  if (bruteForce && bruteForce[1] >= 5) {
    pushFinding(
      bruteForce[1] >= 8 ? "critical" : "high",
      "Brute force pattern indicators",
      `${bruteForce[1]} failed logon events were observed for ${bruteForce[0].split("|")[0]} within a short time window.`,
      "Review the affected account, source system, and surrounding timestamps for possible password spraying or brute force activity.",
      "Brute Force Indicators",
      bruteForce[1] >= 8 ? "high confidence" : "medium confidence",
      {
        eventId: "4625",
        user: bruteForce[0].split("|")[0],
        sourceFile: firstById("4625")?.__sourceFile || "",
        timestamp: getTimestamp(firstById("4625") || {}),
        ipAddress: getSourceIp(firstById("4625") || {}),
        hostname: getHostname(firstById("4625") || {}),
        complianceCategory: "authentication",
      }
    );
  }
  if (repeatedFailedActor && repeatedFailedActor[1] >= 4) {
    pushFinding(
      "medium",
      "Repeated failed authentication activity",
      `${repeatedFailedActor[1]} failed logon events were linked to ${repeatedFailedActor[0]}.`,
      "Validate whether the failed authentication activity was expected and confirm the originating host or source network path.",
      "Authentication Trends",
      "medium confidence",
      {
        eventId: "4625",
        user: repeatedFailedActor[0],
        sourceFile: firstById("4625")?.__sourceFile || "",
        timestamp: getTimestamp(firstById("4625") || {}),
        ipAddress: getSourceIp(firstById("4625") || {}),
        complianceCategory: "authentication",
      }
    );
  }
  if (repeatedSourceIp && repeatedSourceIp[1] >= 4) {
    pushFinding(
      repeatedSourceIp[1] >= 8 ? "high" : "medium",
      "Repeated failed login attempts from same IP",
      `${repeatedSourceIp[1]} failed authentication events were linked to source IP ${repeatedSourceIp[0]}.`,
      "Review the source IP, validate whether it belongs to a trusted network path, and consider temporary blocking if the activity is not authorized.",
      "Suspicious IP Activity",
      repeatedSourceIp[1] >= 8 ? "high confidence" : "medium confidence",
      {
        eventId: "4625",
        ipAddress: repeatedSourceIp[0],
        sourceFile: firstById("4625")?.__sourceFile || "",
        timestamp: getTimestamp(firstById("4625") || {}),
        complianceCategory: "authentication",
      }
    );
  }
  if (lockoutSpike && lockoutSpike[1] >= 3) {
    pushFinding(
      "high",
      "Account lockout spike",
      `${lockoutSpike[1]} lockout events were observed for ${lockoutSpike[0]}.`,
      "Validate lockout causes, review password reset activity, and correlate the timeline with failed logon bursts.",
      "Lockout Activity",
      "medium confidence",
      {
        eventId: "4740",
        user: lockoutSpike[0],
        sourceFile: firstById("4740")?.__sourceFile || "",
        timestamp: getTimestamp(firstById("4740") || {}),
        complianceCategory: "authentication",
      }
    );
  } else if (summary.lockouts > 0) {
    pushFinding(
      "medium",
      "Account lockout activity detected",
      `${summary.lockouts} account lockout events were observed in the uploaded dataset.`,
      "Review affected users and source systems to determine whether the lockouts map to expected password changes or suspicious authentication attempts.",
      "Lockout Activity",
      "low confidence",
      {
        eventId: "4740",
        sourceFile: firstById("4740")?.__sourceFile || "",
        complianceCategory: "authentication",
      }
    );
  }
  if (summary.successfulLogons > 0 && repeatedFailedActor && repeatedFailedActor[1] >= 4 && successByActor[repeatedFailedActor[0]]) {
    pushFinding(
      "high",
      "Successful login after multiple failed attempts",
      `A successful logon was observed for ${repeatedFailedActor[0]} after repeated failed authentication activity.`,
      "Review the login timeline, validate MFA or compensating controls, and confirm whether the successful authentication was expected.",
      "Authentication Trends",
      "medium confidence",
      {
        eventId: "4624",
        user: repeatedFailedActor[0],
        sourceFile: firstById("4624")?.__sourceFile || "",
        timestamp: getTimestamp(firstById("4624") || {}),
        ipAddress: getSourceIp(firstById("4624") || {}),
        complianceCategory: "authentication",
      }
    );
  }
  if (summary.privilegeEvents > 0) {
    pushFinding(
      summary.privilegeEvents >= 5 ? "high" : "medium",
      "Privileged activity requires review",
      `${summary.privilegeEvents} special privilege events were observed${privilegeSpike ? `, with ${privilegeSpike[1]} linked to ${privilegeSpike[0]}` : ""}.`,
      "Review privileged logons and confirm whether the activity was authorized maintenance, administration, or an unusual access pattern.",
      "Privilege Activity",
      summary.privilegeEvents >= 5 ? "medium confidence" : "low confidence",
      {
        eventId: "4672",
        user: privilegeSpike?.[0] || getUserName(firstPrivilege || {}),
        sourceFile: firstPrivilege?.__sourceFile || "",
        timestamp: getTimestamp(firstPrivilege || {}),
        hostname: getHostname(firstPrivilege || {}),
        complianceCategory: "identity",
      }
    );
  }
  if (firstServiceInstall) {
    pushFinding(
      ["4697", "7045"].includes(getEventId(firstServiceInstall)) ? "high" : "medium",
      "New Windows service created",
      `Service installation activity was observed in ${firstServiceInstall.__sourceFile || "imported evidence"}.`,
      "Validate whether the service creation is tied to an approved change and review the binary path, service account, and parent process.",
      "Persistence",
      "medium confidence",
      {
        eventId: getEventId(firstServiceInstall),
        sourceFile: firstServiceInstall.__sourceFile || "",
        timestamp: getTimestamp(firstServiceInstall),
        hostname: getHostname(firstServiceInstall),
        user: getUserName(firstServiceInstall),
        complianceCategory: "execution",
      }
    );
  }
  if (firstPowerShellEvent) {
    pushFinding(
      hasEncodedPowerShell(getMessage(firstPowerShellEvent)) ? "critical" : "high",
      hasEncodedPowerShell(getMessage(firstPowerShellEvent)) ? "Encoded PowerShell execution detected" : "Suspicious PowerShell execution detected",
      `${IMPORTANT_EVENT_IDS[getEventId(firstPowerShellEvent)] || "PowerShell activity"} suggests script execution that requires validation.`,
      "Review script content, command-line arguments, parent process, and host context to determine whether the execution was authorized.",
      "PowerShell Activity",
      hasEncodedPowerShell(getMessage(firstPowerShellEvent)) ? "high confidence" : "medium confidence",
      {
        eventId: getEventId(firstPowerShellEvent),
        sourceFile: firstPowerShellEvent.__sourceFile || "",
        timestamp: getTimestamp(firstPowerShellEvent),
        hostname: getHostname(firstPowerShellEvent),
        user: getUserName(firstPowerShellEvent),
        complianceCategory: "powershell",
      }
    );
  }
  if (firstEncodedPowerShell && firstEncodedPowerShell !== firstPowerShellEvent) {
    pushFinding(
      "critical",
      "Encoded PowerShell command observed",
      "An encoded or obfuscated PowerShell command string was identified in the imported evidence.",
      "Contain the affected host if unauthorized activity is confirmed and preserve the PowerShell evidence for deeper DFIR review.",
      "PowerShell Activity",
      "high confidence",
      {
        eventId: getEventId(firstEncodedPowerShell),
        sourceFile: firstEncodedPowerShell.__sourceFile || "",
        timestamp: getTimestamp(firstEncodedPowerShell),
        hostname: getHostname(firstEncodedPowerShell),
        user: getUserName(firstEncodedPowerShell),
        complianceCategory: "powershell",
      }
    );
  }
  if (Object.keys(processActivity).length) {
    const topProcess = Object.entries(processActivity).sort((a, b) => b[1] - a[1])[0];
    if (topProcess && isSuspiciousProcess(topProcess[0])) {
      pushFinding(
        "medium",
        "Unusual process execution",
        `${topProcess[0]} was observed ${topProcess[1]} time(s) in the imported evidence.`,
        "Validate the process path, parent process, command line, and user context against approved administrative activity.",
        "Execution",
        "low confidence",
        {
          eventId: "4688",
          sourceFile: firstById("4688")?.__sourceFile || "",
          timestamp: getTimestamp(firstById("4688") || {}),
          hostname: getHostname(firstById("4688") || {}),
          complianceCategory: "execution",
        }
      );
    }
  }
  if (summary.userChanges > 0 && firstUserChange) {
    pushFinding(
      "high",
      "User or group membership change detected",
      `${summary.userChanges} identity change event(s) were observed, including ${IMPORTANT_EVENT_IDS[getEventId(firstUserChange)] || `Event ${getEventId(firstUserChange)}`}.`,
      "Review whether the user creation or group membership change is approved and confirm the requesting administrator and ticket context.",
      "Identity Changes",
      "medium confidence",
      {
        eventId: getEventId(firstUserChange),
        sourceFile: firstUserChange.__sourceFile || "",
        timestamp: getTimestamp(firstUserChange),
        user: getUserName(firstUserChange),
        hostname: getHostname(firstUserChange),
        complianceCategory: "identity",
      }
    );
  }
  if (summary.remoteLogons > 0 && firstRemote) {
    pushFinding(
      summary.remoteLogons >= 5 ? "high" : "medium",
      "Remote logon activity requires review",
      `${summary.remoteLogons} remote logon-related event(s) were identified in the imported evidence.`,
      "Review remote access paths, user justification, and source IP history to confirm the access is expected.",
      "Remote Logon Activity",
      "low confidence",
      {
        eventId: getEventId(firstRemote),
        sourceFile: firstRemote.__sourceFile || "",
        timestamp: getTimestamp(firstRemote),
        user: getUserName(firstRemote),
        ipAddress: getSourceIp(firstRemote),
        hostname: getHostname(firstRemote),
        complianceCategory: "authentication",
      }
    );
  }
  if (failedRatio >= 3 && summary.failedLogons >= 6) {
    pushFinding(
      failedRatio >= 6 ? "high" : "medium",
      "Unusual authentication imbalance",
      `Failed logons are ${failedRatio.toFixed(1)}x successful logons in this dataset.`,
      "Correlate suspicious timestamps with endpoint or network telemetry to determine whether the imbalance reflects misconfiguration, automation failure, or possible hostile activity.",
      "Authentication Trends",
      failedRatio >= 6 ? "medium confidence" : "low confidence",
      {
        eventId: "4625",
        sourceFile: firstById("4625")?.__sourceFile || "",
        complianceCategory: "authentication",
      }
    );
  }
  if (highRiskEventIds.length) {
    pushFinding(
      highRiskEventIds.some((item) => item.count >= 5) ? "medium" : "info",
      "High-risk event IDs observed",
      highRiskEventIds.map((item) => `Event ${item.id}: ${item.count}`).join(" | "),
      "Review the highest-frequency event IDs first and compare them with expected administrative or authentication behavior.",
      "High-Risk Event IDs",
      "low confidence",
      {
        eventId: highRiskEventIds[0].id,
        sourceFile: firstById(highRiskEventIds[0].id)?.__sourceFile || "",
        complianceCategory: "reporting",
      }
    );
  }

  const timelineRows = Object.entries(timelineBuckets)
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
  if (profile.country === "India") {
    recommendations.unshift("Assess whether any confirmed cyber incident pattern triggers CERT-In reporting and preserve evidence in line with Indian regulatory expectations.");
    recommendations.push("Align data handling and evidence sharing to DPDP-sensitive workflows before external disclosure.");
  }
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
  const usbForensics = extractUsbArtifacts(events);
  const highRiskObserved = findings.some((finding) => ["critical", "high"].includes(finding.severity));
  const suspiciousClusters = [];
  const attackSequenceHighlights = [];
  const addSequence = (severity, title, detail, sequence, recommendation, meta = {}) => {
    const entry = {
      severity,
      title,
      detail,
      eventIds: sequence.map((item) => item.eventId),
      window: `${sequence[0]?.timestamp || "Unknown"} -> ${sequence[sequence.length - 1]?.timestamp || "Unknown"}`,
      recommendation,
      sourceFile: sequence[0]?.sourceFile || "",
      user: meta.user || sequence.find((item) => item.user)?.user || "",
      ipAddress: meta.ipAddress || sequence.find((item) => item.ipAddress)?.ipAddress || "",
      complianceImpact: mapComplianceImpact(meta.complianceCategory || "authentication", complianceContext),
    };
    suspiciousClusters.push(entry);
    if (["Critical", "High"].includes(severity)) {
      attackSequenceHighlights.push(entry);
    }
  };

  for (let index = 0; index < timeline.length; index += 1) {
    const current = timeline[index];
    const window = timeline.slice(index, index + 6);
    const failedChain = window.filter((item) => item.eventId === "4625");
    const successAfter = window.find((item) => item.eventId === "4624");
    if (failedChain.length >= 3 && successAfter && failedChain[0].user && successAfter.user === failedChain[0].user) {
      addSequence(
        "High",
        "Failed logon burst followed by successful authentication",
        `${failedChain.length} failed logons were followed by a successful authentication for ${successAfter.user || "the same account"}.`,
        [...failedChain, successAfter],
        "Correlate the user, host, and source IP with MFA, VPN, and endpoint telemetry before treating the login as authorized.",
        { user: successAfter.user, ipAddress: successAfter.ipAddress, complianceCategory: "authentication" }
      );
    }

    const privilegeAfterLogin = window.find((item) => item.eventId === "4672");
    if (successAfter && privilegeAfterLogin) {
      addSequence(
        "High",
        "Privilege assignment after suspicious login",
        `Privileged access was assigned shortly after a login sequence that warrants analyst review.`,
        [successAfter, privilegeAfterLogin],
        "Review whether privileged access was expected for the authenticated account and confirm the administrative change context.",
        { user: privilegeAfterLogin.user || successAfter.user, ipAddress: successAfter.ipAddress, complianceCategory: "identity" }
      );
    }

    const encodedPowerShell = window.find((item) => item.eventId === "4104" && hasEncodedPowerShell(item.message));
    if (privilegeAfterLogin && encodedPowerShell) {
      addSequence(
        "Critical",
        "Encoded PowerShell execution after privilege escalation",
        `Encoded or obfuscated PowerShell activity followed privileged access in the reconstructed timeline.`,
        [privilegeAfterLogin, encodedPowerShell],
        "Preserve the host, extract script block evidence, and validate whether the command sequence reflects attacker tradecraft.",
        { user: encodedPowerShell.user || privilegeAfterLogin.user, ipAddress: encodedPowerShell.ipAddress, complianceCategory: "powershell" }
      );
    }

    const powershellActivity = window.find((item) => item.category === "PowerShell Activity");
    const serviceInstall = window.find((item) => item.eventId === "7045");
    if (powershellActivity && serviceInstall) {
      addSequence(
        "High",
        "Service installation after PowerShell activity",
        `PowerShell execution was followed by Windows service installation activity in the same evidence window.`,
        [powershellActivity, serviceInstall],
        "Review the installed service, binary path, and script lineage to confirm whether persistence was established.",
        { user: serviceInstall.user || powershellActivity.user, ipAddress: powershellActivity.ipAddress, complianceCategory: "execution" }
      );
    }
  }

  const immediateAttention = findings
    .filter((finding) => ["critical", "high"].includes(finding.severity))
    .map((finding) => ({
      ...finding,
      findingTitle: finding.title,
    }));
  const riskScoreSummary = {
    critical: findings.filter((finding) => finding.severity === "critical").length,
    high: findings.filter((finding) => finding.severity === "high").length,
    medium: findings.filter((finding) => finding.severity === "medium").length,
    low: findings.filter((finding) => ["low", "info"].includes(finding.severity)).length,
  };
  const suspiciousActivity = [];
  if (repeatedSourceIp) {
    suspiciousActivity.push({
      label: "Repeated source IP",
      severity: repeatedSourceIp[1] >= 8 ? "High" : "Medium",
      ipAddress: repeatedSourceIp[0],
      detail: `${repeatedSourceIp[0]} appeared in ${repeatedSourceIp[1]} failed logon event(s).`,
      recommendation: "Confirm whether the source IP is trusted and correlate it with endpoint, VPN, and firewall telemetry.",
      complianceImpact: mapComplianceImpact("authentication", complianceContext),
      eventId: "4625",
      sourceFile: firstById("4625")?.__sourceFile || "",
      timestamp: getTimestamp(firstById("4625") || {}),
    });
  }
  if (privilegeSpike) {
    suspiciousActivity.push({
      label: "Privileged account activity",
      severity: summary.privilegeEvents >= 5 ? "High" : "Medium",
      user: privilegeSpike[0],
      hostname: Object.entries(adminHosts).sort((a, b) => b[1] - a[1])[0]?.[0] || "",
      detail: `${summary.privilegeEvents} privileged event(s) were observed and require authorization review.`,
      recommendation: "Validate privileged access against approved administration and change windows.",
      complianceImpact: mapComplianceImpact("identity", complianceContext),
      eventId: "4672",
      sourceFile: firstPrivilege?.__sourceFile || "",
      timestamp: getTimestamp(firstPrivilege || {}),
    });
  }
  if (usbForensics.summary.totalUsbDevices) {
    suspiciousActivity.push({
      label: "USB forensic activity",
      severity: usbForensics.suspiciousUsbActivity.length ? "Medium" : "Low",
      detail: `${usbForensics.summary.totalUsbDevices} USB artifact row(s) and ${usbForensics.summary.uniqueUsbSerialNumbers} unique serial number(s) were parsed from imported evidence.`,
      recommendation: "Review removable media handling against approved usage, host custody, and user activity context.",
      complianceImpact: mapComplianceImpact("reporting", complianceContext),
      sourceFile: usbForensics.artifacts[0]?.sourceFile || "",
      timestamp: usbForensics.artifacts[0]?.timestamp || "",
    });
  }

  const suspiciousLoginTimes = timeline
    .filter((item) => ["4624", "4625"].includes(item.eventId))
    .map((item) => item.parsedDate)
    .filter(Boolean);
  if (usbForensics.artifacts.some((item) => item.parsedDate && suspiciousLoginTimes.some((loginTime) => Math.abs(item.parsedDate - loginTime) <= 15 * 60 * 1000))) {
    usbForensics.suspiciousUsbActivity.push({
      title: "USB activity during suspicious login windows",
      severity: "High",
      detail: "USB artifact timestamps overlapped with authentication events that merit timeline correlation.",
    });
  }
  const executiveSummary = events.length
    ? [
      `${summary.totalEvents} event(s) were analyzed across ${evidenceFiles.length || 1} imported evidence file(s) for ${profile.clientCompanyName || "the current client"}.`,
      highRiskObserved
        ? `${findings.filter((finding) => ["critical", "high"].includes(finding.severity)).length} high-risk indicator(s) were observed and should be prioritized for analyst review.`
        : "No high-risk indicator pattern reached the current escalation threshold.",
      findings.length
        ? `${findings.length} investigation finding(s) were generated from authentication, privilege, PowerShell, and identity change activity patterns.`
        : "No structured findings were generated by the current ruleset.",
      highRiskObserved || riskLevel === "Medium"
        ? "Analyst review is recommended before closing the investigation."
        : "Routine validation is still recommended to confirm the observed activity is authorized.",
    ]
    : [];

  return {
    summary,
    findings,
    immediateAttention,
    findingsSummary,
    topEvents,
    timelineRows,
    timeline,
    suspiciousClusters,
    attackSequenceHighlights,
    timelineSummary: [
      {
        label: "Unified timeline events",
        value: `${timeline.length} normalized event(s)`,
        detail: `Events were reconstructed from ${evidenceFiles.length || 1} imported evidence file(s) and sorted chronologically.`,
        severity: "Low",
      },
      {
        label: "Authentication sequence pressure",
        value: `${summary.failedLogons} failed / ${summary.successfulLogons} successful`,
        detail: failedRatio >= 3 ? "Authentication pressure is elevated and should be reviewed in timeline context." : "Authentication sequencing does not exceed the current pressure threshold.",
        severity: failedRatio >= 6 ? "High" : failedRatio >= 3 ? "Medium" : "Low",
      },
      {
        label: "Suspicious event clusters",
        value: `${suspiciousClusters.length} cluster(s)`,
        detail: suspiciousClusters.length ? "At least one event chain suggests a suspicious sequence that should be validated." : "No high-confidence attack sequence identified in the imported evidence.",
        severity: attackSequenceHighlights.some((item) => item.severity === "Critical") ? "Critical" : attackSequenceHighlights.length ? "High" : "Low",
      },
      {
        label: "USB forensic artifacts",
        value: `${usbForensics.summary.totalUsbDevices} artifact(s)`,
        detail: usbForensics.summary.totalUsbDevices
          ? `${usbForensics.summary.uniqueUsbSerialNumbers} unique serial number(s) and ${usbForensics.summary.usbInstallEvents} install-related event(s) were identified.`
          : "No structured USB forensic artifacts identified in the imported evidence.",
        severity: usbForensics.suspiciousUsbActivity.some((item) => item.severity === "High") ? "High" : usbForensics.summary.totalUsbDevices ? "Low" : "Low",
      },
    ],
    extractedIndicators,
    recommendations,
    executiveSummary,
    riskLevel,
    riskScoreSummary,
    suspiciousActivity,
    usbForensics,
    evidenceReferences: evidenceFiles.map((file) => ({
      fileName: file.name,
      logSource: file.logSource,
      sizeLabel: file.sizeLabel,
      dateRange: file.dateRange,
      rowCount: sourceFileCounts[file.name] || 0,
    })),
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
  const [events, setEvents] = useState([]);
  const [evidenceFiles, setEvidenceFiles] = useState([]);
  const [uploadError, setUploadError] = useState("");
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisStage, setAnalysisStage] = useState("Analyzing imported evidence and compliance impact...");
  const [analysisCompletionNotice, setAnalysisCompletionNotice] = useState("");
  const [assessmentProfile, setAssessmentProfile] = useState(DEFAULT_ASSESSMENT_PROFILE);
  const [assessmentStarted, setAssessmentStarted] = useState(false);
  const [timelineFilters, setTimelineFilters] = useState({
    eventId: "",
    severity: "",
    category: "",
    user: "",
    ipAddress: "",
    dateFrom: "",
    dateTo: "",
  });
  const [news, setNews] = useState([]);
  const [selectedIndicator, setSelectedIndicator] = useState(null);
  const [hubResult, setHubResult] = useState(null);
  const [hubLoading, setHubLoading] = useState(false);
  const [hubError, setHubError] = useState("");
  const [scansToday, setScansToday] = useState(0);
  const [liveIndicators, setLiveIndicators] = useState([]);
  const [iocFeedSources, setIocFeedSources] = useState([]);
  const [iocFeedLoading, setIocFeedLoading] = useState(true);
  const [showEvidenceDetails, setShowEvidenceDetails] = useState(false);
  const [showComplianceDetails, setShowComplianceDetails] = useState(false);
  const [showIndiaComplianceDetails, setShowIndiaComplianceDetails] = useState(false);
  const [showAllFindings, setShowAllFindings] = useState(false);
  const [showAllImmediate, setShowAllImmediate] = useState(false);
  const [showAllClusters, setShowAllClusters] = useState(false);
  const [showAllSequences, setShowAllSequences] = useState(false);
  const [timelineVisibleCount, setTimelineVisibleCount] = useState(INITIAL_TIMELINE_VISIBLE);
  const [showEvidenceIntegrityDetails, setShowEvidenceIntegrityDetails] = useState(false);
  const [chainOfCustodyNotes, setChainOfCustodyNotes] = useState("");
  const [showInvestigationNotesDetails, setShowInvestigationNotesDetails] = useState(false);
  const [investigationNotes, setInvestigationNotes] = useState(DEFAULT_INVESTIGATION_NOTES);
  const [showAllUsbArtifacts, setShowAllUsbArtifacts] = useState(false);
  const complianceContext = useMemo(() => buildComplianceContext(assessmentProfile), [assessmentProfile]);

  const analysis = useMemo(
    () => analyzeEvents(events, evidenceFiles, assessmentProfile, complianceContext),
    [events, evidenceFiles, assessmentProfile, complianceContext]
  );
  const analysisResult = analysis.summary.totalEvents ? analysis : null;
  const filteredTimeline = useMemo(
    () =>
      analysis.timeline.filter((item) => {
        const matchesEvent = !timelineFilters.eventId || item.eventId === timelineFilters.eventId;
        const matchesSeverity = !timelineFilters.severity || item.severity === timelineFilters.severity;
        const matchesCategory = !timelineFilters.category || item.category === timelineFilters.category;
        const matchesUser = !timelineFilters.user || item.user.toLowerCase().includes(timelineFilters.user.toLowerCase());
        const matchesIp = !timelineFilters.ipAddress || item.ipAddress.includes(timelineFilters.ipAddress);
        const matchesFrom = !timelineFilters.dateFrom || (item.parsedDate && item.parsedDate >= new Date(timelineFilters.dateFrom));
        const matchesTo = !timelineFilters.dateTo || (item.parsedDate && item.parsedDate <= new Date(`${timelineFilters.dateTo}T23:59:59`));
        return matchesEvent && matchesSeverity && matchesCategory && matchesUser && matchesIp && matchesFrom && matchesTo;
      }),
    [analysis.timeline, timelineFilters]
  );
  const visibleTimeline = useMemo(
    () => filteredTimeline.slice(0, timelineVisibleCount),
    [filteredTimeline, timelineVisibleCount]
  );
  const rankedFindings = useMemo(
    () =>
      [...analysis.findings].sort((a, b) => {
        const rank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
        return (rank[a.severity] ?? 99) - (rank[b.severity] ?? 99);
      }),
    [analysis.findings]
  );
  const visibleFindings = useMemo(
    () => (showAllFindings ? rankedFindings : rankedFindings.slice(0, INITIAL_FINDINGS_VISIBLE)),
    [rankedFindings, showAllFindings]
  );
  const visibleImmediateAttention = useMemo(
    () => (showAllImmediate ? analysis.immediateAttention : analysis.immediateAttention.slice(0, INITIAL_EVENT_GROUP_VISIBLE)),
    [analysis.immediateAttention, showAllImmediate]
  );
  const visibleSuspiciousClusters = useMemo(
    () => (showAllClusters ? analysis.suspiciousClusters : analysis.suspiciousClusters.slice(0, INITIAL_EVENT_GROUP_VISIBLE)),
    [analysis.suspiciousClusters, showAllClusters]
  );
  const visibleAttackSequences = useMemo(
    () => (showAllSequences ? analysis.attackSequenceHighlights : analysis.attackSequenceHighlights.slice(0, INITIAL_EVENT_GROUP_VISIBLE)),
    [analysis.attackSequenceHighlights, showAllSequences]
  );
  const evidenceIntegritySummary = useMemo(() => {
    const hashesGenerated = evidenceFiles.filter((file) => !!file.sha256Hash).length;
    const latestImport = evidenceFiles.reduce((latest, file) => {
      if (!file.importTimestamp) return latest;
      return !latest || new Date(file.importTimestamp) > new Date(latest) ? file.importTimestamp : latest;
    }, "");
    return {
      totalEvidenceFiles: evidenceFiles.length,
      hashesGenerated,
      latestImport,
      analyst: assessmentProfile.analystName || "Not provided",
      client: assessmentProfile.clientCompanyName || "Not provided",
    };
  }, [evidenceFiles, assessmentProfile]);
  const visibleUsbArtifacts = useMemo(
    () => (showAllUsbArtifacts ? analysis.usbForensics.artifacts : analysis.usbForensics.artifacts.slice(0, 5)),
    [analysis.usbForensics.artifacts, showAllUsbArtifacts]
  );
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
  useEffect(() => {
    setTimelineVisibleCount(INITIAL_TIMELINE_VISIBLE);
  }, [timelineFilters, analysis.timeline.length]);

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
    if (!isAnalyzing) return undefined;

    const timer = window.setTimeout(() => {
      if (events.length || analysis.summary.totalEvents || analysis.findings.length) {
        setIsAnalyzing(false);
        setAnalysisCompletionNotice(
          "Analysis completed with available evidence. Review generated findings below."
        );
      }
    }, 18000);

    return () => window.clearTimeout(timer);
  }, [
    analysis.findings.length,
    analysis.summary.totalEvents,
    events.length,
    isAnalyzing,
  ]);

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
    const files = [...(event.target.files || [])];
    setUploadError("");
    setSelectedIndicator(null);
    setHubResult(null);
    setHubError("");
    setAnalysisCompletionNotice("");
    setAnalysisStage("Parsing evidence files...");
    setIsAnalyzing(true);
    if (!files.length) {
      setIsAnalyzing(false);
      return;
    }

    const invalidFile = files.find((file) => !file.name.toLowerCase().endsWith(".csv"));
    if (invalidFile) {
      setEvents([]);
      setEvidenceFiles([]);
      setUploadError("Upload CSV evidence files exported from the Windows log collection workflow.");
      return;
    }

    try {
      setAnalysisStage("Generating evidence integrity hashes...");
      const parsedBundles = await Promise.all(
        files.map(async (file) => {
          const importTimestamp = new Date().toISOString();
          let sha256Hash = "";
          let integrityStatus = "Pending";
          try {
            sha256Hash = await generateFileSha256(file);
            integrityStatus = sha256Hash ? "Verified" : "Pending";
          } catch (hashError) {
            sha256Hash = "";
            integrityStatus = "Hash Failed";
          }
          const fileMeta = {
            name: file.name,
            size: file.size,
            sizeLabel: formatBytes(file.size),
            fileTypeLabel: getFileTypeLabel(file),
            logSource: inferLogSource(file.name),
            dateRange: extractDateRangeFromFileName(file.name),
            importStatus: "Imported",
            importTimestamp,
            analystName: assessmentProfile.analystName,
            clientCompanyName: assessmentProfile.clientCompanyName,
            sha256Hash,
            integrityStatus,
          };
          const parsedRows = parseCsv(await file.text()).map((record) => annotateRecord(record, fileMeta));
          return { fileMeta, parsedRows };
        })
      );

      setAnalysisStage("Building forensic timeline...");
      const allRows = parsedBundles.flatMap((item) => item.parsedRows);
      if (!allRows.length) {
        setEvents([]);
        setEvidenceFiles(parsedBundles.map((item) => ({ ...item.fileMeta, importStatus: "No readable rows" })));
        setUploadError("No readable event rows were found in the imported evidence bundle.");
        return;
      }

      setAnalysisStage("Generating findings...");
      setEvidenceFiles(
        parsedBundles.map((item) => ({
          ...item.fileMeta,
          importStatus: item.parsedRows.length ? "Imported" : "No readable rows",
          rowCount: item.parsedRows.length,
        }))
      );
      setAnalysisStage("Finalizing report data...");
      setEvents(allRows);
    } catch (error) {
      setEvents([]);
      setEvidenceFiles([]);
      setUploadError("One or more evidence files could not be parsed. Confirm the CSV export format and retry.");
    } finally {
      window.setTimeout(() => {
        setIsAnalyzing(false);
        setAnalysisStage("Analyzing imported evidence and compliance impact...");
      }, 0);
    }
  };

  const handleAssessmentProfileChange = (event) => {
    const { name, value } = event.target;
    setAssessmentProfile((current) => ({ ...current, [name]: value }));
  };

  const handleAssessmentStart = (event) => {
    event.preventDefault();
    if (!assessmentProfile.clientCompanyName.trim() || !assessmentProfile.analystName.trim()) {
      setUploadError("Enter the client company name and analyst name before starting the assessment.");
      return;
    }
    setUploadError("");
    setAssessmentStarted(true);
  };

  const handleTimelineFilterChange = (event) => {
    const { name, value } = event.target;
    setTimelineFilters((current) => ({ ...current, [name]: value }));
  };

  const handleInvestigationNotesChange = (event) => {
    const { name, value } = event.target;
    setInvestigationNotes((current) => ({ ...current, [name]: value }));
  };

  const handleCopyHash = async (hashValue) => {
    if (!hashValue) return;
    try {
      await navigator.clipboard.writeText(hashValue);
    } catch (error) {
      window.alert("Unable to copy the SHA256 hash from this browser context.");
    }
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
                Run the local PowerShell exporter with a custom date range, map the evidence to client and compliance context,
                then analyze imported Windows logs for suspicious activity, vulnerable control gaps, and immediate-response indicators.
              </p>
              <div className="command-panel">
                <span>Example local export command</span>
                <code>{SAMPLE_EXPORT_COMMAND}</code>
              </div>
            </section>

            {!assessmentStarted ? (
              <section className="panel logs-hero-panel assessment-form-panel">
                <div className="section-heading">
                  <div>
                    <p className="eyebrow">Client Assessment Profile</p>
                    <h1>Start Client-Based DFIR Assessment</h1>
                  </div>
                </div>
                <p className="section-copy">
                  Select client, industry, region, and compliance context before importing exported Windows event evidence.
                </p>
                <form className="assessment-form-grid" onSubmit={handleAssessmentStart}>
                  <label className="field-group">
                    <span>Client Company Name</span>
                    <input name="clientCompanyName" onChange={handleAssessmentProfileChange} value={assessmentProfile.clientCompanyName} />
                  </label>
                  <label className="field-group">
                    <span>Analyst Name</span>
                    <input name="analystName" onChange={handleAssessmentProfileChange} value={assessmentProfile.analystName} />
                  </label>
                  <label className="field-group">
                    <span>Assessment Date</span>
                    <input name="assessmentDate" onChange={handleAssessmentProfileChange} type="date" value={assessmentProfile.assessmentDate} />
                  </label>
                  <label className="field-group">
                    <span>Industry Selection</span>
                    <select name="industry" onChange={handleAssessmentProfileChange} value={assessmentProfile.industry}>
                      {INDUSTRY_OPTIONS.map((item) => <option key={item} value={item}>{item}</option>)}
                    </select>
                  </label>
                  <label className="field-group">
                    <span>Country Selection</span>
                    <select name="country" onChange={handleAssessmentProfileChange} value={assessmentProfile.country}>
                      {COUNTRY_OPTIONS.map((item) => <option key={item} value={item}>{item}</option>)}
                    </select>
                  </label>
                  <label className="field-group">
                    <span>Compliance Mode</span>
                    <select name="complianceMode" onChange={handleAssessmentProfileChange} value={assessmentProfile.complianceMode}>
                      {COMPLIANCE_OPTIONS.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}
                    </select>
                  </label>
                  <div className="assessment-actions">
                    <button className="btn secondary" type="submit">Open Assessment Workflow</button>
                  </div>
                </form>
              </section>
            ) : (
              <>
                <section className="support-panels logs-context-panels">
                  <section className="panel result-card">
                    <div className="section-heading compact">
                      <div>
                        <p className="eyebrow">Client Assessment Profile</p>
                        <h2>{assessmentProfile.clientCompanyName}</h2>
                      </div>
                      <button className="btn secondary" onClick={() => setAssessmentStarted(false)} type="button">Edit Profile</button>
                    </div>
                    <div className="context-grid">
                      <div className="event-row"><span>Analyst Name</span><strong>{assessmentProfile.analystName}</strong></div>
                      <div className="event-row"><span>Assessment Date</span><strong>{assessmentProfile.assessmentDate}</strong></div>
                      <div className="event-row"><span>Industry</span><strong>{assessmentProfile.industry}</strong></div>
                      <div className="event-row"><span>Country</span><strong>{assessmentProfile.country}</strong></div>
                      <div className="event-row"><span>Compliance Mode</span><strong>{COMPLIANCE_OPTIONS.find((item) => item.value === assessmentProfile.complianceMode)?.label}</strong></div>
                    </div>
                  </section>
                  <section className="panel result-card">
                    <div className="section-heading compact">
                      <div>
                        <p className="eyebrow">Compliance Context</p>
                        <h2>Applicable Frameworks</h2>
                      </div>
                      <button className="btn secondary compact-toggle" onClick={() => setShowComplianceDetails((value) => !value)} type="button">
                        {showComplianceDetails ? "Collapse Compliance Details" : "Expand Compliance Details"}
                      </button>
                    </div>
                    <p className="section-copy">{complianceContext.whyItApplies}</p>
                    <div className="framework-pill-grid">
                      {complianceContext.frameworks.slice(0, showComplianceDetails ? complianceContext.frameworks.length : 4).map((item) => <span className="dataset-pill" key={item}>{item}</span>)}
                    </div>
                    {showComplianceDetails && (
                      <div className="summary-list compact-list">
                        {complianceContext.rationale.map((item) => <p key={item}>{item}</p>)}
                      </div>
                    )}
                  </section>
                  {complianceContext.indiaContext && (
                    <section className="panel result-card">
                      <div className="section-heading compact">
                        <div>
                          <p className="eyebrow">India Compliance Context</p>
                          <h2>Indian Regulatory Guidance</h2>
                        </div>
                        <button className="btn secondary compact-toggle" onClick={() => setShowIndiaComplianceDetails((value) => !value)} type="button">
                          {showIndiaComplianceDetails ? "Collapse Compliance Details" : "Expand Compliance Details"}
                        </button>
                      </div>
                      <div className="guidance-stack">
                        <div className="guidance-item">
                          <strong>Applicable Indian regulations</strong>
                          <p>{complianceContext.indiaContext.regulations.join(", ")}</p>
                        </div>
                        {showIndiaComplianceDetails && (
                          <>
                            <div className="guidance-item">
                              <strong>Mandatory reporting expectations</strong>
                              <p>{complianceContext.indiaContext.reporting.join(" ")}</p>
                            </div>
                            <div className="guidance-item">
                              <strong>Data protection considerations</strong>
                              <p>{complianceContext.indiaContext.dataProtection.join(" ")}</p>
                            </div>
                          </>
                        )}
                      </div>
                    </section>
                  )}
                </section>

                <section className="panel full-width-panel evidence-summary-panel">
                  <div className="section-heading">
                    <div>
                      <p className="eyebrow">Evidence Import Workflow</p>
                      <h1>Evidence Export Summary</h1>
                    </div>
                    <div className="section-actions">
                      <span className="dataset-pill">
                        {evidenceFiles.length ? `${evidenceFiles.length} file(s)` : "Awaiting evidence"}
                      </span>
                      <button className="btn secondary compact-toggle" onClick={() => setShowEvidenceDetails((value) => !value)} type="button">
                        {showEvidenceDetails ? "Collapse Evidence Details" : "Expand Evidence Details"}
                      </button>
                    </div>
                  </div>
                  <div className="evidence-summary-grid">
                    <label className="upload-zone evidence-upload-zone">
                      <input accept=".csv,text/csv" multiple onChange={handleCsvUpload} type="file" />
                      <span>Security Event Log Raw CSV, System Event Log Raw CSV, Application Event Log Raw CSV, PowerShell Operational Raw CSV</span>
                      <strong>Import Evidence Files</strong>
                    </label>
                    <div className="workflow-list">
                      {WORKFLOW_STEPS.map((step, index) => (
                        <div className="workflow-step" key={step}>
                          <span>{String(index + 1).padStart(2, "0")}</span>
                          <p>{step}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                  {uploadError && <p className="status-message status-warning">{uploadError}</p>}
                  {!uploadError && !!evidenceFiles.length && (
                    <p className="status-message">Loaded {events.length} event row(s) from {evidenceFiles.length} evidence file(s).</p>
                  )}
                  {showEvidenceDetails && (
                    <div className="evidence-table">
                      {evidenceFiles.length ? evidenceFiles.map((file) => (
                        <div className="evidence-row" key={file.name}>
                          <strong>{file.name}</strong>
                          <span>{file.logSource}</span>
                          <span>{file.sizeLabel}</span>
                          <span>{file.dateRange || "Date range not inferred"}</span>
                          <span>{file.importStatus}</span>
                        </div>
                      )) : (
                        <p>No evidence files imported yet.</p>
                      )}
                    </div>
                  )}
                </section>

                <section className="panel full-width-panel evidence-integrity-panel">
                  <div className="section-heading">
                    <div>
                      <p className="eyebrow">Evidence Integrity &amp; Chain of Custody</p>
                      <h1>Evidence Integrity &amp; Chain of Custody</h1>
                    </div>
                    <div className="section-actions">
                      <span className="dataset-pill">
                        {evidenceIntegritySummary.hashesGenerated} hash(es) generated
                      </span>
                      <button className="btn secondary compact-toggle" onClick={() => setShowEvidenceIntegrityDetails((value) => !value)} type="button">
                        {showEvidenceIntegrityDetails ? "Collapse Evidence Integrity" : "Expand Evidence Integrity"}
                      </button>
                    </div>
                  </div>
                  <p className="section-copy">
                    This section records file-level integrity metadata for imported evidence and supports auditability of the assessment workflow.
                  </p>
                  <div className="summary-card-grid evidence-integrity-summary-grid">
                    <div className="summary-card">
                      <span className="severity-badge low">Total Evidence Files</span>
                      <p><strong>{evidenceIntegritySummary.totalEvidenceFiles}</strong></p>
                    </div>
                    <div className="summary-card">
                      <span className="severity-badge low">Hashes Generated</span>
                      <p><strong>{evidenceIntegritySummary.hashesGenerated}</strong></p>
                    </div>
                    <div className="summary-card">
                      <span className="severity-badge low">Import Time</span>
                      <p><strong>{evidenceIntegritySummary.latestImport ? new Date(evidenceIntegritySummary.latestImport).toLocaleString() : "Pending"}</strong></p>
                    </div>
                    <div className="summary-card">
                      <span className="severity-badge low">Analyst</span>
                      <p><strong>{evidenceIntegritySummary.analyst}</strong></p>
                    </div>
                    <div className="summary-card">
                      <span className="severity-badge low">Client</span>
                      <p><strong>{evidenceIntegritySummary.client}</strong></p>
                    </div>
                    <div className="summary-card">
                      <span className="severity-badge low">Hash Algorithm</span>
                      <p><strong>SHA256</strong></p>
                    </div>
                    <div className="summary-card">
                      <span className="severity-badge low">Hash Generation</span>
                      <p><strong>Web Crypto API</strong></p>
                    </div>
                    <div className="summary-card">
                      <span className="severity-badge low">Integrity Verification Status</span>
                      <p><strong>{evidenceFiles.some((file) => file.integrityStatus === "Hash Failed") ? "Review Required" : evidenceIntegritySummary.hashesGenerated ? "Verified" : "Pending"}</strong></p>
                    </div>
                  </div>
                  <label className="field-group chain-notes-field">
                    <span>Chain of Custody Notes</span>
                    <textarea
                      onChange={(event) => setChainOfCustodyNotes(event.target.value)}
                      placeholder="Record evidence handling notes, transfer details, validation remarks, or preservation observations for this session."
                      rows="4"
                      value={chainOfCustodyNotes}
                    />
                  </label>
                  {showEvidenceIntegrityDetails && (
                    <div className="evidence-table evidence-integrity-table">
                      <div className="evidence-row evidence-integrity-row evidence-header-row">
                        <strong>File Name</strong>
                        <strong>Source Log</strong>
                        <strong>Size</strong>
                        <strong>SHA256</strong>
                        <strong>Import Time</strong>
                        <strong>Integrity Status</strong>
                      </div>
                      {evidenceFiles.length ? evidenceFiles.map((file) => (
                        <div className="evidence-row evidence-integrity-row" key={`${file.name}-${file.importTimestamp || "pending"}`}>
                          <strong>{file.name}</strong>
                          <span>{file.logSource}</span>
                          <span>{file.sizeLabel}</span>
                          <div className="hash-cell">
                            <code className="hash-value" title="SHA256 evidence integrity hash">{file.sha256Hash || "Not generated"}</code>
                            {!!file.sha256Hash && (
                              <button className="btn secondary hash-copy-btn" onClick={() => handleCopyHash(file.sha256Hash)} title="SHA256 evidence integrity hash" type="button">
                                Copy
                              </button>
                            )}
                          </div>
                          <span>{file.importTimestamp ? new Date(file.importTimestamp).toLocaleString() : "Pending"}</span>
                          <span>{file.integrityStatus || "Pending"}</span>
                        </div>
                      )) : (
                        <p>No evidence files imported yet.</p>
                      )}
                    </div>
                  )}
                </section>

                <section className="panel full-width-panel evidence-integrity-panel">
                  <div className="section-heading">
                    <div>
                      <p className="eyebrow">Investigation Notes &amp; Final Verdict</p>
                      <h1>Investigation Notes &amp; Final Verdict</h1>
                    </div>
                    <div className="section-actions">
                      <span className="dataset-pill">
                        {investigationNotes.finalVerdict}
                      </span>
                      <button className="btn secondary compact-toggle" onClick={() => setShowInvestigationNotesDetails((value) => !value)} type="button">
                        {showInvestigationNotesDetails ? "Collapse Investigation Notes" : "Expand Investigation Notes"}
                      </button>
                    </div>
                  </div>
                  <p className="section-copy">
                    Capture the human investigator assessment so the final report reflects analyst judgement alongside automated findings.
                  </p>
                  <div className="summary-card-grid evidence-integrity-summary-grid">
                    <div className="summary-card">
                      <span className="severity-badge low">Final Verdict</span>
                      <p><strong>{investigationNotes.finalVerdict}</strong></p>
                    </div>
                    <div className="summary-card">
                      <span className="severity-badge low">Investigation Summary</span>
                      <p>{investigationNotes.investigationSummary || "Pending analyst summary."}</p>
                    </div>
                    <div className="summary-card">
                      <span className="severity-badge low">Recommended Next Steps</span>
                      <p>{investigationNotes.recommendedNextSteps || "Pending analyst next steps."}</p>
                    </div>
                  </div>
                  {showInvestigationNotesDetails && (
                    <div className="assessment-form-grid investigation-notes-grid">
                      <label className="field-group chain-notes-field">
                        <span>Investigation Summary</span>
                        <textarea
                          name="investigationSummary"
                          onChange={handleInvestigationNotesChange}
                          placeholder="Summarize the investigation outcome using analyst-assessment language."
                          rows="4"
                          value={investigationNotes.investigationSummary}
                        />
                      </label>
                      <label className="field-group chain-notes-field">
                        <span>Analyst Observations</span>
                        <textarea
                          name="analystObservations"
                          onChange={handleInvestigationNotesChange}
                          placeholder="Record notable observations, correlations, and contextual validation notes."
                          rows="4"
                          value={investigationNotes.analystObservations}
                        />
                      </label>
                      <label className="field-group chain-notes-field">
                        <span>Scope Limitation</span>
                        <textarea
                          name="scopeLimitation"
                          onChange={handleInvestigationNotesChange}
                          placeholder="Document evidence gaps, host coverage limitations, or time-range constraints."
                          rows="4"
                          value={investigationNotes.scopeLimitation}
                        />
                      </label>
                      <label className="field-group">
                        <span>Final Verdict</span>
                        <select name="finalVerdict" onChange={handleInvestigationNotesChange} value={investigationNotes.finalVerdict}>
                          {FINAL_VERDICT_OPTIONS.map((option) => <option key={option} value={option}>{option}</option>)}
                        </select>
                      </label>
                      <label className="field-group chain-notes-field">
                        <span>Recommended Next Steps</span>
                        <textarea
                          name="recommendedNextSteps"
                          onChange={handleInvestigationNotesChange}
                          placeholder="Capture next actions for analysts, responders, or client stakeholders."
                          rows="4"
                          value={investigationNotes.recommendedNextSteps}
                        />
                      </label>
                    </div>
                  )}
                </section>

                <section className="panel full-width-panel evidence-integrity-panel">
                  <div className="section-heading">
                    <div>
                      <p className="eyebrow">USB Forensic Evidence</p>
                      <h1>USB Forensic Evidence</h1>
                    </div>
                    <div className="section-actions">
                      <span className="dataset-pill">{analysis.usbForensics.summary.totalUsbDevices} artifact(s)</span>
                      {analysis.usbForensics.artifacts.length > 5 && (
                        <button className="btn secondary compact-toggle" onClick={() => setShowAllUsbArtifacts((value) => !value)} type="button">
                          {showAllUsbArtifacts ? "Show Less" : "View More"}
                        </button>
                      )}
                    </div>
                  </div>
                  <div className="summary-card-grid evidence-integrity-summary-grid">
                    <div className="summary-card">
                      <span className="severity-badge low">Total USB Devices</span>
                      <p><strong>{analysis.usbForensics.summary.totalUsbDevices}</strong></p>
                    </div>
                    <div className="summary-card">
                      <span className="severity-badge low">Unique USB Serial Numbers</span>
                      <p><strong>{analysis.usbForensics.summary.uniqueUsbSerialNumbers}</strong></p>
                    </div>
                    <div className="summary-card">
                      <span className="severity-badge low">Recently Connected Devices</span>
                      <p><strong>{analysis.usbForensics.summary.recentlyConnectedDevices}</strong></p>
                    </div>
                    <div className="summary-card">
                      <span className="severity-badge low">USB Install Events</span>
                      <p><strong>{analysis.usbForensics.summary.usbInstallEvents}</strong></p>
                    </div>
                    <div className="summary-card">
                      <span className="severity-badge low">Mounted Device Count</span>
                      <p><strong>{analysis.usbForensics.summary.mountedDeviceCount}</strong></p>
                    </div>
                  </div>
                  {analysis.usbForensics.suspiciousUsbActivity.length ? (
                    <div className="guidance-stack usb-suspicious-stack">
                      {analysis.usbForensics.suspiciousUsbActivity.map((item) => (
                        <div className={`guidance-item status-card ${item.severity.toLowerCase()}`} key={`${item.title}-${item.detail}`}>
                          <strong>{item.title}</strong>
                          <p>{item.detail}</p>
                        </div>
                      ))}
                    </div>
                  ) : analysis.usbForensics.artifacts.length ? (
                    <p className="section-copy">USB evidence was parsed, but no suspicious removable media pattern exceeded the current review threshold.</p>
                  ) : (
                    <p className="section-copy">No structured USB forensic artifacts identified in the imported evidence.</p>
                  )}
                  {analysis.usbForensics.artifacts.length ? (
                    <div className="evidence-table evidence-integrity-table">
                      <div className="evidence-row usb-artifact-row evidence-header-row">
                        <strong>Device Name</strong>
                        <strong>Friendly Name</strong>
                        <strong>VID:PID</strong>
                        <strong>Serial Number</strong>
                        <strong>Device Class</strong>
                        <strong>Drive</strong>
                        <strong>Connected</strong>
                        <strong>Disconnected</strong>
                        <strong>Registry Path</strong>
                      </div>
                      {visibleUsbArtifacts.map((item) => (
                        <div className="evidence-row usb-artifact-row" key={item.id}>
                          <span>{item.deviceName}</span>
                          <span>{item.friendlyName || "-"}</span>
                          <span>{item.vendorId || "-"}{item.productId ? `:${item.productId}` : ""}</span>
                          <span>{item.serialNumber || "-"}</span>
                          <span>{item.deviceClass || "-"}</span>
                          <span>{item.driveLetter || "-"}</span>
                          <span>{item.connectionTimestamp || "-"}</span>
                          <span>{item.disconnectTimestamp || "-"}</span>
                          <span>{item.registryPath || "-"}</span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p>No structured USB forensic artifacts identified in the imported evidence.</p>
                  )}
                </section>

                <section className="logs-top-grid">
                  <div className="logs-left-stack">
                    <section className="panel analysis-panel logs-top-findings">
                      <div className="section-heading">
                        <div>
                          <p className="eyebrow">Analysis Dashboard</p>
                          <h1>Security Findings</h1>
                        </div>
                        <span className="dataset-pill">
                          {events.length ? `${events.length} events loaded` : "Awaiting evidence"}
                        </span>
                      </div>

                      {isAnalyzing && (
                        <div className="loading-box dfir-loading-panel" aria-live="polite">
                          <span className="loading-spinner" aria-hidden="true" />
                          <div>
                            <strong>Logs scanning in progress...</strong>
                            <p>{analysisStage}</p>
                          </div>
                        </div>
                      )}

                      {!isAnalyzing && analysisCompletionNotice && (
                        <p className="status-message status-info">{analysisCompletionNotice}</p>
                      )}

                      {!isAnalyzing && (
                        <div className="metric-grid">
                          <div className="metric-card"><span>Total Events</span><strong>{analysis.summary.totalEvents}</strong></div>
                          <div className="metric-card warning"><span>Failed Logons</span><strong>{analysis.summary.failedLogons}</strong></div>
                          <div className="metric-card"><span>Successful Logons</span><strong>{analysis.summary.successfulLogons}</strong></div>
                          <div className="metric-card warning"><span>Account Lockouts</span><strong>{analysis.summary.lockouts}</strong></div>
                          <div className="metric-card"><span>Privilege Events</span><strong>{analysis.summary.privilegeEvents}</strong></div>
                          <div className="metric-card"><span>PowerShell Indicators</span><strong>{analysis.summary.powershellIndicators}</strong></div>
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
                          This workflow helps review uploaded Windows Security, System, Application, and PowerShell logs for suspicious authentication, privilege escalation, service creation, script execution, and client-specific compliance impact.
                        </p>

                        <div className="insight-list">
                          {Object.entries(IMPORTANT_EVENT_IDS).slice(0, 8).map(([id, label]) => (
                            <div className="insight-card" key={id}>
                              <strong>{id}</strong>
                              <span>{label}</span>
                            </div>
                          ))}
                        </div>

                        <div className="guidance-stack">
                          <div className="guidance-item">
                            <strong>Repeated failed logons</strong>
                            <p>May indicate brute force or password spraying when clustered around the same user, IP, or time window.</p>
                          </div>
                          <div className="guidance-item">
                            <strong>Service and PowerShell events</strong>
                            <p>Can indicate persistence, execution, or anti-forensic activity and should be correlated with host change context.</p>
                          </div>
                          <div className="guidance-item">
                            <strong>Compliance-aware review</strong>
                            <p>Findings are mapped to the selected country and industry framework set using advisory-style guidance.</p>
                          </div>
                        </div>
                      </>
                    ) : (
                      <>
                        <p className="section-copy">
                          Detection Summary updates after evidence import and reflects the current findings engine output for this client profile.
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

              <div className="result-card">
                <div className="section-heading compact">
                  <div>
                    <p className="eyebrow">Immediate Attention Required</p>
                    <h2>High-Risk Findings</h2>
                  </div>
                  {analysis.immediateAttention.length > INITIAL_EVENT_GROUP_VISIBLE && (
                    <button className="btn secondary compact-toggle" onClick={() => setShowAllImmediate((value) => !value)} type="button">
                      {showAllImmediate ? "Show Less" : "View More"}
                    </button>
                  )}
                </div>
                {analysis.immediateAttention.length ? (
                  <div className="immediate-attention-grid">
                    {visibleImmediateAttention.map((finding) => (
                      <div className={`finding ${finding.severity}`} key={`${finding.title}-${finding.timestamp}`}>
                        <span className={`severity-badge ${finding.severity}`}>{formatSeverityLabel(finding.severity)}</span>
                        <strong>{finding.title}</strong>
                        <p>{finding.evidence}</p>
                        <div className="event-row"><span>Event ID</span><strong>{finding.eventId || "-"}</strong></div>
                        <div className="event-row"><span>User</span><strong>{finding.user || "-"}</strong></div>
                        <div className="event-row"><span>IP Address</span><strong>{finding.ipAddress || "-"}</strong></div>
                        <div className="event-row"><span>Hostname</span><strong>{finding.hostname || "-"}</strong></div>
                        <div className="event-row"><span>Evidence File</span><strong>{finding.sourceFile || "-"}</strong></div>
                        <p>{finding.recommendedAction}</p>
                        <small>{finding.complianceImpact}</small>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p>No high-risk indicators detected in the imported evidence.</p>
                )}
              </div>

              <div className="finding-grid">
                <div className="result-card">
                  <div className="section-heading compact">
                    <div>
                      <h2>Findings</h2>
                      <p className="section-copy findings-preview-copy">Top critical findings are shown first for faster triage.</p>
                    </div>
                    {rankedFindings.length > INITIAL_FINDINGS_VISIBLE && (
                      <button className="btn secondary compact-toggle" onClick={() => setShowAllFindings((value) => !value)} type="button">
                        {showAllFindings ? "Show Less" : "View More"}
                      </button>
                    )}
                  </div>
                  {rankedFindings.length ? visibleFindings.map((finding) => (
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

              <div className="result-card">
                <div className="section-heading compact">
                  <div>
                    <p className="eyebrow">Forensic Timeline Reconstruction</p>
                    <h2>Timeline Summary</h2>
                  </div>
                </div>
                <div className="summary-card-grid timeline-summary-grid">
                  {analysis.timelineSummary.map((item) => (
                    <div className={`summary-card ${item.severity.toLowerCase()}`} key={item.label}>
                      <span className={`severity-badge ${item.severity.toLowerCase()}`}>{item.label}</span>
                      <p><strong>{item.value}</strong></p>
                      <p>{item.detail}</p>
                    </div>
                  ))}
                </div>
              </div>

              <div className="report-grid">
                <div className="result-card">
                  <div className="section-heading compact">
                    <div>
                      <h2>Suspicious Event Clusters</h2>
                      <p className="section-copy findings-preview-copy">Top suspicious events are shown first to reduce review fatigue.</p>
                    </div>
                    {analysis.suspiciousClusters.length > INITIAL_EVENT_GROUP_VISIBLE && (
                      <button className="btn secondary compact-toggle" onClick={() => setShowAllClusters((value) => !value)} type="button">
                        {showAllClusters ? "Show Less" : "View More"}
                      </button>
                    )}
                  </div>
                  {analysis.suspiciousClusters.length ? visibleSuspiciousClusters.map((item) => (
                    <div className={`finding ${item.severity.toLowerCase()}`} key={`${item.title}-${item.window}`}>
                      <span className={`severity-badge ${item.severity.toLowerCase()}`}>{item.severity}</span>
                      <strong>{item.title}</strong>
                      <p>{item.detail}</p>
                      <small>{item.window}</small>
                      <p>{item.eventIds.join(" -> ")}</p>
                    </div>
                  )) : (
                    <p>No high-confidence attack sequence identified in the imported evidence.</p>
                  )}
                </div>

                <div className="result-card">
                  <div className="section-heading compact">
                    <div>
                      <h2>Attack Sequence Highlights</h2>
                      <p className="section-copy findings-preview-copy">Sequence highlights stay compact until you expand the full chain list.</p>
                    </div>
                    {analysis.attackSequenceHighlights.length > INITIAL_EVENT_GROUP_VISIBLE && (
                      <button className="btn secondary compact-toggle" onClick={() => setShowAllSequences((value) => !value)} type="button">
                        {showAllSequences ? "Show Less" : "View More"}
                      </button>
                    )}
                  </div>
                  {analysis.attackSequenceHighlights.length ? visibleAttackSequences.map((item) => (
                    <div className={`finding ${item.severity.toLowerCase()}`} key={`${item.title}-${item.window}-highlight`}>
                      <span className={`severity-badge ${item.severity.toLowerCase()}`}>{item.severity}</span>
                      <strong>{item.title}</strong>
                      <p>{item.detail}</p>
                      <small>{item.complianceImpact}</small>
                      <p>{item.recommendation}</p>
                    </div>
                  )) : (
                    <p>No high-confidence attack sequence identified in the imported evidence.</p>
                  )}
                </div>
              </div>

              <div className="result-card">
                <div className="section-heading compact">
                  <div>
                    <p className="eyebrow">Forensic Timeline Reconstruction</p>
                    <h2>Chronological Event Table</h2>
                  </div>
                  <div className="section-actions">
                    <span className="dataset-pill">{visibleTimeline.length} of {filteredTimeline.length} visible event(s)</span>
                    {filteredTimeline.length > INITIAL_TIMELINE_VISIBLE && (
                      <button
                        className="btn secondary compact-toggle"
                        onClick={() => setTimelineVisibleCount(timelineVisibleCount >= filteredTimeline.length ? INITIAL_TIMELINE_VISIBLE : filteredTimeline.length)}
                        type="button"
                      >
                        {timelineVisibleCount >= filteredTimeline.length ? "Show Less" : "Show Full Timeline"}
                      </button>
                    )}
                  </div>
                </div>

                <div className="timeline-filter-grid">
                  <label className="field-group">
                    <span>Event ID</span>
                    <input name="eventId" onChange={handleTimelineFilterChange} value={timelineFilters.eventId} />
                  </label>
                  <label className="field-group">
                    <span>Severity</span>
                    <select name="severity" onChange={handleTimelineFilterChange} value={timelineFilters.severity}>
                      <option value="">All</option>
                      {["Critical", "High", "Medium", "Low"].map((item) => <option key={item} value={item}>{item}</option>)}
                    </select>
                  </label>
                  <label className="field-group">
                    <span>Category</span>
                    <select name="category" onChange={handleTimelineFilterChange} value={timelineFilters.category}>
                      <option value="">All</option>
                      {["Authentication", "Privilege Escalation", "Persistence", "PowerShell Activity", "Service Activity", "User Management", "Remote Access", "Process Execution", "USB Activity"].map((item) => <option key={item} value={item}>{item}</option>)}
                    </select>
                  </label>
                  <label className="field-group">
                    <span>User</span>
                    <input name="user" onChange={handleTimelineFilterChange} value={timelineFilters.user} />
                  </label>
                  <label className="field-group">
                    <span>IP</span>
                    <input name="ipAddress" onChange={handleTimelineFilterChange} value={timelineFilters.ipAddress} />
                  </label>
                  <label className="field-group">
                    <span>Date From</span>
                    <input name="dateFrom" onChange={handleTimelineFilterChange} type="date" value={timelineFilters.dateFrom} />
                  </label>
                  <label className="field-group">
                    <span>Date To</span>
                    <input name="dateTo" onChange={handleTimelineFilterChange} type="date" value={timelineFilters.dateTo} />
                  </label>
                </div>

                <div className="timeline-table">
                  {visibleTimeline.length ? visibleTimeline.map((item, index) => (
                    <div className="timeline-row" key={`${item.timestamp}-${item.eventId}-${index}`}>
                      <strong>{item.timestamp}</strong>
                      <span>{item.eventId}</span>
                      <span>{item.category}</span>
                      <span>{item.severity}</span>
                      <span>{item.user || "-"}</span>
                      <span>{item.ipAddress || "-"}</span>
                      <span>{item.hostname || "-"}</span>
                      <span>{item.processName || "-"}</span>
                      <span>{item.sourceFile}</span>
                    </div>
                  )) : (
                    <p>No timeline events match the selected filters.</p>
                  )}
                </div>
                {filteredTimeline.length > INITIAL_TIMELINE_VISIBLE && (
                  <div className="timeline-actions">
                    {timelineVisibleCount < filteredTimeline.length ? (
                      <>
                        <button className="btn secondary compact-toggle" onClick={() => setTimelineVisibleCount((count) => Math.min(filteredTimeline.length, count + TIMELINE_PAGE_SIZE))} type="button">
                          Load More
                        </button>
                        <button className="btn secondary compact-toggle" onClick={() => setTimelineVisibleCount(filteredTimeline.length)} type="button">
                          Show Full Timeline
                        </button>
                      </>
                    ) : (
                      <button className="btn secondary compact-toggle" onClick={() => setTimelineVisibleCount(INITIAL_TIMELINE_VISIBLE)} type="button">
                        Show Less
                      </button>
                    )}
                  </div>
                )}
              </div>

              {analysisResult && !isAnalyzing && (
                <div className="report-actions report-actions-inline">
                  <button className="btn secondary" onClick={() => exportDfirPdf(analysisResult, assessmentProfile, complianceContext, evidenceFiles, chainOfCustodyNotes, investigationNotes)} type="button">
                    Download PDF
                  </button>
                  <button className="btn secondary" onClick={() => exportDfirCsv(analysisResult, assessmentProfile, complianceContext, evidenceFiles, chainOfCustodyNotes, investigationNotes)} type="button">
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
