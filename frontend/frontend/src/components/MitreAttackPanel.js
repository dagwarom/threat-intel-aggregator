import React from "react";
import "./MitreAttackPanel.css";

const MITRE_ROWS = [
  {
    eventId: "4625",
    description: "Failed Logon",
    tactic: "Initial Access",
    technique: "T1566 Phishing",
    note: "Use when suspicious URLs, domains, or email artifacts appear in triage data.",
  },
  {
    eventId: "4625",
    description: "Failed Logon Pattern",
    tactic: "Credential Access",
    technique: "T1110 Brute Force",
    note: "Maps well to repeated 4625 activity, password spraying, and auth abuse.",
  },
  {
    eventId: "4672",
    description: "Privileged Logon",
    tactic: "Privilege Escalation",
    technique: "T1078 Valid Accounts",
    note: "Relevant when privileged logons and unexpected admin activity require review.",
  },
  {
    eventId: "1100+",
    description: "Coverage Gap / Log Suppression",
    tactic: "Defense Evasion",
    technique: "T1070 Indicator Removal",
    note: "Helpful when logs are incomplete or event coverage drops unexpectedly.",
  },
  {
    eventId: "4624",
    description: "Successful Logon Review",
    tactic: "Discovery",
    technique: "T1087 Account Discovery",
    note: "Useful during account-focused investigations and unusual identity enumeration.",
  },
  {
    eventId: "4688",
    description: "Process Created",
    tactic: "Execution",
    technique: "T1059 - Command and Scripting Interpreter",
    note: "Useful for identifying suspicious PowerShell, CMD, or script execution.",
  },
  {
    eventId: "7045",
    description: "Service Installed",
    tactic: "Persistence",
    technique: "T1543.003 - Windows Service",
    note: "Useful for detecting suspicious service creation or persistence activity.",
  },
];

function MitreAttackPanel() {
  return (
    <section className="reference-panel" aria-labelledby="mitre-reference-title">
      <p className="eyebrow">Detection Mapping</p>
      <h2 id="mitre-reference-title">MITRE ATT&amp;CK Reference</h2>
      <div className="mitre-grid">
        {MITRE_ROWS.map((item) => (
          <article className="mitre-item" key={`${item.eventId}-${item.technique}`}>
            <span>{item.tactic}</span>
            <strong>{item.technique}</strong>
            <small>{item.eventId} · {item.description}</small>
            <p>{item.note}</p>
          </article>
        ))}
      </div>
    </section>
  );
}

export default MitreAttackPanel;
