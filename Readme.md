**Threat Intel Aggregator (Mini SOC + DFIR Dashboard)**

Threat Intel Aggregator is a combined Security Operations (SOC) and Digital Forensics (DFIR) dashboard designed to analyze Indicators of Compromise (IOCs) and review Windows Security Logs for investigation and audit purposes.

This project integrates real-time threat intelligence with offline log analysis to provide a practical and investigator-focused security workflow.

**Core Capabilities**
1. IOC Analysis Engine
The platform allows analysts to scan and evaluate:
IP addresses
Domains
URLs
File hashes (MD5, SHA1, SHA256)
Email indicators
The system aggregates results from multiple threat intelligence providers such as:
VirusTotal
AbuseIPDB
AlienVault OTX
MalwareBazaar
ThreatFox
Each scan produces:
Verdict (Malicious / Suspicious / Clean)
Severity score
Provider-backed context
Threat intelligence enrichment

2. Windows Security Log Export (PowerShell-Based)
A dedicated PowerShell-based utility is included to extract Windows Security Logs from endpoints.
Features:
Custom date range selection
Export logs in CSV format
No installation required (plug-and-play)
Designed for offline DFIR workflows
The exported logs serve as raw forensic evidence for further analysis.

3. DFIR Log Analysis Dashboard
The exported CSV logs can be uploaded into the dashboard for analysis.
The system processes logs to identify
Failed logon attempts (Event ID 4625)
Successful logons (4624)
Account lockouts (4740)
Privilege escalation events (4672)
Authentication patterns and anomalies

4. Investigation & Risk Insights
Based on the uploaded logs, the dashboard provides
Executive summary of activity
Risk assessment (Low / Medium / High)
Investigation insights (brute force indicators, lockout spikes, privilege misuse)
Event correlation and pattern detection

This helps analysts understand whether the system shows signs of compromise or misuse.

5. Threat Intelligence Feed
The dashboard includes a live cybersecurity news and threat intelligence feed to keep analysts informed about:
Latest vulnerabilities
Active campaigns
Malware trends

**Workflow**
Export Windows Security Logs using the provided PowerShell script
Upload the generated CSV into the dashboard
Analyze system behavior and identify suspicious activity
Use IOC scanning module to validate indicators
Review risk insights and investigation findings

**Use Cases**
SOC monitoring and alert validation
Digital Forensics and Incident Response (DFIR)
Security audits and system health assessment
Suspicious activity investigation
Threat intelligence enrichment


**Tech Stack**
Frontend:
React (Vite)
Tailwind CSS

Backend:
Python (Flask)

Integrations:
VirusTotal API
AbuseIPDB API
AlienVault OTX API
MalwareBazaar API
ThreatFox API

**Important Notes**
API keys are required for live threat intelligence integrations
The tool is designed for educational and security research purposes
Results should be validated before making critical security decisions
API keys are required for live threat intelligence integrations
The tool is designed for educational and security research purposes
Results should be validated before making critical security decisions
