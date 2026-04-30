Windows DFIR Offline Log Triage and Exporter

A PowerShell-based offline DFIR utility for collecting Windows event logs,
exporting raw evidence to CSV, and generating focused triage output for common
investigation event IDs.

This tool is built for manual incident response and forensic triage on a local
Windows system. It does not use cloud services, APIs, SIEM connectors, or any
online dependency.

Tool Purpose
------------

The goal of this project is to:

- collect important Windows logs from a chosen date range
- export lightweight raw CSVs for offline review
- generate focused DFIR triage output for common security-relevant events
- review suspicious process execution tied to process creation events
- keep everything local and beginner-friendly

Supported log sources:

- Security
- System
- Application
- Microsoft-Windows-PowerShell/Operational

Priority DFIR event IDs:

- 4624 successful logon
- 4625 failed logon
- 4634 logoff
- 4647 user initiated logoff
- 4672 special privileges assigned
- 4688 process creation
- 4720 user account created
- 4722 user account enabled
- 4723 password change attempted
- 4724 password reset attempted
- 7045 service installed
- 4104 PowerShell script block logging

Modes
-----

Full DFIR Mode:

- raw CSV export per log source
- DFIR_KeyEvents_*.csv
- Suspicious_Processes_4688_*.csv when suspicious hits are found
- DFIR_Summary_*.txt

Fast Raw-Only Mode:

- raw CSV export per log source
- DFIR_Summary_*.txt

Raw-only mode does not generate filtered DFIR CSV output and does not perform
suspicious process detection.

Output Structure
----------------

Output\
  Raw\
  Filtered\
  Summary\

Privileges and Execution
------------------------

Administrator privileges are mandatory.

- Security_Logs.ps1 automatically relaunches itself with UAC elevation if it is
  not already running as Administrator.
- Run.bat also relaunches itself as Administrator when double-clicked.
- The tool does not continue without elevation.

Recommended launch:

1. Extract the ZIP before running the tool.
2. Double-click Run.bat.
3. Approve the UAC prompt.
4. Enter the date range and choose a mode.

Performance and Progress
------------------------

The tool is optimized for large offline log exports:

- raw export does not render the full Message field
- raw export does not call ToXml() for all events
- XML parsing is limited to priority DFIR event IDs in Full DFIR mode
- event ID counts are tracked during collection to avoid repeated rescans

Visible progress is shown for:

- collecting logs
- raw export
- DFIR filtering
- suspicious process analysis
- summary generation

Limitations
-----------

This utility is an offline triage helper, not a full forensic acquisition
platform.

- it only works with locally available Windows event logs
- old events may already be overwritten based on log retention settings
- some channels may be disabled or not populated on a given host
- suspicious process names alone are not enough to confirm malicious activity
- it does not replace EDR, SIEM, memory analysis, disk acquisition, or deeper
  forensic collection
