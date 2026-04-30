# Windows DFIR Offline Log Triage and Export Utility
# Author: Om
#
# Offline/manual Windows event log exporter for DFIR triage.
# Raw exports stay lightweight for speed. Deep XML parsing is limited to
# priority DFIR event IDs in Full DFIR mode.

$ErrorActionPreference = "Stop"

function Write-Status {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [ConsoleColor]$Color = [ConsoleColor]::White
    )

    Write-Host "[*] $Message" -ForegroundColor $Color
}

function Format-Duration {
    param(
        [Parameter(Mandatory = $true)]
        [TimeSpan]$Duration
    )

    if ($Duration.TotalHours -ge 1) {
        return "{0:hh\:mm\:ss}" -f $Duration
    }

    return "{0:mm\:ss}" -f $Duration
}

function Show-Progress {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Activity,

        [Parameter(Mandatory = $true)]
        [string]$Status,

        [int]$Processed = 0,
        [int]$Total = 0,
        [TimeSpan]$Elapsed = [TimeSpan]::Zero
    )

    if ($Total -gt 0) {
        $percent = [math]::Min(100, [math]::Round(($Processed / $Total) * 100, 1))
        Write-Progress -Activity $Activity -Status "$Status | $Processed / $Total ($percent%) | Elapsed: $(Format-Duration $Elapsed)" -PercentComplete $percent
    }
    else {
        Write-Progress -Activity $Activity -Status "$Status | Processed: $Processed | Elapsed: $(Format-Duration $Elapsed)" -PercentComplete -1
    }
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Ensure-Administrator {
    if (Test-IsAdministrator) {
        return $true
    }

    $scriptPath = $PSCommandPath
    if ([string]::IsNullOrWhiteSpace($scriptPath)) {
        $scriptPath = $MyInvocation.MyCommand.Path
    }

    if ([string]::IsNullOrWhiteSpace($scriptPath)) {
        Write-Host "Unable to determine the current script path for elevation." -ForegroundColor Red
        exit 1
    }

    $hostPath = (Get-Process -Id $PID -ErrorAction SilentlyContinue).Path
    if ([string]::IsNullOrWhiteSpace($hostPath)) {
        $hostPath = "powershell.exe"
    }

    $arguments = @(
        "-NoProfile"
        "-ExecutionPolicy"
        "Bypass"
        "-File"
        "`"$scriptPath`""
    )

    Write-Host "Administrator privileges are required. Requesting elevation..." -ForegroundColor Yellow

    try {
        Start-Process -FilePath $hostPath -ArgumentList $arguments -Verb RunAs | Out-Null
        exit 0
    }
    catch {
        Write-Host "Elevation was cancelled or failed. The tool cannot continue without Administrator privileges." -ForegroundColor Red
        exit 1
    }
}

function Show-ConsoleWidthWarning {
    param(
        [int]$MinimumWidth = 120
    )

    try {
        if ($Host.UI.RawUI.WindowSize.Width -lt $MinimumWidth) {
            Write-Host "For best viewing experience, maximize the window before running." -ForegroundColor Yellow
            Write-Host ""
        }
    }
    catch {
        # Some hosts may not expose a resizable console window. Skip the warning.
    }
}

function Read-DateInput {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Prompt
    )

    while ($true) {
        $inputValue = Read-Host $Prompt
        $parsedDate = [datetime]::MinValue

        $isValid = [datetime]::TryParseExact(
            $inputValue,
            "yyyy-MM-dd",
            [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::None,
            [ref]$parsedDate
        )

        if ($isValid) {
            return $parsedDate.Date
        }

        Write-Host "Invalid date. Please use yyyy-MM-dd, for example 2026-04-01." -ForegroundColor Red
    }
}

function Read-RunMode {
    Write-Host ""
    Write-Host "Select mode:" -ForegroundColor Cyan
    Write-Host "1. Full DFIR mode (raw export + filtered events + suspicious review + summary)"
    Write-Host "2. Fast raw-only mode (raw CSVs + summary only)"

    while ($true) {
        $choice = Read-Host "Enter 1 or 2"
        switch ($choice) {
            "1" { return "Full" }
            "2" { return "RawOnly" }
            default { Write-Host "Invalid selection. Enter 1 or 2." -ForegroundColor Red }
        }
    }
}

function New-SafeDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function ConvertTo-SafeFileName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    return ($Name -replace '[\\/:*?"<>|]', '_')
}

function Test-EventLogAvailable {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LogName
    )

    try {
        Get-WinEvent -ListLog $LogName -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

function Get-EventDataMap {
    param(
        [Parameter(Mandatory = $true)]
        [System.Diagnostics.Eventing.Reader.EventRecord]$Event
    )

    $map = [ordered]@{}

    try {
        [xml]$xml = $Event.ToXml()
        foreach ($data in $xml.Event.EventData.Data) {
            $name = $data.Name
            if ([string]::IsNullOrWhiteSpace($name)) {
                $name = "Data$($map.Count)"
            }

            if (-not $map.Contains($name)) {
                $map[$name] = [string]$data.'#text'
            }
        }
    }
    catch {
        # Keep processing even if one event cannot be parsed.
    }

    return $map
}

function Convert-RawEventForCsv {
    param(
        [Parameter(Mandatory = $true)]
        [System.Diagnostics.Eventing.Reader.EventRecord]$Event
    )

    # Raw mode intentionally avoids Message rendering and XML parsing for speed.
    [pscustomobject]@{
        TimeCreated  = $Event.TimeCreated
        LogName      = $Event.LogName
        ProviderName = $Event.ProviderName
        EventId      = $Event.Id
        Level        = $Event.LevelDisplayName
        RecordId     = $Event.RecordId
        MachineName  = $Event.MachineName
        UserId       = $Event.UserId
        ProcessId    = $Event.ProcessId
        ThreadId     = $Event.ThreadId
    }
}

function Convert-DfirEventForCsv {
    param(
        [Parameter(Mandatory = $true)]
        [System.Diagnostics.Eventing.Reader.EventRecord]$Event
    )

    $eventData = Get-EventDataMap -Event $Event

    [pscustomobject]@{
        TimeCreated       = $Event.TimeCreated
        LogName           = $Event.LogName
        ProviderName      = $Event.ProviderName
        EventId           = $Event.Id
        Level             = $Event.LevelDisplayName
        RecordId          = $Event.RecordId
        MachineName       = $Event.MachineName
        UserId            = $Event.UserId
        ProcessId         = $Event.ProcessId
        ThreadId          = $Event.ThreadId
        SubjectUserName   = $eventData["SubjectUserName"]
        TargetUserName    = $eventData["TargetUserName"]
        IpAddress         = $eventData["IpAddress"]
        WorkstationName   = $eventData["WorkstationName"]
        LogonType         = $eventData["LogonType"]
        NewProcessName    = $eventData["NewProcessName"]
        ParentProcessName = $eventData["ParentProcessName"]
        ServiceName       = $eventData["ServiceName"]
        ScriptBlockText   = $eventData["ScriptBlockText"]
        EventData         = ($eventData.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "; "
    }
}

function Export-EventsToCsvWithProgress {
    param(
        [Parameter(Mandatory = $true)]
        [array]$Events,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Activity,

        [Parameter(Mandatory = $true)]
        [string]$Phase,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Raw", "Dfir")]
        [string]$ExportType
    )

    $total = $Events.Count
    $processed = 0
    $watch = [System.Diagnostics.Stopwatch]::StartNew()

    Show-Progress -Activity $Activity -Status $Phase -Processed 0 -Total $total -Elapsed $watch.Elapsed

    $Events |
        ForEach-Object {
            $processed++

            if (($processed -eq 1) -or ($processed -eq $total) -or (($processed % 500) -eq 0)) {
                Show-Progress -Activity $Activity -Status $Phase -Processed $processed -Total $total -Elapsed $watch.Elapsed
            }

            if ($ExportType -eq "Raw") {
                Convert-RawEventForCsv -Event $_
            }
            else {
                Convert-DfirEventForCsv -Event $_
            }
        } |
        Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8

    $watch.Stop()
    Write-Progress -Activity $Activity -Completed
    return $watch.Elapsed
}

function Get-EventsForLogWithProgress {
    param(
        [Parameter(Mandatory = $true)]
        [string]$LogName,

        [Parameter(Mandatory = $true)]
        [datetime]$StartTime,

        [Parameter(Mandatory = $true)]
        [datetime]$EndTime,

        [Parameter(Mandatory = $true)]
        [hashtable]$DfirEventIdLookup,

        [Parameter(Mandatory = $true)]
        [hashtable]$EventIdCounts
    )

    $events = New-Object System.Collections.Generic.List[object]
    $dfirEvents = New-Object System.Collections.Generic.List[object]
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $processed = 0
    $activity = "Collecting logs: $LogName"

    try {
        Show-Progress -Activity $activity -Status "Collecting logs" -Processed 0 -Total 0 -Elapsed $watch.Elapsed

        Get-WinEvent -FilterHashtable @{
            LogName   = $LogName
            StartTime = $StartTime
            EndTime   = $EndTime
        } -ErrorAction Stop | ForEach-Object {
            $processed++
            $events.Add($_)

            if ($DfirEventIdLookup.ContainsKey($_.Id)) {
                $dfirEvents.Add($_)
                $EventIdCounts[$_.Id]++
            }

            if (($processed -eq 1) -or (($processed % 500) -eq 0)) {
                Show-Progress -Activity $activity -Status "Collecting logs" -Processed $processed -Total 0 -Elapsed $watch.Elapsed
            }
        }

        $watch.Stop()
        Write-Progress -Activity $activity -Completed

        return [pscustomobject]@{
            Events     = $events
            DfirEvents = $dfirEvents
            Count      = $processed
            Duration   = $watch.Elapsed
            Error      = $null
        }
    }
    catch [System.Diagnostics.Eventing.Reader.EventLogNotFoundException] {
        $watch.Stop()
        Write-Progress -Activity $activity -Completed

        return [pscustomobject]@{
            Events     = $events
            DfirEvents = $dfirEvents
            Count      = $processed
            Duration   = $watch.Elapsed
            Error      = "Log channel not found."
        }
    }
    catch [System.UnauthorizedAccessException] {
        $watch.Stop()
        Write-Progress -Activity $activity -Completed

        return [pscustomobject]@{
            Events     = $events
            DfirEvents = $dfirEvents
            Count      = $processed
            Duration   = $watch.Elapsed
            Error      = "Access denied while reading the log."
        }
    }
    catch {
        $watch.Stop()
        Write-Progress -Activity $activity -Completed

        return [pscustomobject]@{
            Events     = $events
            DfirEvents = $dfirEvents
            Count      = $processed
            Duration   = $watch.Elapsed
            Error      = $_.Exception.Message
        }
    }
}

Ensure-Administrator

Clear-Host
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host " Windows DFIR Offline Log Triage and Exporter" -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host ""
Show-ConsoleWidthWarning

$scriptWatch = [System.Diagnostics.Stopwatch]::StartNew()
$isAdmin = Test-IsAdministrator

if ($isAdmin) {
    Write-Status "Administrator privileges detected." Green
}

$basePath = Split-Path -Parent $MyInvocation.MyCommand.Path
$outputRoot = Join-Path $basePath "Output"
$rawFolder = Join-Path $outputRoot "Raw"
$filteredFolder = Join-Path $outputRoot "Filtered"
$summaryFolder = Join-Path $outputRoot "Summary"

New-SafeDirectory -Path $outputRoot
New-SafeDirectory -Path $rawFolder
New-SafeDirectory -Path $filteredFolder
New-SafeDirectory -Path $summaryFolder

Write-Host ""
$startDate = Read-DateInput -Prompt "Enter Start Date (yyyy-MM-dd)"

do {
    $endDate = Read-DateInput -Prompt "Enter End Date   (yyyy-MM-dd)"
    if ($startDate -gt $endDate) {
        Write-Host "End date cannot be earlier than start date." -ForegroundColor Red
    }
} while ($startDate -gt $endDate)

$runMode = Read-RunMode

if ($runMode -eq "RawOnly") {
    Write-Status "Fast raw-only mode selected. Filtered output will not be generated in this mode." Yellow
}

# Add one day so the analyst's end date includes the whole selected day.
$endDateExclusive = $endDate.AddDays(1)
$dateStamp = "{0}_{1}" -f $startDate.ToString("yyyyMMdd"), $endDate.ToString("yyyyMMdd")

$logSources = @(
    "Security",
    "System",
    "Application",
    "Microsoft-Windows-PowerShell/Operational"
)

$dfirEventIds = @(4624, 4625, 4634, 4647, 4672, 4688, 4720, 4722, 4723, 4724, 7045, 4104)
$dfirEventIdLookup = @{}
foreach ($eventId in $dfirEventIds) {
    $dfirEventIdLookup[$eventId] = $true
}

$eventDescriptions = @{
    4624 = "Successful logon"
    4625 = "Failed logon"
    4634 = "Logoff"
    4647 = "User initiated logoff"
    4672 = "Special privileges assigned"
    4688 = "Process creation"
    4720 = "User account created"
    4722 = "User account enabled"
    4723 = "Password change attempted"
    4724 = "Password reset attempted"
    7045 = "Service installed"
    4104 = "PowerShell script block logging"
}
$suspiciousProcessNames = @(
    "powershell.exe",
    "cmd.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "wscript.exe",
    "cscript.exe"
)

$summaryLines = New-Object System.Collections.Generic.List[string]
$warningLines = New-Object System.Collections.Generic.List[string]
$logStats = New-Object System.Collections.Generic.List[object]
$allDfirEvents = New-Object System.Collections.Generic.List[object]
$suspiciousHits = New-Object System.Collections.Generic.List[object]
$eventIdCounts = @{}

foreach ($eventId in $dfirEventIds) {
    $eventIdCounts[$eventId] = 0
}

Write-Host ""
Write-Status "Mode: $runMode" Cyan
Write-Status "Collecting logs from $($startDate.ToString('yyyy-MM-dd')) through $($endDate.ToString('yyyy-MM-dd'))..." Cyan

foreach ($logName in $logSources) {
    Write-Host ""
    Write-Status "Checking log source: $logName" Cyan

    if (-not (Test-EventLogAvailable -LogName $logName)) {
        $warningMessage = "$logName log source is unavailable on this system."

        if ($logName -eq "Security" -and -not $isAdmin) {
            $warningMessage = "Security log unavailable due to missing administrator privileges."
        }

        Write-Status $warningMessage Yellow
        $warningLines.Add($warningMessage)
        $logStats.Add([pscustomobject]@{
            LogName        = $logName
            EventCount     = 0
            DfirCount      = 0
            CollectTime    = [TimeSpan]::Zero
            RawExportTime  = [TimeSpan]::Zero
            Status         = "Unavailable"
        })
        continue
    }

    $collection = Get-EventsForLogWithProgress -LogName $logName -StartTime $startDate -EndTime $endDateExclusive -DfirEventIdLookup $dfirEventIdLookup -EventIdCounts $eventIdCounts

    if ($collection.Error) {
        $warningMessage = "$logName log collection error: $($collection.Error)"

        if ($logName -eq "Security") {
            $warningMessage = "Security log unavailable: $($collection.Error)"
        }

        Write-Status $warningMessage Yellow
        $warningLines.Add($warningMessage)
        $logStats.Add([pscustomobject]@{
            LogName        = $logName
            EventCount     = $collection.Count
            DfirCount      = $collection.DfirEvents.Count
            CollectTime    = $collection.Duration
            RawExportTime  = [TimeSpan]::Zero
            Status         = $collection.Error
        })
        continue
    }

    Write-Status "$logName total events found: $($collection.Count) | collection time: $(Format-Duration $collection.Duration)" Green

    if ($collection.Count -eq 0) {
        $logStats.Add([pscustomobject]@{
            LogName        = $logName
            EventCount     = 0
            DfirCount      = 0
            CollectTime    = $collection.Duration
            RawExportTime  = [TimeSpan]::Zero
            Status         = "No events in selected range"
        })
        continue
    }

    $safeLogName = ConvertTo-SafeFileName -Name $logName
    $rawPath = Join-Path $rawFolder ("{0}_{1}_Raw.csv" -f $safeLogName, $dateStamp)

    Write-Status "Raw export phase for $logName started." Cyan
    $rawExportTime = Export-EventsToCsvWithProgress -Events $collection.Events.ToArray() -Path $rawPath -Activity "Raw export: $logName" -Phase "Raw export" -ExportType Raw
    Write-Status "$logName raw export completed in $(Format-Duration $rawExportTime)." Green

    if ($runMode -eq "Full") {
        foreach ($event in $collection.DfirEvents) {
            $allDfirEvents.Add($event)
        }
    }

    $logStats.Add([pscustomobject]@{
        LogName        = $logName
        EventCount     = $collection.Count
        DfirCount      = $collection.DfirEvents.Count
        CollectTime    = $collection.Duration
        RawExportTime  = $rawExportTime
        Status         = "Completed"
    })
}

$filteredPath = Join-Path $filteredFolder ("DFIR_KeyEvents_{0}.csv" -f $dateStamp)
$suspiciousPath = Join-Path $filteredFolder ("Suspicious_Processes_4688_{0}.csv" -f $dateStamp)
$dfirExportTime = [TimeSpan]::Zero
$suspiciousTime = [TimeSpan]::Zero

if ($runMode -eq "Full") {
    Write-Host ""
    Write-Status "DFIR filtering phase started. Priority event count: $($allDfirEvents.Count)" Cyan

    if ($allDfirEvents.Count -gt 0) {
        $dfirExportTime = Export-EventsToCsvWithProgress -Events $allDfirEvents.ToArray() -Path $filteredPath -Activity "DFIR filtering" -Phase "DFIR filtering" -ExportType Dfir
        Write-Status "DFIR filtered export completed in $(Format-Duration $dfirExportTime)." Green
    }
    else {
        $warningMessage = "No prioritized DFIR event IDs were found in the selected range."
        Write-Status $warningMessage Yellow
        $warningLines.Add($warningMessage)
    }

    $processEvents = @($allDfirEvents | Where-Object { $_.Id -eq 4688 })
    $processed = 0
    $suspiciousWatch = [System.Diagnostics.Stopwatch]::StartNew()

    Write-Status "Suspicious process analysis started for 4688 events." Cyan
    Show-Progress -Activity "Suspicious process analysis" -Status "Suspicious process analysis" -Processed 0 -Total $processEvents.Count -Elapsed $suspiciousWatch.Elapsed

    foreach ($event in $processEvents) {
        $processed++
        $eventData = Get-EventDataMap -Event $event
        $newProcessName = [string]$eventData["NewProcessName"]

        foreach ($processName in $suspiciousProcessNames) {
            if ($newProcessName -and $newProcessName.ToLowerInvariant().EndsWith($processName)) {
                $suspiciousHits.Add([pscustomobject]@{
                    TimeCreated     = $event.TimeCreated
                    EventId         = $event.Id
                    ProcessName     = $newProcessName
                    ParentProcess   = $eventData["ParentProcessName"]
                    SubjectUserName = $eventData["SubjectUserName"]
                    RecordId        = $event.RecordId
                    MachineName     = $event.MachineName
                })
            }
        }

        if (($processed -eq 1) -or ($processed -eq $processEvents.Count) -or (($processed % 250) -eq 0)) {
            Show-Progress -Activity "Suspicious process analysis" -Status "Suspicious process analysis" -Processed $processed -Total $processEvents.Count -Elapsed $suspiciousWatch.Elapsed
        }
    }

    $suspiciousWatch.Stop()
    $suspiciousTime = $suspiciousWatch.Elapsed
    Write-Progress -Activity "Suspicious process analysis" -Completed

    if ($suspiciousHits.Count -gt 0) {
        Write-Status "Suspicious process names found in 4688 events: $($suspiciousHits.Count)" Red
        $suspiciousHits | Export-Csv -Path $suspiciousPath -NoTypeInformation -Encoding UTF8
    }
    else {
        Write-Status "No suspicious process-name hits found in 4688 events." Green
    }
}

$summaryWatch = [System.Diagnostics.Stopwatch]::StartNew()
$summaryPath = Join-Path $summaryFolder ("DFIR_Summary_{0}.txt" -f $dateStamp)
Show-Progress -Activity "Summary generation" -Status "Summary generation" -Processed 0 -Total 1 -Elapsed $summaryWatch.Elapsed

$summaryLines.Add("Windows DFIR Offline Log Triage Summary")
$summaryLines.Add("Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
$summaryLines.Add("Computer: $env:COMPUTERNAME")
$summaryLines.Add("Run as Administrator: $isAdmin")
$summaryLines.Add("Mode: $runMode")
$summaryLines.Add("Date range: $($startDate.ToString('yyyy-MM-dd')) through $($endDate.ToString('yyyy-MM-dd'))")
$summaryLines.Add("Total elapsed time: $(Format-Duration $scriptWatch.Elapsed)")
$summaryLines.Add("")
$summaryLines.Add("Output folders:")
$summaryLines.Add("Raw: $rawFolder")
$summaryLines.Add("Filtered: $filteredFolder")
$summaryLines.Add("Summary: $summaryFolder")
$summaryLines.Add("")
$summaryLines.Add("Per-log-source results:")

foreach ($stat in $logStats) {
    $summaryLines.Add("- $($stat.LogName): events=$($stat.EventCount), priority_events=$($stat.DfirCount), collection_time=$(Format-Duration $stat.CollectTime), export_time=$(Format-Duration $stat.RawExportTime), status=$($stat.Status)")
}

$summaryLines.Add("")
$summaryLines.Add("Prioritized DFIR event counts:")
foreach ($eventId in $dfirEventIds) {
    $summaryLines.Add("- $eventId ($($eventDescriptions[$eventId])): $($eventIdCounts[$eventId])")
}

$summaryLines.Add("")
if ($runMode -eq "Full") {
    $summaryLines.Add("Full DFIR analysis timings:")
    $summaryLines.Add("- DFIR filtering: $(Format-Duration $dfirExportTime)")
    $summaryLines.Add("- Suspicious process analysis: $(Format-Duration $suspiciousTime)")
    $summaryLines.Add("")
    $summaryLines.Add("Suspicious process hits:")

    if ($suspiciousHits.Count -gt 0) {
        foreach ($hit in $suspiciousHits) {
            $summaryLines.Add("- $($hit.TimeCreated) | $($hit.SubjectUserName) | $($hit.ProcessName) | Parent: $($hit.ParentProcess) | RecordId: $($hit.RecordId)")
        }
    }
    else {
        $summaryLines.Add("- None found")
    }
}
else {
    $summaryLines.Add("Raw-only mode note:")
    $summaryLines.Add("- Filtered output was not generated in this mode.")
}

$summaryLines.Add("")
$summaryLines.Add("Warnings:")
if ($warningLines.Count -gt 0) {
    foreach ($warning in $warningLines) {
        $summaryLines.Add("- $warning")
    }
}
else {
    $summaryLines.Add("- None")
}

$summaryLines.Add("")
$summaryLines.Add("Performance note:")
$summaryLines.Add("Raw export skips Message rendering and XML parsing for speed. Full DFIR mode performs deeper extraction only for priority event IDs.")
$summaryLines.Add("")
$summaryLines.Add("Analyst note:")
$summaryLines.Add("These exports are triage aids. Suspicious process names are not proof of compromise by themselves; correlate with parent process, user, host role, timestamps, and surrounding events.")

$summaryLines | Out-File -FilePath $summaryPath -Encoding UTF8
$summaryWatch.Stop()
Show-Progress -Activity "Summary generation" -Status "Summary generation" -Processed 1 -Total 1 -Elapsed $summaryWatch.Elapsed
Write-Progress -Activity "Summary generation" -Completed

$scriptWatch.Stop()
$completedWithWarnings = $warningLines.Count -gt 0
$finalStatusText = "Completed successfully"
$finalColor = [ConsoleColor]::Green

if ($completedWithWarnings) {
    $finalStatusText = "Completed with warnings"
    $finalColor = [ConsoleColor]::Yellow
}

Write-Host ""
Write-Host "===============================================" -ForegroundColor $finalColor
Write-Host " $finalStatusText" -ForegroundColor $finalColor
Write-Host "===============================================" -ForegroundColor $finalColor
Write-Host "Mode:          $runMode" -ForegroundColor Cyan
Write-Host "Elapsed time:  $(Format-Duration $scriptWatch.Elapsed)" -ForegroundColor Cyan
Write-Host "Raw logs:      $rawFolder" -ForegroundColor Cyan
Write-Host "Filtered CSVs: $filteredFolder" -ForegroundColor Cyan
Write-Host "Summary file:  $summaryPath" -ForegroundColor Cyan

if ($completedWithWarnings) {
    Write-Host ""
    Write-Host "Warnings:" -ForegroundColor Yellow
    foreach ($warning in $warningLines) {
        Write-Host "- $warning" -ForegroundColor Yellow
    }
}

Write-Host ""
Read-Host "Press Enter to exit"
