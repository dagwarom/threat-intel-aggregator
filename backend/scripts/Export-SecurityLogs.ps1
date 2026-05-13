param(
    [Parameter(Mandatory = $true)]
    [datetime]$Start,

    [Parameter(Mandatory = $true)]
    [datetime]$End,

    [Parameter(Mandatory = $false)]
    [string]$OutFile = ".\security-audit.csv"
)

if ($End -lt $Start) {
    throw "End date must be greater than or equal to Start date."
}

$filter = @{
    LogName   = "Security"
    StartTime = $Start
    EndTime   = $End
}

Get-WinEvent -FilterHashtable $filter |
    Select-Object `
        TimeCreated,
        Id,
        ProviderName,
        LevelDisplayName,
        MachineName,
        UserId,
        RecordId,
        Message |
    Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8

Write-Host "Exported Windows Security events to $OutFile"
