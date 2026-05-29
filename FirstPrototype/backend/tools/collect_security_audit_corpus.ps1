param(
    [string]$OutputDir = "D:\FAKI\SecurityAuditNormalCorpus",
    [int]$ExerciseSeconds = 20,
    [switch]$KeepAuditPolicy
)

$ErrorActionPreference = "Stop"

function Test-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    throw "Run this script from an elevated PowerShell session. Security log export and auditpol changes require Administrator."
}

$targetIds = @(4661, 5140, 5145, 5156, 5158, 4624, 4672, 4776, 1102)
$subcategories = @(
    "Filtering Platform Connection",
    "Filtering Platform Packet Drop",
    "File Share",
    "Detailed File Share",
    "File System",
    "Kernel Object",
    "SAM",
    "Logon",
    "Special Logon",
    "Credential Validation"
)

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$start = Get-Date
$startUtc = $start.ToUniversalTime().ToString("o")
$policyBefore = Join-Path $OutputDir "auditpol_before.txt"
$policyAfter = Join-Path $OutputDir "auditpol_after.txt"
$csvPath = Join-Path $OutputDir "security_audit_normal.csv"
$evtxPath = Join-Path $OutputDir "security_audit_normal.evtx"
$summaryPath = Join-Path $OutputDir "security_audit_normal_summary.txt"
$workDir = Join-Path $OutputDir "benign_activity"
$shareName = "CodexAuditCorpus"

auditpol /get /category:* | Out-File -Encoding utf8 $policyBefore

try {
    foreach ($subcategory in $subcategories) {
        auditpol /set /subcategory:"$subcategory" /success:enable /failure:disable | Out-Null
    }
    auditpol /get /category:* | Out-File -Encoding utf8 $policyAfter

    New-Item -ItemType Directory -Force -Path $workDir | Out-Null
    1..20 | ForEach-Object {
        $file = Join-Path $workDir "normal_file_$_.txt"
        "normal security audit corpus $_ $(Get-Date -Format o)" | Set-Content -Encoding utf8 $file
        Get-Content $file | Out-Null
    }

    try {
        if (-not (Get-SmbShare -Name $shareName -ErrorAction SilentlyContinue)) {
            New-SmbShare -Name $shareName -Path $workDir -FullAccess $env:USERNAME | Out-Null
        }
        Get-ChildItem "\\localhost\$shareName" -ErrorAction SilentlyContinue | Out-Null
        Copy-Item (Join-Path $workDir "normal_file_1.txt") "\\localhost\$shareName\normal_file_copy.txt" -Force -ErrorAction SilentlyContinue
    } catch {
        "SMB exercise skipped: $($_.Exception.Message)" | Out-File -Append -Encoding utf8 $summaryPath
    }

    whoami /groups | Out-Null
    net localgroup Administrators | Out-Null

    try {
        $client = [Net.Sockets.TcpClient]::new()
        $async = $client.BeginConnect("127.0.0.1", 445, $null, $null)
        $async.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds(2)) | Out-Null
        if ($client.Connected) {
            $client.EndConnect($async)
        }
        $client.Close()
    } catch {
        "TCP exercise skipped: $($_.Exception.Message)" | Out-File -Append -Encoding utf8 $summaryPath
    }

    Start-Sleep -Seconds $ExerciseSeconds

    $events = Get-WinEvent -FilterHashtable @{
        LogName = "Security"
        Id = $targetIds
        StartTime = $start
    } -ErrorAction SilentlyContinue

    $events |
        Select-Object TimeCreated, Id, ProviderName, LogName, MachineName, Message |
        Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

    $idQuery = ($targetIds | ForEach-Object { "EventID=$_"} ) -join " or "
    $query = "*[System[TimeCreated[@SystemTime>='$startUtc'] and ($idQuery)]]"
    wevtutil epl Security "$evtxPath" /q:"$query"

    $events |
        Group-Object Id |
        Sort-Object Name |
        ForEach-Object { "$($_.Name): $($_.Count)" } |
        Out-File -Append -Encoding utf8 $summaryPath

    "EVTX: $evtxPath" | Out-File -Append -Encoding utf8 $summaryPath
    "CSV: $csvPath" | Out-File -Append -Encoding utf8 $summaryPath
} finally {
    try {
        if (Get-SmbShare -Name $shareName -ErrorAction SilentlyContinue) {
            Remove-SmbShare -Name $shareName -Force
        }
    } catch {}

    if (-not $KeepAuditPolicy) {
        foreach ($subcategory in $subcategories) {
            auditpol /set /subcategory:"$subcategory" /success:disable /failure:disable | Out-Null
        }
    }
}
