# SIEM Detection Queries and Continuous Testing Pipeline

## Step 4 detail: SIEM detection-validation queries

Query your SIEM to confirm whether atomic tests generated alerts.

```
Splunk SPL Queries for Detection Validation:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

-- T1059.001: PowerShell Execution
index=windows sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational"
  EventCode=4104
  | eval script_block=ScriptBlockText
  | where len(script_block) > 500
  | stats count by host, script_block
  | sort -count

-- T1003.001: LSASS Memory Credential Dumping
index=windows sourcetype="WinEventLog:Security" EventCode=4663
  ObjectName="*lsass*"
  | stats count by host, SubjectUserName, ProcessName
  | where count > 0

-- T1547.001: Registry Run Key Persistence
index=windows sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"
  EventCode=13
  TargetObject="*\\CurrentVersion\\Run*"
  | stats count by host, Image, TargetObject, Details

-- T1053.005: Scheduled Task Creation
index=windows sourcetype="WinEventLog:Security" EventCode=4698
  | stats count by host, SubjectUserName, TaskName, TaskContent
  | sort -count

-- Generic: Hunt for Atomic Red Team artifacts
index=windows (sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"
  OR sourcetype="WinEventLog:Security")
  | search "*AtomicRedTeam*" OR "*atomic*" OR "*Invoke-AtomicTest*"
  | stats count by sourcetype, EventCode, host
```

```
Elastic / KQL Queries:
━━━━━━━━━━━━━━━━━━━━━

-- PowerShell script block logging
event.code: "4104" and powershell.file.script_block_text: *

-- Sysmon process creation from AtomicRedTeam paths
event.code: "1" and process.executable: *AtomicRedTeam*

-- Registry modification (persistence)
event.code: "13" and registry.path: *CurrentVersion\\Run*

-- Credential access indicators
event.code: "10" and winlog.event_data.TargetImage: *lsass.exe*
```

## Step 6 detail: continuous atomic testing pipeline

Schedule recurring tests against priority techniques (Windows Task Scheduler or CI/CD).

```powershell
# Continuous Atomic Testing - scheduled execution with validation
# Run as a scheduled task or via CI/CD pipeline

$PriorityTechniques = @(
    # Top MITRE ATT&CK techniques by prevalence (Red Canary Threat Detection Report)
    @{ Id = "T1059.001"; Name = "PowerShell" },
    @{ Id = "T1059.003"; Name = "Windows Command Shell" },
    @{ Id = "T1547.001"; Name = "Registry Run Keys" },
    @{ Id = "T1053.005"; Name = "Scheduled Task" },
    @{ Id = "T1003.001"; Name = "LSASS Memory" },
    @{ Id = "T1003.003"; Name = "NTDS" },
    @{ Id = "T1070.004"; Name = "File Deletion" },
    @{ Id = "T1218.011"; Name = "Rundll32" },
    @{ Id = "T1082";     Name = "System Information Discovery" },
    @{ Id = "T1105";     Name = "Ingress Tool Transfer" }
)

$ResultsLog = @()
$RunTimestamp = Get-Date -Format "yyyyMMdd_HHmmss"

foreach ($technique in $PriorityTechniques) {
    Write-Host "`n[*] Testing $($technique.Id) - $($technique.Name)" -ForegroundColor Cyan

    # Check prerequisites
    try {
        $prereqs = Invoke-AtomicTest $technique.Id -TestNumbers 1 -CheckPrereqs 2>&1
        $prereqsMet = $prereqs -notmatch "not met"
    } catch {
        $prereqsMet = $false
    }

    if (-not $prereqsMet) {
        Write-Host "    [!] Prerequisites not met, attempting install..." -ForegroundColor Yellow
        try {
            Invoke-AtomicTest $technique.Id -TestNumbers 1 -GetPrereqs 2>&1 | Out-Null
        } catch {
            Write-Host "    [!] Prereq install failed, skipping" -ForegroundColor Red
            $ResultsLog += [PSCustomObject]@{
                TechniqueId = $technique.Id
                Name        = $technique.Name
                Status      = "PREREQS_FAILED"
                Timestamp   = (Get-Date).ToString("o")
            }
            continue
        }
    }

    # Execute the test
    try {
        $startTime = Get-Date
        Invoke-AtomicTest $technique.Id -TestNumbers 1 -Confirm:$false
        $endTime = Get-Date
        $duration = ($endTime - $startTime).TotalSeconds

        Write-Host "    [+] Executed successfully (${duration}s)" -ForegroundColor Green

        $ResultsLog += [PSCustomObject]@{
            TechniqueId = $technique.Id
            Name        = $technique.Name
            Status      = "EXECUTED"
            Duration    = $duration
            Timestamp   = $startTime.ToString("o")
        }
    } catch {
        Write-Host "    [-] Execution failed: $($_.Exception.Message)" -ForegroundColor Red
        $ResultsLog += [PSCustomObject]@{
            TechniqueId = $technique.Id
            Name        = $technique.Name
            Status      = "FAILED"
            Error       = $_.Exception.Message
            Timestamp   = (Get-Date).ToString("o")
        }
    }

    # Cleanup
    try {
        Invoke-AtomicTest $technique.Id -TestNumbers 1 -Cleanup 2>&1 | Out-Null
        Write-Host "    [+] Cleanup completed" -ForegroundColor DarkGray
    } catch {
        Write-Host "    [!] Cleanup failed" -ForegroundColor Yellow
    }

    # Brief pause between tests for log ingestion
    Start-Sleep -Seconds 10
}

# Export results
$ResultsLog | Export-Csv "C:\AtomicRedTeam\logs\continuous_test_$RunTimestamp.csv" -NoTypeInformation
$ResultsLog | Format-Table -AutoSize

# Summary
$executed = ($ResultsLog | Where-Object Status -eq "EXECUTED").Count
$failed = ($ResultsLog | Where-Object Status -ne "EXECUTED").Count
Write-Host "`n=== CONTINUOUS TEST SUMMARY ===" -ForegroundColor Cyan
Write-Host "  Executed: $executed / $($PriorityTechniques.Count)" -ForegroundColor Green
Write-Host "  Failed:   $failed / $($PriorityTechniques.Count)" -ForegroundColor Red
```

