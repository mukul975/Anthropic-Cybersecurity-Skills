# Detailed Hunting Workflow - Suspicious Scheduled Tasks

## Phase 1: Task Enumeration
```powershell
# Full task export with details
Get-ScheduledTask | Where-Object { $_.TaskPath -notmatch "\\Microsoft\\" } |
    ForEach-Object { $_ | Get-ScheduledTaskInfo; $_.Actions | Select-Object Execute, Arguments }

# Check for hidden tasks in registry
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree" -Recurse
```

## Phase 2: SIEM Analysis
```spl
index=wineventlog EventCode=4698
| spath output=TaskName path=EventData.TaskName
| spath output=TaskContent path=EventData.TaskContent
| rex field=TaskContent "<Command>(?<cmd>[^<]+)</Command>"
| rex field=TaskContent "<Arguments>(?<args>[^<]+)</Arguments>"
| table _time Computer SubjectUserName TaskName cmd args
```

## Phase 3: Remote Task Creation Detection
```spl
index=sysmon EventCode=1 Image="*\\schtasks.exe"
| where match(CommandLine, "(?i)/create.*/s\s+")
| rex field=CommandLine "/s\s+(?<remote_host>\S+)"
| table _time Computer User remote_host CommandLine
```

## Phase 4: Response
1. Remove malicious scheduled tasks
2. Check task XML definitions for hidden parameters
3. Audit all non-Microsoft scheduled tasks across fleet
4. Deploy detection rules for suspicious task creation
