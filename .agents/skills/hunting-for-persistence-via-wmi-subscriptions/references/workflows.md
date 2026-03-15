# Detailed Hunting Workflow - WMI Subscription Persistence

## Phase 1: Enumerate Existing Subscriptions

### Step 1.1 - PowerShell Enumeration
```powershell
# List all event filters
Get-WMIObject -Namespace root\Subscription -Class __EventFilter | Select-Object Name, Query, QueryLanguage

# List all event consumers
Get-WMIObject -Namespace root\Subscription -Class __EventConsumer | Select-Object Name, __CLASS

# List all bindings
Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding | Select-Object Filter, Consumer

# Detailed ActiveScriptEventConsumer inspection
Get-WMIObject -Namespace root\Subscription -Class ActiveScriptEventConsumer | Select-Object Name, ScriptingEngine, ScriptText

# Detailed CommandLineEventConsumer inspection
Get-WMIObject -Namespace root\Subscription -Class CommandLineEventConsumer | Select-Object Name, ExecutablePath, CommandLineTemplate
```

### Step 1.2 - WMIC Enumeration
```cmd
wmic /namespace:\\root\subscription path __EventFilter get Name, Query
wmic /namespace:\\root\subscription path __EventConsumer get Name, __CLASS
wmic /namespace:\\root\subscription path __FilterToConsumerBinding get Filter, Consumer
```

## Phase 2: Monitor Creation Events

### Step 2.1 - Sysmon WMI Event Detection
```spl
index=sysmon (EventCode=19 OR EventCode=20 OR EventCode=21)
| eval event_type=case(
    EventCode=19, "EventFilter Created",
    EventCode=20, "EventConsumer Created",
    EventCode=21, "Binding Created"
)
| table _time Computer User event_type Name Query Consumer Destination
```

### Step 2.2 - Windows WMI Activity Log
```spl
index=wineventlog source="Microsoft-Windows-WMI-Activity/Operational"
| where EventCode IN (5857, 5858, 5859, 5860, 5861)
| table _time Computer EventCode NamespaceName Query Operation PossibleCause
```

## Phase 3: Hunt for WmiPrvSe.exe Suspicious Children

### Step 3.1 - Process Tree Analysis
```spl
index=sysmon EventCode=1
| where match(ParentImage, "(?i)WmiPrvSe\.exe$")
| where match(Image, "(?i)(cmd|powershell|wscript|cscript|mshta|rundll32|regsvr32)\.exe$")
| table _time Computer Image CommandLine User ParentImage
```

### Step 3.2 - MOF Compilation Detection
```spl
index=sysmon EventCode=1 Image="*\\mofcomp.exe"
| table _time Computer User CommandLine ParentImage
```

## Phase 4: Removal and Cleanup

### Step 4.1 - Remove Malicious Subscription
```powershell
# Remove specific subscription components
Get-WMIObject -Namespace root\Subscription -Class __EventFilter -Filter "Name='MaliciousFilter'" | Remove-WmiObject
Get-WMIObject -Namespace root\Subscription -Class CommandLineEventConsumer -Filter "Name='MaliciousConsumer'" | Remove-WmiObject
Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding -Filter "Filter=""__EventFilter.Name='MaliciousFilter'""" | Remove-WmiObject
```

## Phase 5: Response
1. Document all found subscriptions with full details
2. Remove malicious subscriptions from all affected hosts
3. Block WMI subscription creation via Group Policy where possible
4. Deploy ongoing monitoring via Sysmon Events 19/20/21
5. Investigate initial infection vector that created the subscription
