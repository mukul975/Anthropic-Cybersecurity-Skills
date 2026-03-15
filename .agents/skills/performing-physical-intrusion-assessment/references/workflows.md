# Workflows: Physical Intrusion Assessment

## Assessment Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│           PHYSICAL INTRUSION ASSESSMENT WORKFLOW                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. RECONNAISSANCE (Day 1-2)                                     │
│     ├── External perimeter survey                                │
│     ├── Entry/exit point mapping                                 │
│     ├── Camera placement analysis                                │
│     ├── Guard patrol timing                                      │
│     ├── Employee behavior observation                            │
│     ├── Badge technology identification                          │
│     └── Loading dock / service entrance survey                   │
│                                                                  │
│  2. BADGE CAPTURE (Day 2-3)                                      │
│     ├── Position near badge readers / elevators                  │
│     ├── Capture RFID data from passing employees                 │
│     ├── Clone to blank cards                                     │
│     └── Test cloned badges on external readers first             │
│                                                                  │
│  3. INTRUSION ATTEMPTS (Day 3-5)                                 │
│     ├── Tailgating through main entrance                         │
│     ├── Badge cloning at restricted doors                        │
│     ├── Lock bypass on server room / network closet              │
│     ├── Social engineering at reception                          │
│     ├── Loading dock / service entrance access                   │
│     └── After-hours access attempts                              │
│                                                                  │
│  4. INTERNAL OBJECTIVES (Day 4-5)                                │
│     ├── Access server room / data center                         │
│     ├── Deploy rogue network device                              │
│     ├── Access unlocked workstations                             │
│     ├── Plug in USB device to exposed port                       │
│     ├── Photograph sensitive documents on desks                  │
│     └── Test dumpster diving                                     │
│                                                                  │
│  5. REPORTING (Day 6-7)                                          │
│     ├── Document all access attempts with evidence               │
│     ├── Map successful paths on facility diagram                 │
│     ├── Provide remediation for each finding                     │
│     └── Present findings to security team                        │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Entry Point Decision Tree

```
Select Entry Point
│
├── Main Entrance
│   ├── Tailgate during shift change
│   ├── Social engineer past reception
│   └── Use cloned badge at turnstile
│
├── Side/Emergency Doors
│   ├── Check for propped doors
│   ├── Use under-door tool on push-bar
│   └── Badge clone if reader present
│
├── Loading Dock
│   ├── Impersonate delivery driver
│   ├── Follow truck into dock area
│   └── Access internal doors from dock
│
├── Parking Garage
│   ├── Tailgate vehicle through gate
│   ├── Access stairwells to building
│   └── Check for unlocked access doors
│
└── Smoking Area
    ├── Wait for employees on break
    ├── Build rapport during conversation
    └── Follow group back inside
```
