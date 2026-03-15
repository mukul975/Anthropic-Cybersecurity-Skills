# Workflows - OT Network Security Assessment

## Assessment Lifecycle

```
Phase 1: Scoping          Phase 2: Discovery       Phase 3: Analysis
+-----------------+       +-----------------+      +-----------------+
| Define scope    |       | Passive capture |      | Protocol review |
| Safety limits   | ----> | Asset inventory | ---> | Zone evaluation |
| Authorization   |       | Traffic mapping |      | Firewall audit  |
+-----------------+       +-----------------+      +-----------------+
                                                          |
Phase 6: Verify           Phase 5: Remediate       Phase 4: Report
+-----------------+       +-----------------+      +-----------------+
| Validate fixes  |       | Segmentation    |      | Risk scoring    |
| Re-assessment   | <---- | FW rule changes | <--- | Finding detail  |
| Compliance map  |       | Protocol harden |      | Prioritization  |
+-----------------+       +-----------------+      +-----------------+
```

## Phase 1: Scoping and Authorization

### Inputs
- Facility type and industry vertical
- Regulatory requirements (NERC CIP, IEC 62443, NIST CSF)
- Existing network diagrams and asset inventories
- Maintenance window schedules

### Activities
1. Meet with operations, engineering, and IT security teams
2. Define Purdue levels in scope and safety-critical exclusions
3. Obtain written authorization specifying permitted assessment activities
4. Identify SPAN/TAP points for passive monitoring deployment
5. Review prior assessment reports and known issues

### Outputs
- Signed Rules of Engagement document
- Assessment scope matrix (Purdue levels vs. activity types)
- SPAN/TAP deployment plan
- Emergency contact list and escalation procedures

## Phase 2: Passive Network Discovery

### Inputs
- SPAN port access on OT network switches
- Assessment scope document

### Activities
1. Deploy passive monitoring sensors on SPAN ports at each Purdue level boundary
2. Capture network traffic for minimum 2 weeks to observe full operational cycle
3. Build asset inventory from observed traffic (MAC, IP, protocols, firmware versions)
4. Map all communication flows with source, destination, protocol, and frequency
5. Identify industrial protocols in use (Modbus, DNP3, OPC UA, EtherNet/IP, S7comm)
6. Detect unauthorized devices and rogue connections

### Activities - Wireless Assessment
1. Scan for wireless access points in OT areas using spectrum analyzer
2. Identify wireless industrial protocols (WirelessHART, ISA100.11a, Zigbee)
3. Check for unauthorized Wi-Fi networks bridging IT and OT

### Outputs
- Complete asset inventory with Purdue level classification
- Network communication flow map
- Protocol distribution analysis
- Unauthorized device/connection list

## Phase 3: Analysis and Evaluation

### Inputs
- Asset inventory and traffic capture data
- Firewall rule exports
- Network architecture diagrams

### Activities
1. Evaluate zone architecture against IEC 62443-3-2 requirements
2. Analyze firewall rules for overly permissive or prohibited conduits
3. Assess industrial protocol security (authentication, encryption, access controls)
4. Review remote access architecture and authentication mechanisms
5. Evaluate patch levels of HMI, engineering workstations, and servers
6. Check for known vulnerabilities in discovered OT firmware versions
7. Assess physical security of network equipment in field locations

### Outputs
- Finding list with severity ratings
- Gap analysis against applicable standards
- Risk matrix mapping findings to operational/safety impact

## Phase 4: Reporting

### Report Structure
1. Executive Summary (1 page)
2. Scope and Methodology
3. Asset Inventory Summary
4. Network Architecture Assessment
5. Detailed Findings (Critical/High/Medium/Low)
6. Compliance Gap Analysis
7. Remediation Roadmap with Prioritization
8. Appendices (asset inventory, network diagrams, tool output)

## Phase 5: Remediation Support

### Priority Order
1. **Immediate**: Block unauthorized cross-zone paths (enterprise to field devices)
2. **30-day**: Implement DMZ between corporate IT and OT operations
3. **60-day**: Deploy industrial protocol-aware firewalls between zones
4. **90-day**: Harden remote access with MFA and jump servers
5. **6-month**: Full zone/conduit segmentation per IEC 62443 design

## Risk Scoring for OT Environments

OT risk scoring must account for safety impact beyond traditional CIA triad:

| Factor | Weight | Description |
|--------|--------|-------------|
| Safety Impact | 30% | Potential for physical harm to personnel or public |
| Operational Impact | 25% | Production disruption or equipment damage |
| Environmental Impact | 15% | Release of hazardous materials |
| Financial Impact | 15% | Direct costs and regulatory penalties |
| Reputational Impact | 15% | Public trust and regulatory scrutiny |
