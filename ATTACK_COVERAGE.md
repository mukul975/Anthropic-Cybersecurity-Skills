# MITRE ATT&CK Coverage Map

<p align="center">
  <a href="https://attack.mitre.org/"><img src="https://img.shields.io/badge/MITRE_ATT%26CK-v16-red?style=for-the-badge&logo=shield&logoColor=white" alt="MITRE ATT&CK" /></a>
  <img src="https://img.shields.io/badge/Techniques-291+-blueviolet?style=for-the-badge" alt="Techniques" />
  <img src="https://img.shields.io/badge/Tactics-14%2F14-green?style=for-the-badge" alt="Tactics" />
</p>

This document maps all **291 unique MITRE ATT&CK techniques** (across **149 parent techniques**) referenced in our **753+ cybersecurity skills** to the 14 Enterprise ATT&CK tactics. Use this to identify coverage gaps, plan detection engineering priorities, or validate your security program against the ATT&CK framework.

> **How to read this:** Each technique links to its official ATT&CK page. Skills listed under each technique are the ones in this repository that teach detection, hunting, exploitation, or response for that technique.

---

## Coverage Summary

| Tactic | Techniques | Coverage |
|:-------|:---------:|:---------|
| 🔎 **Reconnaissance** | **12** | `████████████░░░░░░░░░░░░░░░░░░` |
| 🏗️ **Resource Development** | **7** | `███████░░░░░░░░░░░░░░░░░░░░░░░` |
| 🚪 **Initial Access** | **18** | `██████████████████░░░░░░░░░░░░` |
| ⚡ **Execution** | **18** | `██████████████████░░░░░░░░░░░░` |
| 🔩 **Persistence** | **36** | `██████████████████████████████` |
| ⬆️ **Privilege Escalation** | **11** | `███████████░░░░░░░░░░░░░░░░░░░` |
| 🥷 **Defense Evasion** | **48** | `██████████████████████████████` |
| 🔑 **Credential Access** | **27** | `███████████████████████████░░░` |
| 🗺️ **Discovery** | **20** | `████████████████████░░░░░░░░░░` |
| ↔️ **Lateral Movement** | **9** | `█████████░░░░░░░░░░░░░░░░░░░░░` |
| 📦 **Collection** | **13** | `█████████████░░░░░░░░░░░░░░░░░` |
| 📡 **Command and Control** | **20** | `████████████████████░░░░░░░░░░` |
| 📤 **Exfiltration** | **12** | `████████████░░░░░░░░░░░░░░░░░░` |
| 💥 **Impact** | **6** | `██████░░░░░░░░░░░░░░░░░░░░░░░░` |
| 🔧 **Other/Cross-tactic** | **34** | |
| | **291** | **Total unique techniques** |

---

## 🔎 Reconnaissance

**12 techniques covered**

| Technique | Skills |
|:----------|:-------|
| [T1589](https://attack.mitre.org/techniques/T1589/) | `conducting-full-scope-red-team-engagement`, `conducting-social-engineering-pretext-call`, `performing-open-source-intelligence-gathering` |
| [T1590](https://attack.mitre.org/techniques/T1590/) | `performing-open-source-intelligence-gathering` |
| [T1591](https://attack.mitre.org/techniques/T1591/) | `collecting-open-source-intelligence`, `conducting-social-engineering-pretext-call`, `performing-open-source-intelligence-gathering` |
| [T1592](https://attack.mitre.org/techniques/T1592/) | `performing-open-source-intelligence-gathering` |
| [T1593](https://attack.mitre.org/techniques/T1593/) | `conducting-full-scope-red-team-engagement`, `performing-open-source-intelligence-gathering` |
| [T1594](https://attack.mitre.org/techniques/T1594/) | `performing-open-source-intelligence-gathering` |
| [T1595](https://attack.mitre.org/techniques/T1595/) | `executing-red-team-engagement-planning`, `triaging-security-incident` |
| [T1595.001](https://attack.mitre.org/techniques/T1595/001/) | `performing-open-source-intelligence-gathering` |
| [T1595.002](https://attack.mitre.org/techniques/T1595/002/) | `performing-open-source-intelligence-gathering` |
| [T1596](https://attack.mitre.org/techniques/T1596/) | `performing-open-source-intelligence-gathering` |
| [T1598](https://attack.mitre.org/techniques/T1598/) | `conducting-social-engineering-pretext-call` |
| [T1598.003](https://attack.mitre.org/techniques/T1598/003/) | `conducting-social-engineering-pretext-call`, `conducting-spearphishing-simulation-campaign` |

---

## 🏗️ Resource Development

**7 techniques covered**

| Technique | Skills |
|:----------|:-------|
| [T1583.001](https://attack.mitre.org/techniques/T1583/001/) | `building-red-team-c2-infrastructure-with-havoc`, `conducting-full-scope-red-team-engagement`, `conducting-spearphishing-simulation-campaign`, `implementing-mitre-attack-coverage-mapping` |
| [T1583.003](https://attack.mitre.org/techniques/T1583/003/) | `building-red-team-c2-infrastructure-with-havoc` |
| [T1584.001](https://attack.mitre.org/techniques/T1584/001/) | `hunting-for-dns-based-persistence` |
| [T1585.002](https://attack.mitre.org/techniques/T1585/002/) | `conducting-spearphishing-simulation-campaign` |
| [T1587.001](https://attack.mitre.org/techniques/T1587/001/) | `building-red-team-c2-infrastructure-with-havoc`, `conducting-full-scope-red-team-engagement` |
| [T1608.001](https://attack.mitre.org/techniques/T1608/001/) | `conducting-spearphishing-simulation-campaign` |
| [T1608.005](https://attack.mitre.org/techniques/T1608/005/) | `conducting-spearphishing-simulation-campaign` |

---

## 🚪 Initial Access

**18 techniques covered**

| Technique | Skills |
|:----------|:-------|
| [T1078](https://attack.mitre.org/techniques/T1078/) | `analyzing-apt-group-with-mitre-navigator`, `analyzing-powershell-script-block-logging`, `analyzing-windows-event-logs-in-splunk`, `building-threat-hunt-hypothesis-framework`, `conducting-full-scope-red-team-engagement` +13 more |
| [T1078.001](https://attack.mitre.org/techniques/T1078/001/) | `detecting-service-account-abuse` |
| [T1078.002](https://attack.mitre.org/techniques/T1078/002/) | `conducting-domain-persistence-with-dcsync`, `detecting-service-account-abuse`, `exploiting-active-directory-certificate-services-esc1`, `exploiting-constrained-delegation-abuse`, `exploiting-nopac-cve-2021-42278-42287` +1 more |
| [T1078.003](https://attack.mitre.org/techniques/T1078/003/) | `performing-privilege-escalation-assessment` |
| [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | `detecting-azure-lateral-movement`, `detecting-azure-service-principal-abuse`, `implementing-mitre-attack-coverage-mapping`, `implementing-threat-modeling-with-mitre-attack` |
| [T1091](https://attack.mitre.org/techniques/T1091/) | `executing-red-team-engagement-planning`, `performing-physical-intrusion-assessment` |
| [T1133](https://attack.mitre.org/techniques/T1133/) | `executing-red-team-engagement-planning`, `performing-threat-landscape-assessment-for-sector` |
| [T1190](https://attack.mitre.org/techniques/T1190/) | `conducting-full-scope-red-team-engagement`, `executing-red-team-engagement-planning`, `exploiting-ms17-010-eternalblue-vulnerability`, `hunting-for-webshell-activity`, `performing-threat-landscape-assessment-for-sector` +1 more |
| [T1195](https://attack.mitre.org/techniques/T1195/) | `analyzing-supply-chain-malware-artifacts`, `performing-threat-landscape-assessment-for-sector` |
| [T1195.001](https://attack.mitre.org/techniques/T1195/001/) | `hunting-for-supply-chain-compromise` |
| [T1195.002](https://attack.mitre.org/techniques/T1195/002/) | `hunting-for-supply-chain-compromise` |
| [T1199](https://attack.mitre.org/techniques/T1199/) | `hunting-for-supply-chain-compromise`, `performing-physical-intrusion-assessment` |
| [T1200](https://attack.mitre.org/techniques/T1200/) | `executing-red-team-engagement-planning`, `performing-physical-intrusion-assessment` |
| [T1566](https://attack.mitre.org/techniques/T1566/) | `analyzing-apt-group-with-mitre-navigator`, `analyzing-threat-actor-ttps-with-mitre-attack`, `analyzing-threat-landscape-with-misp`, `building-attack-pattern-library-from-cti-reports`, `hunting-advanced-persistent-threats` +3 more |
| [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | `analyzing-apt-group-with-mitre-navigator`, `analyzing-campaign-attribution-evidence`, `analyzing-macro-malware-in-office-documents`, `analyzing-threat-actor-ttps-with-mitre-navigator`, `building-attack-pattern-library-from-cti-reports` +13 more |
| [T1566.002](https://attack.mitre.org/techniques/T1566/002/) | `building-attack-pattern-library-from-cti-reports`, `conducting-spearphishing-simulation-campaign`, `hunting-for-spearphishing-indicators`, `implementing-continuous-security-validation-with-bas`, `implementing-mitre-attack-coverage-mapping` +1 more |
| [T1566.003](https://attack.mitre.org/techniques/T1566/003/) | `conducting-spearphishing-simulation-campaign`, `hunting-for-spearphishing-indicators`, `implementing-continuous-security-validation-with-bas` |
| [T1566.004](https://attack.mitre.org/techniques/T1566/004/) | `conducting-social-engineering-pretext-call` |

---

## ⚡ Execution

**18 techniques covered**

| Technique | Skills |
|:----------|:-------|
| [T1047](https://attack.mitre.org/techniques/T1047/) | `conducting-full-scope-red-team-engagement`, `detecting-fileless-attacks-on-endpoints`, `detecting-lateral-movement-with-splunk`, `detecting-living-off-the-land-attacks`, `detecting-living-off-the-land-with-lolbas` +8 more |
| [T1053](https://attack.mitre.org/techniques/T1053/) | `analyzing-apt-group-with-mitre-navigator`, `analyzing-persistence-mechanisms-in-linux`, `hunting-advanced-persistent-threats`, `hunting-for-persistence-mechanisms-in-windows`, `implementing-mitre-attack-coverage-mapping` +4 more |
| [T1053.002](https://attack.mitre.org/techniques/T1053/002/) | `hunting-for-scheduled-task-persistence` |
| [T1053.003](https://attack.mitre.org/techniques/T1053/003/) | `analyzing-persistence-mechanisms-in-linux`, `hunting-for-scheduled-task-persistence`, `performing-privilege-escalation-assessment`, `performing-privilege-escalation-on-linux` |
| [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | `analyzing-apt-group-with-mitre-navigator`, `analyzing-campaign-attribution-evidence`, `analyzing-windows-event-logs-in-splunk`, `building-attack-pattern-library-from-cti-reports`, `building-detection-rule-with-splunk-spl` +17 more |
| [T1059](https://attack.mitre.org/techniques/T1059/) | `analyzing-apt-group-with-mitre-navigator`, `analyzing-threat-actor-ttps-with-mitre-attack`, `analyzing-windows-event-logs-in-splunk`, `building-incident-timeline-with-timesketch`, `deobfuscating-powershell-obfuscated-malware` +7 more |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | `analyzing-apt-group-with-mitre-navigator`, `analyzing-campaign-attribution-evidence`, `analyzing-macro-malware-in-office-documents`, `analyzing-powershell-empire-artifacts`, `analyzing-powershell-script-block-logging` +29 more |
| [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | `building-attack-pattern-library-from-cti-reports`, `building-detection-rule-with-splunk-spl`, `detecting-suspicious-powershell-execution`, `mapping-mitre-attack-techniques`, `performing-purple-team-atomic-testing` |
| [T1059.004](https://attack.mitre.org/techniques/T1059/004/) | `performing-purple-team-atomic-testing` |
| [T1059.005](https://attack.mitre.org/techniques/T1059/005/) | `analyzing-macro-malware-in-office-documents`, `detecting-living-off-the-land-attacks`, `executing-red-team-exercise`, `hunting-for-living-off-the-land-binaries`, `hunting-for-lolbins-execution-in-endpoint-logs` +2 more |
| [T1059.006](https://attack.mitre.org/techniques/T1059/006/) | `performing-purple-team-atomic-testing` |
| [T1059.007](https://attack.mitre.org/techniques/T1059/007/) | `performing-purple-team-atomic-testing` |
| [T1129](https://attack.mitre.org/techniques/T1129/) | `performing-purple-team-atomic-testing` |
| [T1203](https://attack.mitre.org/techniques/T1203/) | `performing-purple-team-atomic-testing` |
| [T1204.001](https://attack.mitre.org/techniques/T1204/001/) | `conducting-spearphishing-simulation-campaign` |
| [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | `analyzing-macro-malware-in-office-documents`, `conducting-full-scope-red-team-engagement`, `conducting-spearphishing-simulation-campaign`, `detecting-living-off-the-land-attacks`, `executing-red-team-engagement-planning` +4 more |
| [T1569](https://attack.mitre.org/techniques/T1569/) | `performing-purple-team-atomic-testing` |
| [T1569.002](https://attack.mitre.org/techniques/T1569/002/) | `detecting-lateral-movement-in-network`, `detecting-lateral-movement-with-splunk`, `exploiting-ms17-010-eternalblue-vulnerability`, `performing-purple-team-atomic-testing` |

---

## 🔩 Persistence

**36 techniques covered**

| Technique | Skills |
|:----------|:-------|
| [T1098](https://attack.mitre.org/techniques/T1098/) | `analyzing-windows-event-logs-in-splunk`, `conducting-domain-persistence-with-dcsync`, `hunting-for-t1098-account-manipulation`, `implementing-mitre-attack-coverage-mapping`, `implementing-siem-use-cases-for-detection` +1 more |
| [T1098.001](https://attack.mitre.org/techniques/T1098/001/) | `conducting-cloud-penetration-testing`, `detecting-azure-lateral-movement`, `detecting-azure-service-principal-abuse`, `hunting-for-t1098-account-manipulation`, `implementing-mitre-attack-coverage-mapping` |
| [T1098.002](https://attack.mitre.org/techniques/T1098/002/) | `detecting-azure-lateral-movement`, `detecting-email-forwarding-rules-attack` |
| [T1098.004](https://attack.mitre.org/techniques/T1098/004/) | `analyzing-persistence-mechanisms-in-linux`, `implementing-security-monitoring-with-datadog` |
| [T1136](https://attack.mitre.org/techniques/T1136/) | `detecting-privilege-escalation-in-kubernetes-pods`, `implementing-mitre-attack-coverage-mapping`, `performing-purple-team-atomic-testing` |
| [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | `analyzing-windows-event-logs-in-splunk`, `performing-purple-team-atomic-testing` |
| [T1136.002](https://attack.mitre.org/techniques/T1136/002/) | `exploiting-nopac-cve-2021-42278-42287` |
| [T1197](https://attack.mitre.org/techniques/T1197/) | `detecting-living-off-the-land-attacks`, `detecting-living-off-the-land-with-lolbas`, `hunting-for-living-off-the-land-binaries`, `hunting-for-lolbins-execution-in-endpoint-logs`, `performing-purple-team-atomic-testing` |
| [T1505](https://attack.mitre.org/techniques/T1505/) | `performing-purple-team-atomic-testing` |
| [T1505.003](https://attack.mitre.org/techniques/T1505/003/) | `building-attack-pattern-library-from-cti-reports`, `hunting-for-webshell-activity`, `performing-purple-team-atomic-testing` |
| [T1542.001](https://attack.mitre.org/techniques/T1542/001/) | `analyzing-uefi-bootkit-persistence` |
| [T1542.003](https://attack.mitre.org/techniques/T1542/003/) | `analyzing-uefi-bootkit-persistence` |
| [T1543](https://attack.mitre.org/techniques/T1543/) | `analyzing-persistence-mechanisms-in-linux`, `hunting-for-persistence-mechanisms-in-windows`, `performing-purple-team-atomic-testing` |
| [T1543.002](https://attack.mitre.org/techniques/T1543/002/) | `analyzing-persistence-mechanisms-in-linux`, `performing-privilege-escalation-on-linux` |
| [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | `detecting-lateral-movement-with-splunk`, `detecting-living-off-the-land-attacks`, `detecting-privilege-escalation-attempts`, `hunting-for-persistence-mechanisms-in-windows`, `hunting-for-unusual-service-installations` +2 more |
| [T1546](https://attack.mitre.org/techniques/T1546/) | `analyzing-persistence-mechanisms-in-linux`, `performing-purple-team-atomic-testing` |
| [T1546.001](https://attack.mitre.org/techniques/T1546/001/) | `performing-purple-team-atomic-testing` |
| [T1546.003](https://attack.mitre.org/techniques/T1546/003/) | `analyzing-windows-event-logs-in-splunk`, `detecting-fileless-attacks-on-endpoints`, `detecting-fileless-malware-techniques`, `detecting-wmi-persistence`, `hunting-for-lateral-movement-via-wmi` +3 more |
| [T1546.004](https://attack.mitre.org/techniques/T1546/004/) | `analyzing-persistence-mechanisms-in-linux` |
| [T1546.010](https://attack.mitre.org/techniques/T1546/010/) | `hunting-for-persistence-mechanisms-in-windows` |
| [T1546.012](https://attack.mitre.org/techniques/T1546/012/) | `hunting-for-persistence-mechanisms-in-windows`, `hunting-for-registry-persistence-mechanisms` |
| [T1546.015](https://attack.mitre.org/techniques/T1546/015/) | `hunting-for-persistence-mechanisms-in-windows`, `hunting-for-registry-persistence-mechanisms` |
| [T1547](https://attack.mitre.org/techniques/T1547/) | `analyzing-apt-group-with-mitre-navigator`, `analyzing-malware-persistence-with-autoruns`, `hunting-advanced-persistent-threats`, `hunting-for-persistence-mechanisms-in-windows`, `implementing-siem-use-cases-for-detection` +3 more |
| [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | `analyzing-apt-group-with-mitre-navigator`, `analyzing-windows-event-logs-in-splunk`, `building-attack-pattern-library-from-cti-reports`, `conducting-full-scope-red-team-engagement`, `detecting-fileless-attacks-on-endpoints` +10 more |
| [T1547.004](https://attack.mitre.org/techniques/T1547/004/) | `hunting-for-persistence-mechanisms-in-windows`, `hunting-for-registry-persistence-mechanisms`, `performing-purple-team-atomic-testing` |
| [T1547.005](https://attack.mitre.org/techniques/T1547/005/) | `hunting-for-persistence-mechanisms-in-windows` |
| [T1547.009](https://attack.mitre.org/techniques/T1547/009/) | `performing-purple-team-atomic-testing` |
| [T1556](https://attack.mitre.org/techniques/T1556/) | `performing-initial-access-with-evilginx3` |
| [T1556.007](https://attack.mitre.org/techniques/T1556/007/) | `detecting-azure-lateral-movement` |
| [T1574](https://attack.mitre.org/techniques/T1574/) | `analyzing-persistence-mechanisms-in-linux`, `performing-purple-team-atomic-testing` |
| [T1574.001](https://attack.mitre.org/techniques/T1574/001/) | `detecting-dll-sideloading-attacks`, `hunting-for-persistence-mechanisms-in-windows`, `performing-purple-team-atomic-testing` |
| [T1574.002](https://attack.mitre.org/techniques/T1574/002/) | `analyzing-windows-event-logs-in-splunk`, `building-attack-pattern-library-from-cti-reports`, `detecting-dll-sideloading-attacks`, `implementing-siem-use-cases-for-detection`, `performing-purple-team-atomic-testing` |
| [T1574.006](https://attack.mitre.org/techniques/T1574/006/) | `analyzing-persistence-mechanisms-in-linux`, `detecting-dll-sideloading-attacks`, `performing-privilege-escalation-on-linux` |
| [T1574.008](https://attack.mitre.org/techniques/T1574/008/) | `detecting-dll-sideloading-attacks` |
| [T1574.009](https://attack.mitre.org/techniques/T1574/009/) | `detecting-privilege-escalation-attempts` |
| [T1574.011](https://attack.mitre.org/techniques/T1574/011/) | `detecting-privilege-escalation-attempts` |

---

## ⬆️ Privilege Escalation

**11 techniques covered**

| Technique | Skills |
|:----------|:-------|
| [T1068](https://attack.mitre.org/techniques/T1068/) | `conducting-full-scope-red-team-engagement`, `detecting-container-escape-attempts`, `detecting-privilege-escalation-attempts`, `detecting-privilege-escalation-in-kubernetes-pods`, `executing-red-team-engagement-planning` +5 more |
| [T1134](https://attack.mitre.org/techniques/T1134/) | `analyzing-windows-event-logs-in-splunk`, `detecting-privilege-escalation-attempts` |
| [T1134.001](https://attack.mitre.org/techniques/T1134/001/) | `detecting-privilege-escalation-attempts`, `exploiting-constrained-delegation-abuse`, `performing-purple-team-atomic-testing` |
| [T1134.005](https://attack.mitre.org/techniques/T1134/005/) | `hunting-for-t1098-account-manipulation`, `performing-active-directory-compromise-investigation` |
| [T1484](https://attack.mitre.org/techniques/T1484/) | `exploiting-active-directory-certificate-services-esc1`, `performing-active-directory-vulnerability-assessment` |
| [T1484.001](https://attack.mitre.org/techniques/T1484/001/) | `deploying-active-directory-honeytokens`, `performing-active-directory-compromise-investigation` |
| [T1548](https://attack.mitre.org/techniques/T1548/) | `detecting-container-escape-attempts`, `detecting-privilege-escalation-in-kubernetes-pods`, `detecting-t1548-abuse-elevation-control-mechanism`, `performing-privilege-escalation-assessment` |
| [T1548.001](https://attack.mitre.org/techniques/T1548/001/) | `detecting-privilege-escalation-attempts`, `detecting-privilege-escalation-in-kubernetes-pods`, `detecting-t1548-abuse-elevation-control-mechanism`, `performing-privilege-escalation-assessment`, `performing-privilege-escalation-on-linux` |
| [T1548.002](https://attack.mitre.org/techniques/T1548/002/) | `conducting-full-scope-red-team-engagement`, `detecting-privilege-escalation-attempts`, `detecting-t1548-abuse-elevation-control-mechanism`, `performing-purple-team-atomic-testing` |
| [T1548.003](https://attack.mitre.org/techniques/T1548/003/) | `detecting-privilege-escalation-attempts`, `detecting-t1548-abuse-elevation-control-mechanism`, `performing-privilege-escalation-assessment`, `performing-privilege-escalation-on-linux` |
| [T1548.004](https://attack.mitre.org/techniques/T1548/004/) | `detecting-t1548-abuse-elevation-control-mechanism` |

---

## 🥷 Defense Evasion

**48 techniques covered**

| Technique | Skills |
|:----------|:-------|
| [T1027](https://attack.mitre.org/techniques/T1027/) | `analyzing-apt-group-with-mitre-navigator`, `analyzing-powershell-empire-artifacts`, `analyzing-powershell-script-block-logging`, `building-attack-pattern-library-from-cti-reports`, `conducting-full-scope-red-team-engagement` +3 more |
| [T1036](https://attack.mitre.org/techniques/T1036/) | `detecting-evasion-techniques-in-endpoint-logs`, `implementing-mitre-attack-coverage-mapping`, `implementing-siem-use-cases-for-detection`, `performing-purple-team-atomic-testing` |
| [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | `detecting-process-injection-techniques`, `performing-purple-team-atomic-testing` |
| [T1055](https://attack.mitre.org/techniques/T1055/) | `building-attack-pattern-library-from-cti-reports`, `building-red-team-c2-infrastructure-with-havoc`, `conducting-full-scope-red-team-engagement`, `detecting-evasion-techniques-in-endpoint-logs`, `detecting-fileless-attacks-on-endpoints` +13 more |
| [T1055.001](https://attack.mitre.org/techniques/T1055/001/) | `detecting-process-hollowing-technique`, `detecting-process-injection-techniques`, `detecting-t1055-process-injection-with-sysmon`, `hunting-for-process-injection-techniques`, `performing-purple-team-atomic-testing` +1 more |
| [T1055.002](https://attack.mitre.org/techniques/T1055/002/) | `detecting-process-injection-techniques`, `detecting-t1055-process-injection-with-sysmon` |
| [T1055.003](https://attack.mitre.org/techniques/T1055/003/) | `detecting-process-hollowing-technique`, `detecting-process-injection-techniques`, `detecting-t1055-process-injection-with-sysmon`, `performing-purple-team-atomic-testing` |
| [T1055.004](https://attack.mitre.org/techniques/T1055/004/) | `detecting-process-hollowing-technique`, `detecting-process-injection-techniques`, `detecting-t1055-process-injection-with-sysmon`, `hunting-for-process-injection-techniques` |
| [T1055.005](https://attack.mitre.org/techniques/T1055/005/) | `detecting-process-injection-techniques`, `detecting-t1055-process-injection-with-sysmon` |
| [T1055.008](https://attack.mitre.org/techniques/T1055/008/) | `detecting-process-injection-techniques` |
| [T1055.009](https://attack.mitre.org/techniques/T1055/009/) | `detecting-process-injection-techniques` |
| [T1055.011](https://attack.mitre.org/techniques/T1055/011/) | `detecting-process-injection-techniques` |
| [T1055.012](https://attack.mitre.org/techniques/T1055/012/) | `conducting-malware-incident-response`, `detecting-fileless-malware-techniques`, `detecting-process-hollowing-technique`, `detecting-process-injection-techniques`, `detecting-t1055-process-injection-with-sysmon` +2 more |
| [T1055.013](https://attack.mitre.org/techniques/T1055/013/) | `detecting-process-hollowing-technique`, `detecting-process-injection-techniques`, `detecting-t1055-process-injection-with-sysmon` |
| [T1055.014](https://attack.mitre.org/techniques/T1055/014/) | `detecting-process-injection-techniques` |
| [T1055.015](https://attack.mitre.org/techniques/T1055/015/) | `detecting-process-injection-techniques`, `detecting-t1055-process-injection-with-sysmon` |
| [T1070](https://attack.mitre.org/techniques/T1070/) | `detecting-evasion-techniques-in-endpoint-logs`, `implementing-siem-use-cases-for-detection`, `implementing-velociraptor-for-ir-collection`, `performing-purple-team-atomic-testing` |
| [T1070.001](https://attack.mitre.org/techniques/T1070/001/) | `detecting-evasion-techniques-in-endpoint-logs`, `implementing-mitre-attack-coverage-mapping`, `performing-purple-team-atomic-testing`, `performing-purple-team-exercise` |
| [T1070.004](https://attack.mitre.org/techniques/T1070/004/) | `implementing-threat-modeling-with-mitre-attack`, `performing-purple-team-atomic-testing` |
| [T1070.006](https://attack.mitre.org/techniques/T1070/006/) | `detecting-evasion-techniques-in-endpoint-logs`, `hunting-for-defense-evasion-via-timestomping` |
| [T1112](https://attack.mitre.org/techniques/T1112/) | `detecting-fileless-malware-techniques`, `performing-purple-team-atomic-testing` |
| [T1127](https://attack.mitre.org/techniques/T1127/) | `detecting-evasion-techniques-in-endpoint-logs`, `detecting-living-off-the-land-with-lolbas`, `hunting-for-lolbins-execution-in-endpoint-logs` |
| [T1127.001](https://attack.mitre.org/techniques/T1127/001/) | `detecting-living-off-the-land-attacks`, `detecting-living-off-the-land-with-lolbas`, `hunting-for-lolbins-execution-in-endpoint-logs` |
| [T1140](https://attack.mitre.org/techniques/T1140/) | `analyzing-powershell-script-block-logging`, `detecting-fileless-attacks-on-endpoints`, `detecting-living-off-the-land-with-lolbas`, `hunting-for-living-off-the-land-binaries`, `hunting-for-lolbins-execution-in-endpoint-logs` +1 more |
| [T1202](https://attack.mitre.org/techniques/T1202/) | `hunting-for-living-off-the-land-binaries`, `hunting-for-lolbins-execution-in-endpoint-logs` |
| [T1218](https://attack.mitre.org/techniques/T1218/) | `detecting-evasion-techniques-in-endpoint-logs`, `detecting-living-off-the-land-attacks`, `detecting-living-off-the-land-with-lolbas`, `hunting-advanced-persistent-threats`, `hunting-for-living-off-the-land-binaries` +3 more |
| [T1218.001](https://attack.mitre.org/techniques/T1218/001/) | `hunting-for-living-off-the-land-binaries`, `hunting-for-lolbins-execution-in-endpoint-logs`, `performing-purple-team-atomic-testing` |
| [T1218.002](https://attack.mitre.org/techniques/T1218/002/) | `hunting-for-living-off-the-land-binaries` |
| [T1218.003](https://attack.mitre.org/techniques/T1218/003/) | `detecting-living-off-the-land-attacks`, `detecting-living-off-the-land-with-lolbas`, `hunting-for-living-off-the-land-binaries`, `hunting-for-lolbins-execution-in-endpoint-logs`, `performing-purple-team-atomic-testing` |
| [T1218.004](https://attack.mitre.org/techniques/T1218/004/) | `detecting-living-off-the-land-attacks`, `hunting-for-lolbins-execution-in-endpoint-logs` |
| [T1218.005](https://attack.mitre.org/techniques/T1218/005/) | `detecting-fileless-malware-techniques`, `detecting-living-off-the-land-attacks`, `detecting-living-off-the-land-with-lolbas`, `hunting-for-living-off-the-land-binaries`, `hunting-for-lolbins-execution-in-endpoint-logs` +1 more |
| [T1218.007](https://attack.mitre.org/techniques/T1218/007/) | `hunting-for-living-off-the-land-binaries`, `hunting-for-lolbins-execution-in-endpoint-logs` |
| [T1218.010](https://attack.mitre.org/techniques/T1218/010/) | `detecting-living-off-the-land-attacks`, `detecting-living-off-the-land-with-lolbas`, `hunting-for-living-off-the-land-binaries`, `hunting-for-lolbins-execution-in-endpoint-logs`, `performing-purple-team-atomic-testing` |
| [T1218.011](https://attack.mitre.org/techniques/T1218/011/) | `detecting-living-off-the-land-attacks`, `detecting-living-off-the-land-with-lolbas`, `hunting-for-living-off-the-land-binaries`, `hunting-for-lolbins-execution-in-endpoint-logs`, `performing-dynamic-analysis-with-any-run` +1 more |
| [T1218.013](https://attack.mitre.org/techniques/T1218/013/) | `detecting-living-off-the-land-attacks` |
| [T1222.001](https://attack.mitre.org/techniques/T1222/001/) | `conducting-domain-persistence-with-dcsync` |
| [T1497](https://attack.mitre.org/techniques/T1497/) | `analyzing-malware-sandbox-evasion-techniques` |
| [T1497.001](https://attack.mitre.org/techniques/T1497/001/) | `analyzing-malware-sandbox-evasion-techniques` |
| [T1497.002](https://attack.mitre.org/techniques/T1497/002/) | `analyzing-malware-sandbox-evasion-techniques` |
| [T1497.003](https://attack.mitre.org/techniques/T1497/003/) | `analyzing-malware-sandbox-evasion-techniques` |
| [T1550](https://attack.mitre.org/techniques/T1550/) | `performing-lateral-movement-detection` |
| [T1550.001](https://attack.mitre.org/techniques/T1550/001/) | `detecting-azure-lateral-movement` |
| [T1550.002](https://attack.mitre.org/techniques/T1550/002/) | `analyzing-windows-event-logs-in-splunk`, `building-attack-pattern-library-from-cti-reports`, `conducting-full-scope-red-team-engagement`, `detecting-lateral-movement-in-network`, `detecting-lateral-movement-with-splunk` +6 more |
| [T1550.003](https://attack.mitre.org/techniques/T1550/003/) | `conducting-pass-the-ticket-attack`, `detecting-pass-the-hash-attacks`, `detecting-pass-the-ticket-attacks`, `exploiting-constrained-delegation-abuse` |
| [T1550.004](https://attack.mitre.org/techniques/T1550/004/) | `performing-initial-access-with-evilginx3` |
| [T1562](https://attack.mitre.org/techniques/T1562/) | `detecting-evasion-techniques-in-endpoint-logs`, `performing-purple-team-atomic-testing` |
| [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | `analyzing-powershell-script-block-logging`, `building-attack-pattern-library-from-cti-reports`, `detecting-evasion-techniques-in-endpoint-logs`, `detecting-fileless-attacks-on-endpoints`, `detecting-suspicious-powershell-execution` +1 more |
| [T1610](https://attack.mitre.org/techniques/T1610/) | `detecting-container-escape-attempts`, `detecting-container-escape-with-falco-rules` |

---

## 🔑 Credential Access

**27 techniques covered**

| Technique | Skills |
|:----------|:-------|
| [T1003](https://attack.mitre.org/techniques/T1003/) | `analyzing-powershell-script-block-logging`, `building-attack-pattern-library-from-cti-reports`, `building-detection-rules-with-sigma`, `detecting-container-escape-with-falco-rules`, `detecting-credential-dumping-techniques` +10 more |
| [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | `analyzing-campaign-attribution-evidence`, `analyzing-powershell-script-block-logging`, `analyzing-windows-event-logs-in-splunk`, `building-attack-pattern-library-from-cti-reports`, `building-detection-rule-with-splunk-spl` +13 more |
| [T1003.002](https://attack.mitre.org/techniques/T1003/002/) | `detecting-credential-dumping-techniques`, `detecting-t1003-credential-dumping-with-edr`, `performing-purple-team-atomic-testing` |
| [T1003.003](https://attack.mitre.org/techniques/T1003/003/) | `detecting-credential-dumping-techniques`, `detecting-t1003-credential-dumping-with-edr`, `performing-purple-team-atomic-testing` |
| [T1003.004](https://attack.mitre.org/techniques/T1003/004/) | `detecting-t1003-credential-dumping-with-edr`, `performing-credential-access-with-lazagne`, `performing-purple-team-atomic-testing` |
| [T1003.005](https://attack.mitre.org/techniques/T1003/005/) | `detecting-t1003-credential-dumping-with-edr`, `performing-purple-team-atomic-testing` |
| [T1003.006](https://attack.mitre.org/techniques/T1003/006/) | `analyzing-windows-event-logs-in-splunk`, `conducting-domain-persistence-with-dcsync`, `conducting-full-scope-red-team-engagement`, `conducting-internal-network-penetration-test`, `detecting-dcsync-attack-in-active-directory` +8 more |
| [T1110](https://attack.mitre.org/techniques/T1110/) | `analyzing-windows-event-logs-in-splunk`, `building-detection-rule-with-splunk-spl`, `conducting-internal-network-penetration-test`, `implementing-mitre-attack-coverage-mapping`, `implementing-siem-use-cases-for-detection` +3 more |
| [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | `analyzing-windows-event-logs-in-splunk`, `building-detection-rule-with-splunk-spl`, `implementing-siem-use-cases-for-detection`, `performing-false-positive-reduction-in-siem`, `performing-purple-team-atomic-testing` |
| [T1110.002](https://attack.mitre.org/techniques/T1110/002/) | `exploiting-kerberoasting-with-impacket` |
| [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | `detecting-pass-the-ticket-attacks`, `implementing-siem-use-cases-for-detection`, `performing-purple-team-atomic-testing` |
| [T1187](https://attack.mitre.org/techniques/T1187/) | `detecting-ntlm-relay-with-event-correlation` |
| [T1528](https://attack.mitre.org/techniques/T1528/) | `detecting-azure-lateral-movement`, `detecting-azure-service-principal-abuse` |
| [T1539](https://attack.mitre.org/techniques/T1539/) | `performing-credential-access-with-lazagne`, `performing-initial-access-with-evilginx3` |
| [T1552](https://attack.mitre.org/techniques/T1552/) | `performing-cloud-incident-containment-procedures`, `performing-purple-team-atomic-testing` |
| [T1552.001](https://attack.mitre.org/techniques/T1552/001/) | `performing-credential-access-with-lazagne`, `performing-purple-team-atomic-testing` |
| [T1552.002](https://attack.mitre.org/techniques/T1552/002/) | `performing-credential-access-with-lazagne` |
| [T1552.005](https://attack.mitre.org/techniques/T1552/005/) | `conducting-cloud-penetration-testing` |
| [T1552.006](https://attack.mitre.org/techniques/T1552/006/) | `deploying-active-directory-honeytokens` |
| [T1557](https://attack.mitre.org/techniques/T1557/) | `performing-initial-access-with-evilginx3` |
| [T1557.001](https://attack.mitre.org/techniques/T1557/001/) | `conducting-internal-network-penetration-test`, `detecting-ntlm-relay-with-event-correlation`, `hunting-for-ntlm-relay-attacks` |
| [T1558](https://attack.mitre.org/techniques/T1558/) | `analyzing-windows-event-logs-in-splunk`, `conducting-pass-the-ticket-attack`, `exploiting-kerberoasting-with-impacket`, `exploiting-nopac-cve-2021-42278-42287`, `performing-lateral-movement-detection` +1 more |
| [T1558.001](https://attack.mitre.org/techniques/T1558/001/) | `analyzing-windows-event-logs-in-splunk`, `conducting-domain-persistence-with-dcsync`, `detecting-golden-ticket-attacks-in-kerberos-logs`, `detecting-golden-ticket-forgery`, `detecting-kerberoasting-attacks` +3 more |
| [T1558.002](https://attack.mitre.org/techniques/T1558/002/) | `performing-active-directory-compromise-investigation` |
| [T1558.003](https://attack.mitre.org/techniques/T1558/003/) | `analyzing-windows-event-logs-in-splunk`, `building-attack-pattern-library-from-cti-reports`, `conducting-full-scope-red-team-engagement`, `conducting-internal-network-penetration-test`, `deploying-active-directory-honeytokens` +12 more |
| [T1558.004](https://attack.mitre.org/techniques/T1558/004/) | `detecting-kerberoasting-attacks` |
| [T1649](https://attack.mitre.org/techniques/T1649/) | `exploiting-active-directory-certificate-services-esc1` |

---

## 🗺️ Discovery

**20 techniques covered**

| Technique | Skills |
|:----------|:-------|
| [T1016](https://attack.mitre.org/techniques/T1016/) | `conducting-full-scope-red-team-engagement`, `conducting-internal-reconnaissance-with-bloodhound-ce`, `exploiting-active-directory-with-bloodhound`, `performing-purple-team-atomic-testing` |
| [T1018](https://attack.mitre.org/techniques/T1018/) | `conducting-full-scope-red-team-engagement`, `conducting-internal-reconnaissance-with-bloodhound-ce`, `detecting-network-scanning-with-ids-signatures`, `exploiting-active-directory-with-bloodhound`, `performing-active-directory-bloodhound-analysis` |
| [T1033](https://attack.mitre.org/techniques/T1033/) | `conducting-internal-reconnaissance-with-bloodhound-ce`, `detecting-privilege-escalation-attempts`, `exploiting-active-directory-with-bloodhound`, `performing-purple-team-atomic-testing` |
| [T1040](https://attack.mitre.org/techniques/T1040/) | `implementing-continuous-security-validation-with-bas` |
| [T1046](https://attack.mitre.org/techniques/T1046/) | `detecting-network-scanning-with-ids-signatures`, `detecting-privilege-escalation-attempts`, `performing-packet-injection-attack`, `triaging-security-incident` |
| [T1049](https://attack.mitre.org/techniques/T1049/) | `performing-purple-team-atomic-testing` |
| [T1057](https://attack.mitre.org/techniques/T1057/) | `performing-purple-team-atomic-testing` |
| [T1069](https://attack.mitre.org/techniques/T1069/) | `performing-purple-team-atomic-testing` |
| [T1069.001](https://attack.mitre.org/techniques/T1069/001/) | `performing-active-directory-bloodhound-analysis`, `performing-purple-team-atomic-testing` |
| [T1069.002](https://attack.mitre.org/techniques/T1069/002/) | `conducting-internal-reconnaissance-with-bloodhound-ce`, `exploiting-active-directory-with-bloodhound`, `performing-active-directory-bloodhound-analysis`, `performing-kerberoasting-attack`, `performing-purple-team-atomic-testing` |
| [T1082](https://attack.mitre.org/techniques/T1082/) | `conducting-full-scope-red-team-engagement`, `performing-purple-team-atomic-testing` |
| [T1083](https://attack.mitre.org/techniques/T1083/) | `implementing-canary-tokens-for-network-intrusion`, `performing-purple-team-atomic-testing` |
| [T1087](https://attack.mitre.org/techniques/T1087/) | `conducting-full-scope-red-team-engagement`, `executing-red-team-engagement-planning`, `implementing-continuous-security-validation-with-bas`, `performing-purple-team-atomic-testing` |
| [T1087.001](https://attack.mitre.org/techniques/T1087/001/) | `performing-purple-team-atomic-testing` |
| [T1087.002](https://attack.mitre.org/techniques/T1087/002/) | `conducting-internal-reconnaissance-with-bloodhound-ce`, `deploying-active-directory-honeytokens`, `exploiting-active-directory-certificate-services-esc1`, `exploiting-active-directory-with-bloodhound`, `exploiting-kerberoasting-with-impacket` +3 more |
| [T1087.004](https://attack.mitre.org/techniques/T1087/004/) | `detecting-azure-service-principal-abuse`, `implementing-mitre-attack-coverage-mapping` |
| [T1482](https://attack.mitre.org/techniques/T1482/) | `conducting-internal-reconnaissance-with-bloodhound-ce`, `exploiting-active-directory-with-bloodhound`, `performing-active-directory-bloodhound-analysis` |
| [T1518](https://attack.mitre.org/techniques/T1518/) | `performing-purple-team-atomic-testing` |
| [T1518.001](https://attack.mitre.org/techniques/T1518/001/) | `performing-purple-team-atomic-testing` |
| [T1580](https://attack.mitre.org/techniques/T1580/) | `implementing-mitre-attack-coverage-mapping` |

---

## ↔️ Lateral Movement

**9 techniques covered**

| Technique | Skills |
|:----------|:-------|
| [T1021](https://attack.mitre.org/techniques/T1021/) | `detecting-lateral-movement-in-network`, `detecting-lateral-movement-with-splunk`, `detecting-service-account-abuse`, `executing-red-team-engagement-planning`, `exploiting-constrained-delegation-abuse` +10 more |
| [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | `analyzing-campaign-attribution-evidence`, `analyzing-windows-event-logs-in-splunk`, `building-attack-pattern-library-from-cti-reports`, `building-detection-rule-with-splunk-spl`, `building-threat-hunt-hypothesis-framework` +8 more |
| [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | `analyzing-windows-event-logs-in-splunk`, `building-attack-pattern-library-from-cti-reports`, `building-detection-rule-with-splunk-spl`, `conducting-full-scope-red-team-engagement`, `conducting-internal-network-penetration-test` +10 more |
| [T1021.003](https://attack.mitre.org/techniques/T1021/003/) | `detecting-lateral-movement-with-splunk`, `hunting-for-dcom-lateral-movement`, `performing-lateral-movement-detection`, `performing-lateral-movement-with-wmiexec`, `performing-purple-team-atomic-testing` |
| [T1021.004](https://attack.mitre.org/techniques/T1021/004/) | `detecting-lateral-movement-with-splunk`, `performing-purple-team-atomic-testing` |
| [T1021.006](https://attack.mitre.org/techniques/T1021/006/) | `building-attack-pattern-library-from-cti-reports`, `detecting-lateral-movement-with-splunk`, `performing-lateral-movement-detection`, `performing-purple-team-atomic-testing` |
| [T1210](https://attack.mitre.org/techniques/T1210/) | `exploiting-ms17-010-eternalblue-vulnerability`, `exploiting-zerologon-vulnerability-cve-2020-1472` |
| [T1534](https://attack.mitre.org/techniques/T1534/) | `implementing-mitre-attack-coverage-mapping` |
| [T1570](https://attack.mitre.org/techniques/T1570/) | `detecting-lateral-movement-in-network`, `detecting-lateral-movement-with-splunk`, `performing-lateral-movement-with-wmiexec`, `performing-purple-team-atomic-testing` |

---

## 📦 Collection

**13 techniques covered**

| Technique | Skills |
|:----------|:-------|
| [T1005](https://attack.mitre.org/techniques/T1005/) | `conducting-malware-incident-response`, `detecting-container-escape-with-falco-rules`, `performing-purple-team-atomic-testing` |
| [T1039](https://attack.mitre.org/techniques/T1039/) | `performing-purple-team-atomic-testing` |
| [T1074](https://attack.mitre.org/techniques/T1074/) | `building-attack-pattern-library-from-cti-reports`, `executing-red-team-exercise`, `hunting-for-data-staging-before-exfiltration` |
| [T1074.001](https://attack.mitre.org/techniques/T1074/001/) | `hunting-for-data-staging-before-exfiltration`, `performing-purple-team-atomic-testing` |
| [T1074.002](https://attack.mitre.org/techniques/T1074/002/) | `hunting-for-data-staging-before-exfiltration` |
| [T1113](https://attack.mitre.org/techniques/T1113/) | `performing-purple-team-atomic-testing` |
| [T1114.002](https://attack.mitre.org/techniques/T1114/002/) | `detecting-email-forwarding-rules-attack` |
| [T1114.003](https://attack.mitre.org/techniques/T1114/003/) | `detecting-business-email-compromise`, `detecting-email-forwarding-rules-attack` |
| [T1115](https://attack.mitre.org/techniques/T1115/) | `performing-purple-team-atomic-testing` |
| [T1213](https://attack.mitre.org/techniques/T1213/) | `conducting-full-scope-red-team-engagement` |
| [T1530](https://attack.mitre.org/techniques/T1530/) | `detecting-insider-threat-behaviors`, `implementing-mitre-attack-coverage-mapping`, `performing-cloud-incident-containment-procedures` |
| [T1560](https://attack.mitre.org/techniques/T1560/) | `conducting-full-scope-red-team-engagement`, `hunting-for-data-staging-before-exfiltration` |
| [T1560.001](https://attack.mitre.org/techniques/T1560/001/) | `hunting-for-data-staging-before-exfiltration`, `performing-purple-team-atomic-testing` |

---

## 📡 Command and Control

**20 techniques covered**

| Technique | Skills |
|:----------|:-------|
| [T1071](https://attack.mitre.org/techniques/T1071/) | `analyzing-apt-group-with-mitre-navigator`, `analyzing-network-covert-channels-in-malware`, `analyzing-ransomware-network-indicators`, `analyzing-threat-actor-ttps-with-mitre-attack`, `hunting-advanced-persistent-threats` +6 more |
| [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | `analyzing-apt-group-with-mitre-navigator`, `analyzing-campaign-attribution-evidence`, `analyzing-powershell-empire-artifacts`, `analyzing-powershell-script-block-logging`, `building-attack-pattern-library-from-cti-reports` +13 more |
| [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | `building-attack-pattern-library-from-cti-reports`, `building-c2-infrastructure-with-sliver-framework`, `hunting-for-beaconing-with-frequency-analysis`, `hunting-for-command-and-control-beaconing`, `hunting-for-dns-tunneling-with-zeek` +3 more |
| [T1090](https://attack.mitre.org/techniques/T1090/) | `implementing-mitre-attack-coverage-mapping`, `performing-purple-team-atomic-testing` |
| [T1090.001](https://attack.mitre.org/techniques/T1090/001/) | `performing-purple-team-atomic-testing` |
| [T1090.002](https://attack.mitre.org/techniques/T1090/002/) | `building-c2-infrastructure-with-sliver-framework`, `building-red-team-c2-infrastructure-with-havoc` |
| [T1090.004](https://attack.mitre.org/techniques/T1090/004/) | `hunting-for-domain-fronting-c2-traffic` |
| [T1095](https://attack.mitre.org/techniques/T1095/) | `hunting-for-command-and-control-beaconing`, `hunting-for-unusual-network-connections` |
| [T1102](https://attack.mitre.org/techniques/T1102/) | `hunting-for-living-off-the-cloud-techniques` |
| [T1105](https://attack.mitre.org/techniques/T1105/) | `analyzing-powershell-script-block-logging`, `building-attack-pattern-library-from-cti-reports`, `building-c2-infrastructure-with-sliver-framework`, `building-red-team-c2-infrastructure-with-havoc`, `detecting-fileless-attacks-on-endpoints` +7 more |
| [T1132](https://attack.mitre.org/techniques/T1132/) | `hunting-for-command-and-control-beaconing`, `performing-purple-team-atomic-testing` |
| [T1132.001](https://attack.mitre.org/techniques/T1132/001/) | `building-c2-infrastructure-with-sliver-framework`, `performing-purple-team-atomic-testing` |
| [T1219](https://attack.mitre.org/techniques/T1219/) | `performing-purple-team-atomic-testing` |
| [T1568](https://attack.mitre.org/techniques/T1568/) | `hunting-for-command-and-control-beaconing`, `implementing-mitre-attack-coverage-mapping` |
| [T1568.002](https://attack.mitre.org/techniques/T1568/002/) | `hunting-for-beaconing-with-frequency-analysis` |
| [T1571](https://attack.mitre.org/techniques/T1571/) | `hunting-for-unusual-network-connections`, `implementing-mitre-attack-coverage-mapping` |
| [T1572](https://attack.mitre.org/techniques/T1572/) | `building-c2-infrastructure-with-sliver-framework`, `hunting-for-command-and-control-beaconing`, `hunting-for-dns-tunneling-with-zeek`, `implementing-mitre-attack-coverage-mapping` |
| [T1573](https://attack.mitre.org/techniques/T1573/) | `analyzing-ransomware-network-indicators`, `hunting-for-beaconing-with-frequency-analysis`, `hunting-for-command-and-control-beaconing`, `implementing-mitre-attack-coverage-mapping`, `performing-purple-team-atomic-testing` |
| [T1573.001](https://attack.mitre.org/techniques/T1573/001/) | `performing-purple-team-atomic-testing` |
| [T1573.002](https://attack.mitre.org/techniques/T1573/002/) | `building-c2-infrastructure-with-sliver-framework`, `building-red-team-c2-infrastructure-with-havoc` |

---

## 📤 Exfiltration

**12 techniques covered**

| Technique | Skills |
|:----------|:-------|
| [T1020](https://attack.mitre.org/techniques/T1020/) | `hunting-for-data-exfiltration-indicators` |
| [T1029](https://attack.mitre.org/techniques/T1029/) | `hunting-for-data-exfiltration-indicators` |
| [T1030](https://attack.mitre.org/techniques/T1030/) | `hunting-for-data-exfiltration-indicators` |
| [T1041](https://attack.mitre.org/techniques/T1041/) | `analyzing-campaign-attribution-evidence`, `analyzing-ransomware-network-indicators`, `building-attack-pattern-library-from-cti-reports`, `conducting-full-scope-red-team-engagement`, `conducting-malware-incident-response` +6 more |
| [T1048](https://attack.mitre.org/techniques/T1048/) | `building-attack-pattern-library-from-cti-reports`, `building-detection-rule-with-splunk-spl`, `conducting-full-scope-red-team-engagement`, `hunting-for-data-exfiltration-indicators`, `implementing-continuous-security-validation-with-bas` +2 more |
| [T1048.001](https://attack.mitre.org/techniques/T1048/001/) | `hunting-for-data-exfiltration-indicators` |
| [T1048.002](https://attack.mitre.org/techniques/T1048/002/) | `hunting-for-data-exfiltration-indicators` |
| [T1048.003](https://attack.mitre.org/techniques/T1048/003/) | `conducting-full-scope-red-team-engagement`, `hunting-for-data-exfiltration-indicators`, `hunting-for-dns-tunneling-with-zeek`, `implementing-continuous-security-validation-with-bas`, `implementing-mitre-attack-coverage-mapping` +2 more |
| [T1052](https://attack.mitre.org/techniques/T1052/) | `hunting-for-data-exfiltration-indicators` |
| [T1537](https://attack.mitre.org/techniques/T1537/) | `hunting-for-data-exfiltration-indicators`, `hunting-for-living-off-the-cloud-techniques`, `implementing-mitre-attack-coverage-mapping`, `implementing-threat-modeling-with-mitre-attack`, `performing-cloud-incident-containment-procedures` |
| [T1567](https://attack.mitre.org/techniques/T1567/) | `detecting-insider-threat-behaviors`, `hunting-for-data-exfiltration-indicators`, `hunting-for-living-off-the-cloud-techniques`, `implementing-continuous-security-validation-with-bas`, `performing-purple-team-atomic-testing` |
| [T1567.002](https://attack.mitre.org/techniques/T1567/002/) | `hunting-for-data-exfiltration-indicators`, `performing-purple-team-atomic-testing` |

---

## 💥 Impact

**6 techniques covered**

| Technique | Skills |
|:----------|:-------|
| [T1485](https://attack.mitre.org/techniques/T1485/) | `hunting-for-shadow-copy-deletion`, `performing-purple-team-atomic-testing` |
| [T1486](https://attack.mitre.org/techniques/T1486/) | `analyzing-ransomware-network-indicators`, `building-attack-pattern-library-from-cti-reports`, `building-threat-hunt-hypothesis-framework`, `conducting-full-scope-red-team-engagement`, `hunting-for-shadow-copy-deletion` +7 more |
| [T1489](https://attack.mitre.org/techniques/T1489/) | `conducting-full-scope-red-team-engagement`, `performing-purple-team-atomic-testing` |
| [T1490](https://attack.mitre.org/techniques/T1490/) | `building-soc-playbook-for-ransomware`, `hunting-for-shadow-copy-deletion`, `performing-purple-team-atomic-testing`, `performing-purple-team-exercise` |
| [T1491](https://attack.mitre.org/techniques/T1491/) | `performing-purple-team-atomic-testing` |
| [T1491.002](https://attack.mitre.org/techniques/T1491/002/) | `performing-purple-team-atomic-testing` |

---

## 🔧 Other / Cross-Tactic Techniques

| Technique | Skills |
|:----------|:-------|
| T0157 | `exploiting-kerberoasting-with-impacket` |
| T0200 | `building-vulnerability-scanning-workflow`, `performing-authenticated-scan-with-openvas` |
| T0802 | `detecting-attacks-on-historian-servers` |
| T0809 | `detecting-attacks-on-historian-servers` |
| T0814 | `detecting-modbus-command-injection-attacks` |
| T0816 | `detecting-dnp3-protocol-anomalies` |
| T0830 | `detecting-modbus-protocol-anomalies` |
| T0831 | `detecting-modbus-protocol-anomalies` |
| T0832 | `detecting-attacks-on-historian-servers` |
| T0833 | `detecting-stuxnet-style-attacks` |
| T0836 | `detecting-modbus-command-injection-attacks`, `detecting-modbus-protocol-anomalies`, `detecting-stuxnet-style-attacks` |
| T0839 | `detecting-dnp3-protocol-anomalies`, `detecting-stuxnet-style-attacks` |
| T0843 | `detecting-modbus-command-injection-attacks`, `performing-s7comm-protocol-security-analysis` |
| T0847 | `detecting-stuxnet-style-attacks` |
| T0855 | `detecting-dnp3-protocol-anomalies`, `detecting-modbus-command-injection-attacks`, `detecting-modbus-protocol-anomalies` |
| T0856 | `detecting-stuxnet-style-attacks` |
| T0862 | `detecting-stuxnet-style-attacks` |
| T0866 | `detecting-stuxnet-style-attacks` |
| T0869 | `detecting-dnp3-protocol-anomalies` |
| T0881 | `performing-s7comm-protocol-security-analysis` |
| T0886 | `detecting-modbus-protocol-anomalies` |
| T1404 | `analyzing-android-malware-with-apktool` |
| T1417 | `analyzing-android-malware-with-apktool` |
| T1418 | `analyzing-android-malware-with-apktool` |
| T1553.006 | `analyzing-uefi-bootkit-persistence` |
| T1555 | `performing-credential-access-with-lazagne`, `performing-purple-team-atomic-testing` |
| T1555.003 | `performing-credential-access-with-lazagne`, `performing-purple-team-atomic-testing` |
| T1555.004 | `performing-credential-access-with-lazagne` |
| T1578 | `performing-cloud-incident-containment-procedures` |
| T1582 | `analyzing-android-malware-with-apktool` |
| T1611 | `detecting-container-escape-attempts`, `detecting-container-escape-with-falco-rules` |
| T1615 | `conducting-internal-reconnaissance-with-bloodhound-ce`, `exploiting-active-directory-with-bloodhound`, `performing-active-directory-bloodhound-analysis` |
| T1620 | `detecting-fileless-attacks-on-endpoints` |
| T5577 | `performing-physical-intrusion-assessment` |

---

## How This Was Generated

This coverage map was automatically generated by scanning all 753+ SKILL.md and agent.py files for MITRE ATT&CK technique IDs (pattern: `T####` and `T####.###`). Each technique was mapped to its parent tactic using the [MITRE ATT&CK Enterprise Matrix v16](https://attack.mitre.org/matrices/enterprise/).

To regenerate: `python3 extract_attack.py`

---

## MITRE ATLAS Coverage (v5.5.0)

81 skills mapped to ATLAS adversarial ML techniques.

Key techniques applied:

- AML.T0051 — LLM Prompt Injection (Execution)
- AML.T0054 — LLM Jailbreak (Privilege Escalation)
- AML.T0088 — Generate Deepfakes (AI Attack Staging)
- AML.T0010 — AI Supply Chain Compromise (Initial Access)
- AML.T0020 — Poison Training Data (Resource Development)
- AML.T0070 — RAG Poisoning (Persistence)
- AML.T0080 — AI Agent Context Poisoning (Persistence)
- AML.T0056 — Extract LLM System Prompt (Exfiltration)

## MITRE D3FEND Coverage (v1.3)

11 skills mapped to D3FEND defensive countermeasures.

Countermeasures applied span D3FEND tactical categories:
Harden, Detect, Isolate, Deceive, Evict, Restore.
Each skill's d3fend_techniques field lists the top 5 most relevant
defensive countermeasures derived from the skill's ATT&CK technique tags.

## NIST AI RMF Coverage (AI 100-1)

85 skills mapped to NIST AI Risk Management Framework subcategories.

Core functions covered:

- GOVERN: Organizational accountability for AI risk (GOVERN-1.1, GOVERN-6.1, GOVERN-6.2)
- MAP: AI risk identification and context (MAP-5.1, MAP-5.2, MAP-1.6)
- MEASURE: AI risk analysis and evaluation (MEASURE-2.5, MEASURE-2.7, MEASURE-2.8, MEASURE-2.11)
- MANAGE: AI risk response and recovery (MANAGE-2.4, MANAGE-3.1)

GenAI-specific subcategories applied: GOVERN-6.1, GOVERN-6.2 (responsible deployment policies).

---

<p align="center">
  <sub>Part of <a href="https://github.com/mukul975/Anthropic-Cybersecurity-Skills">Anthropic Cybersecurity Skills</a> — 753+ open-source cybersecurity skills for AI agents</sub>
</p>
