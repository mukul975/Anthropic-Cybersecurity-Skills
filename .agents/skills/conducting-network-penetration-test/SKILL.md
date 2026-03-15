---
name: conducting-network-penetration-test
description: >
  Conducts comprehensive network penetration tests against authorized target environments by
  performing host discovery, port scanning, service enumeration, vulnerability identification,
  and controlled exploitation to assess the security posture of network infrastructure. The
  tester follows PTES methodology from reconnaissance through post-exploitation and reporting.
  Activates for requests involving network pentest, infrastructure security assessment,
  internal network testing, or external perimeter testing.
domain: cybersecurity
subdomain: penetration-testing
tags: [network-pentest, Nmap, Metasploit, vulnerability-exploitation, infrastructure-security]
version: 1.0.0
author: mahipal
license: Apache-2.0
---
# Conducting Network Penetration Test

## When to Use

- Assessing the security posture of internal or external network infrastructure before or after deployment
- Validating firewall rules, network segmentation, and access controls under realistic attack conditions
- Identifying exploitable vulnerabilities in network services, protocols, and configurations
- Meeting compliance requirements for PCI-DSS, HIPAA, SOC 2, or ISO 27001 that mandate periodic penetration testing
- Evaluating the effectiveness of IDS/IPS, SIEM, and SOC detection capabilities against real attack traffic

**Do not use** for testing networks without explicit written authorization from the asset owner, against production systems without a pre-approved change window and rollback plan, or for denial-of-service testing unless explicitly scoped and authorized.

## Prerequisites

- Signed Rules of Engagement (RoE) document specifying target IP ranges, excluded hosts, testing hours, and emergency contacts
- Written authorization letter (get-out-of-jail letter) from the network owner
- Dedicated testing laptop with Kali Linux or equivalent distribution with up-to-date tools
- VPN or direct network access to the target scope as defined in the RoE
- Out-of-band communication channel with the client's incident response team
- Scope document listing in-scope IP ranges, domains, and any explicitly excluded systems (medical devices, SCADA, critical infrastructure)

## Workflow

### Step 1: Pre-Engagement and Scope Validation

Validate the scope by confirming IP ranges with the client. Verify that all IP addresses in scope are owned by the client using ARIN/RIPE WHOIS lookups. Confirm testing windows, escalation procedures, and any sensitivity constraints. Set up the testing environment with a dedicated VM, VPN connection, and logging enabled on all tools. Create a timestamped activity log that records every command executed, every scan launched, and every exploit attempted throughout the engagement.

### Step 2: Host Discovery and Network Mapping

Identify live hosts within the authorized scope using layered discovery techniques:

- **ICMP sweep**: `nmap -sn -PE -PP -PM 10.10.0.0/16 -oA discovery_icmp` to find hosts responding to ping
- **ARP scan** (internal networks): `nmap -sn -PR 10.10.0.0/24 -oA discovery_arp` or `arp-scan -l` for local subnet enumeration
- **TCP SYN discovery**: `nmap -sn -PS21,22,25,80,443,445,3389,8080 10.10.0.0/16 -oA discovery_tcp` to find hosts with ICMP blocked
- **UDP discovery**: `nmap -sn -PU53,161,500 10.10.0.0/16 -oA discovery_udp` for hosts only responding on UDP

Consolidate live hosts into a target list. Map the network topology by identifying gateways, VLAN boundaries, and trust relationships using traceroute and SNMP community string guessing where authorized.

### Step 3: Port Scanning and Service Enumeration

Perform detailed port scanning on discovered hosts:

- **Full TCP scan**: `nmap -sS -p- --min-rate 1000 -T4 -oA full_tcp <target>` to identify all open TCP ports
- **Top UDP ports**: `nmap -sU --top-ports 200 -T4 -oA top_udp <target>` for commonly exploitable UDP services
- **Service version detection**: `nmap -sV -sC -p <open_ports> -oA service_enum <target>` to fingerprint service versions and run default NSE scripts
- **OS fingerprinting**: `nmap -O --osscan-guess -oA os_detection <target>` to identify operating systems

Enumerate discovered services in depth using protocol-specific tools:
- SMB: `enum4linux -a <target>`, `crackmapexec smb <target> --shares`
- SNMP: `snmpwalk -v2c -c public <target>`
- DNS: `dig axfr @<dns_server> <domain>` for zone transfer attempts
- LDAP: `ldapsearch -x -H ldap://<target> -b "dc=example,dc=com"`

### Step 4: Vulnerability Identification

Correlate discovered service versions against known vulnerability databases:

- Run `nmap --script vuln -p <ports> <target>` for NSE vulnerability scripts
- Use `searchsploit <service> <version>` to query the Exploit-DB offline database
- Cross-reference with NVD (National Vulnerability Database) and CVE records for confirmed vulnerabilities
- Check for default credentials on management interfaces (Tomcat Manager, Jenkins, phpMyAdmin, database consoles)
- Test for common misconfigurations: anonymous FTP, open SMTP relays, unrestricted SNMP communities, NFS exports without authentication

Prioritize vulnerabilities by CVSS score, exploitability, and business impact. Document each finding with CVE identifier, affected host, service, and version.

### Step 5: Exploitation

Attempt controlled exploitation of validated vulnerabilities using the principle of minimum necessary access:

- **Metasploit Framework**: `msfconsole` with appropriate exploit modules matched to confirmed vulnerabilities. Set RHOSTS, RPORT, and payload options. Prefer bind/reverse TCP Meterpreter for post-exploitation flexibility.
- **Manual exploitation**: Use public proof-of-concept exploits from Exploit-DB after code review. Compile and modify as needed for the target environment.
- **Credential attacks**: Use `hydra` or `crackmapexec` for password spraying against discovered services (SSH, RDP, SMB, HTTP basic auth) using common credential lists. Respect lockout policies.
- **Pass-the-hash / relay**: If NTLM hashes are obtained, attempt pass-the-hash with `impacket-psexec` or relay attacks with `impacket-ntlmrelayx` where SMB signing is disabled.

Document every exploitation attempt including failures. Capture screenshots of successful compromises showing hostname, IP, current user, and privilege level.

### Step 6: Post-Exploitation and Pivoting

After gaining access to a host, demonstrate business impact:

- **Privilege escalation**: Check for local privilege escalation paths using `linpeas.sh` (Linux) or `winPEAS.exe` (Windows). Look for misconfigured services, SUID binaries, unquoted service paths, or kernel exploits.
- **Credential harvesting**: Extract stored credentials from memory (`mimikatz`), files (config files, browser stores), or cached hashes (`hashdump`).
- **Lateral movement**: Use obtained credentials to pivot to additional systems. Test network segmentation by attempting to reach out-of-scope networks from compromised hosts.
- **Data access demonstration**: Identify sensitive data accessible from compromised systems (PII databases, file shares, backup files) and document access without exfiltrating actual data.

Maintain detailed notes on every pivot point, credential obtained, and system accessed to build the attack chain narrative.

### Step 7: Cleanup and Reporting

Remove all testing artifacts from compromised systems:

- Delete uploaded tools, shells, and temporary files
- Remove any accounts created during testing
- Revert configuration changes made during exploitation
- Verify cleanup by re-scanning affected hosts

Prepare the penetration test report with executive summary, methodology description, finding details with CVSS scores, proof-of-concept evidence, and prioritized remediation recommendations.

## Key Concepts

| Term | Definition |
|------|------------|
| **Rules of Engagement (RoE)** | Formal document defining the scope, boundaries, testing hours, authorized actions, and escalation procedures for a penetration test |
| **Pivot** | Using a compromised host as a relay point to access additional network segments not directly reachable from the tester's position |
| **Service Enumeration** | The process of identifying running services, their versions, and configurations on discovered hosts to map the attack surface |
| **Credential Spraying** | Testing a small number of commonly used passwords against many accounts simultaneously to avoid account lockout thresholds |
| **CVSS** | Common Vulnerability Scoring System; an industry-standard framework for rating the severity of vulnerabilities on a 0-10 scale |
| **Lateral Movement** | Techniques used to move from one compromised system to another within a network, expanding the scope of access |
| **Post-Exploitation** | Activities performed after initial compromise including privilege escalation, persistence, credential harvesting, and data access |

## Tools & Systems

- **Nmap**: Network discovery, port scanning, service enumeration, and vulnerability detection via the Nmap Scripting Engine (NSE)
- **Metasploit Framework**: Exploitation framework providing exploit modules, payloads, encoders, and post-exploitation tools for validated vulnerability exploitation
- **CrackMapExec**: Swiss-army knife for Windows/Active Directory environments supporting SMB, WinRM, LDAP, and MSSQL enumeration and exploitation
- **Impacket**: Python library providing low-level programmatic access to network protocols (SMB, MSRPC, Kerberos) used for relay attacks and remote execution
- **Burp Suite**: Web application proxy used when network services expose HTTP-based management interfaces

## Common Scenarios

### Scenario: Internal Network Penetration Test for a Financial Institution

**Context**: The client is a mid-size bank requiring PCI-DSS compliance. Scope includes the internal corporate network (10.10.0.0/16), excluding payment processing systems in a separate VLAN. Testing window is Monday-Friday 20:00-06:00 to minimize impact on operations.

**Approach**:
1. Perform ARP-based host discovery on accessible subnets and TCP SYN discovery for hosts with ICMP disabled
2. Conduct full port scans on all discovered hosts, prioritizing Windows servers and domain controllers
3. Enumerate SMB shares, SNMP communities, and web management interfaces for quick wins
4. Identify and exploit an unpatched Apache Tomcat instance with default credentials to gain initial foothold
5. Escalate privileges via a local Windows kernel vulnerability, then extract cached domain credentials with Mimikatz
6. Demonstrate lateral movement to the database server containing customer records, proving inadequate network segmentation
7. Document the complete attack path from initial access to sensitive data, with remediation steps for each vulnerability

**Pitfalls**:
- Scanning too aggressively during business hours and triggering IDS alerts or service disruptions
- Failing to verify that all target IPs are actually owned by the client before scanning
- Not documenting exploitation attempts that failed, missing the opportunity to report on effective controls
- Forgetting to clean up Meterpreter sessions and uploaded tools after testing

## Output Format

```
## Finding: Unpatched Apache Tomcat with Default Credentials

**ID**: NET-001
**Severity**: Critical (CVSS 9.8)
**Affected Host**: 10.10.5.23 (tomcat-prod.internal.corp)
**Service**: Apache Tomcat 8.5.31 on port 8080
**CVE**: CVE-2019-0232

**Description**:
The Apache Tomcat instance on 10.10.5.23:8080 is running version 8.5.31, which is
vulnerable to CVE-2019-0232 (remote code execution via CGI Servlet). Additionally,
the Tomcat Manager interface is accessible with default credentials (tomcat:tomcat),
allowing deployment of arbitrary WAR files.

**Proof of Concept**:
1. Accessed http://10.10.5.23:8080/manager/html with credentials tomcat:tomcat
2. Deployed malicious WAR file containing a reverse shell payload
3. Obtained command execution as NT AUTHORITY\SYSTEM

**Impact**:
Full system compromise of the Tomcat server. From this host, the tester
pivoted to 3 additional systems on the same subnet using harvested credentials,
ultimately accessing the customer database containing 50,000+ records.

**Remediation**:
1. Immediately change default Tomcat Manager credentials
2. Upgrade Apache Tomcat to the latest stable release (currently 10.1.x)
3. Restrict access to the Tomcat Manager interface to authorized management IPs only
4. Implement network segmentation between web servers and database tier
```
