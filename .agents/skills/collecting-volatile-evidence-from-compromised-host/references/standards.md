# Standards and Framework References - Volatile Evidence Collection

## RFC 3227 - Guidelines for Evidence Collection and Archiving
- Defines the order of volatility for digital evidence:
  1. Registers, cache
  2. Routing table, ARP cache, process table, kernel statistics, memory
  3. Temporary file systems
  4. Disk
  5. Remote logging and monitoring data
  6. Physical configuration, network topology
  7. Archival media
- Key principles: minimize data alteration, document actions, use trusted tools
- Reference: https://www.rfc-editor.org/rfc/rfc3227

## NIST SP 800-86 - Guide to Integrating Forensic Techniques
- Section 4: Using Data from Data Sources
  - 4.2: Data Files - Volatile and non-volatile OS data
  - 4.3: Operating System Data - Memory, processes, network connections
- Forensic process: Collection, Examination, Analysis, Reporting
- Emphasis on preserving data integrity through proper acquisition
- Reference: https://csrc.nist.gov/pubs/sp/800/86/final

## NIST SP 800-61 Rev. 3 - Evidence Handling
- **Respond (RS)** function alignment:
  - RS.AN-03: Analysis to establish incident scope
- Evidence must be collected in a forensically sound manner
- Document all collection activities and maintain chain of custody

## SANS DFIR - Live Evidence Collection Best Practices
- Collect evidence from most volatile to least volatile
- Use external trusted tools (not tools from compromised system)
- Hash all evidence immediately after collection
- Document system time offset from UTC
- Minimize footprint on compromised system
- Reference: https://www.sans.org/white-papers/

## MITRE ATT&CK - Evidence Sources for Detection
| Data Source | ATT&CK Reference | Evidence Type |
|------------|-------------------|---------------|
| Process (DS0009) | Process creation, command line | Running processes |
| Network Traffic (DS0029) | Connection creation, flow | Network connections |
| File (DS0022) | File creation, modification | Open handles, temp files |
| Windows Registry (DS0024) | Registry key modification | Autostart entries |
| Logon Session (DS0028) | Logon creation | Active user sessions |
| Module (DS0011) | Module load | Loaded DLLs/shared objects |

## ACPO Good Practice Guide for Digital Evidence
- Principle 1: No action should change data on digital devices
- Principle 2: Competent person must access original data when necessary
- Principle 3: Audit trail of all processes applied to evidence
- Principle 4: Person in charge ensures law and principles are adhered to

## ISO/IEC 27037 - Guidelines for Identification, Collection, Acquisition, and Preservation
- Defines procedures for handling digital evidence
- Specifies requirements for first responders and forensic specialists
- Covers volatile and non-volatile evidence acquisition
- Emphasizes competency of evidence handlers

## SWGDE Best Practices for Computer Forensics
- Scientific Working Group on Digital Evidence
- Standards for evidence acquisition, examination, and reporting
- Quality assurance requirements for forensic processes
