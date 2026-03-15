# Standards Reference - OT Network Security Assessment

## IEC 62443 (ISA/IEC 62443)

### IEC 62443-1-1: Terminology, Concepts, and Models
- Defines foundational concepts including zones, conduits, security levels, and the IACS reference architecture
- Establishes the vocabulary used across all parts of the standard

### IEC 62443-2-1: Security Management System Requirements
- Requirements for an IACS security management system (SMS)
- Covers risk assessment, security policies, organization, staff competence, and awareness

### IEC 62443-3-2: Security Risk Assessment for System Design
- Defines the process for partitioning an IACS into zones and conduits
- Establishes Security Level targets (SL-T) for each zone based on risk assessment
- Zone characteristics: assets, access points, communication channels, data flows
- Conduit characteristics: connected zones, protocols, security countermeasures

### IEC 62443-3-3: System Security Requirements and Security Levels
- Foundational requirements (FR) mapped to security levels (SL 1-4):
  - FR 1: Identification and Authentication Control (IAC)
  - FR 2: Use Control (UC)
  - FR 3: System Integrity (SI)
  - FR 4: Data Confidentiality (DC)
  - FR 5: Restricted Data Flow (RDF)
  - FR 6: Timely Response to Events (TRE)
  - FR 7: Resource Availability (RA)

### Security Levels
| Level | Description |
|-------|-------------|
| SL 1 | Protection against casual or coincidental violation |
| SL 2 | Protection against intentional violation using simple means |
| SL 3 | Protection against sophisticated attack with moderate resources |
| SL 4 | Protection against state-sponsored attack with extensive resources |

## NIST SP 800-82 Revision 3

### Guide to Operational Technology (OT) Security
- Published September 2023, replacing the ICS-focused Rev. 2
- Expanded scope covers: ICS/SCADA, building automation, transportation, physical access control, physical environment monitoring
- Provides OT overlay for NIST SP 800-53r5 security controls
- Tailored security control baselines for low/moderate/high-impact OT systems

### Key Sections for Network Assessment
- Section 3: OT Overview and Architectures (Purdue Model reference)
- Section 4: OT Risk Management
- Section 5: OT Security Architecture (network segmentation, DMZ design)
- Section 6: Applying Security Controls to OT (overlay guidance)

### OT-Specific Control Tailoring
- AC-4 (Information Flow Enforcement): Implement data diodes for unidirectional flows from Level 3 to Level 3.5
- SC-7 (Boundary Protection): Industrial firewalls with protocol-aware deep packet inspection
- AU-6 (Audit Record Review): Correlate OT network events with process alarms

## NERC CIP Standards (Power Sector)

### CIP-002-5.1a: BES Cyber System Categorization
- Identify and categorize Bulk Electric System (BES) cyber systems as high, medium, or low impact

### CIP-005-7: Electronic Security Perimeters
- Define Electronic Security Perimeters (ESP) around BES cyber systems
- Require Electronic Access Points (EAP) at all ESP boundaries
- 2025 update requires MFA for remote access to medium and high-impact systems

### CIP-007-6: System Security Management
- Port and service management, security patch management
- Malicious code prevention, security event monitoring
- System access controls and authentication

### CIP-010-4: Configuration Change Management and Vulnerability Assessments
- Baseline configurations for BES cyber systems
- Transient cyber asset and removable media management
- Active vulnerability assessments at least every 15 months

## Purdue Reference Model (ISA-95)

### Level Architecture
| Level | Name | Examples |
|-------|------|----------|
| Level 0 | Physical Process | Sensors, actuators, analyzers |
| Level 1 | Basic Control | PLCs, RTUs, safety controllers |
| Level 2 | Area Supervisory Control | HMI, engineering workstations, local historian |
| Level 3 | Site Operations | OPC servers, site historian, MES |
| Level 3.5 | DMZ | Data diodes, jump servers, patch servers |
| Level 4 | Enterprise | ERP, email, corporate IT |
| Level 5 | Internet/Cloud | Remote access, cloud services |
