# Standards and Frameworks Reference

## NIST SP 800-207: Zero Trust Architecture

### Microsegmentation as ZTA Deployment Model
NIST SP 800-207 identifies microsegmentation as one of three primary deployment approaches for zero trust:
- Places individual or groups of resources on a unique network segment protected by a gateway security component
- The enterprise places infrastructure devices such as intelligent switches, next-generation firewalls, or special-purpose gateway devices to act as PEPs protecting each resource or group of resources
- This approach can be implemented using software-defined networking (SDN) or hypervisor-level enforcement

### Applicable Controls
- **AC-4 (Information Flow Enforcement)**: Microsegmentation enforces approved information flows between workloads
- **SC-7 (Boundary Protection)**: Each microsegment boundary acts as a security boundary
- **SI-4 (Information System Monitoring)**: Microsegmentation tools provide flow telemetry for monitoring

## CISA Zero Trust Maturity Model v2.0

### Network Pillar - Microsegmentation Maturity

| Level | Network Segmentation | Microsegmentation | Traffic Management |
|---|---|---|---|
| Traditional | Large, macro-segmented perimeters | None | Static ACLs |
| Initial | Defined architecture with some isolation | Initial workload isolation | Basic flow visibility |
| Advanced | Ingress/egress micro-perimeters | Workload-level microsegmentation | Identity-based traffic rules |
| Optimal | Full microsegmentation, dynamically defined | Automated, adaptive policies | ML-driven anomaly detection |

### Cross-Cutting: Visibility and Analytics
- Flow telemetry from microsegmentation agents feeds into SIEM/SOAR
- Application dependency maps provide baseline for anomaly detection
- Policy violation alerts enable real-time incident detection

## PCI DSS v4.0

### Microsegmentation for Scope Reduction
- **Requirement 1.3**: Network controls restrict access to and from the cardholder data environment (CDE)
- **Requirement 1.4**: Network connections between trusted and untrusted networks are controlled
- Microsegmentation can reduce PCI scope by isolating CDE workloads from non-CDE systems
- Compensating control: host-based microsegmentation validated by QSA as equivalent to network segmentation

## Forrester Zero Trust eXtended (ZTX) Framework

### Workload Security Pillar
- Microsegmentation is a core capability for securing workloads
- Policies should be based on workload identity and context, not network location
- Continuous monitoring of east-west traffic for anomaly detection
- Integration with DevOps pipelines for automated policy management

## VMware NSX Distributed Firewall

### Architecture
- Stateful Layer 4-7 firewall embedded in the hypervisor kernel
- Policies evaluated at the vNIC level before traffic reaches the physical network
- Context-aware rules using Active Directory groups, VM tags, and application identification
- No network topology changes required for deployment

## Illumio Core Platform

### Architecture
- Virtual Enforcement Node (VEN) agents installed on workloads
- Policy Compute Engine (PCE) centralizes policy management and visualization
- Enforcement via native OS firewall (iptables on Linux, WFP on Windows)
- Label-based policy model: Role, Application, Environment, Location

## Guardicore (Akamai)

### Architecture
- Lightweight agents provide process-level visibility and enforcement
- Reveal module builds application dependency maps
- Centra management platform for policy creation and monitoring
- Supports bare-metal, VM, container, and cloud workloads
