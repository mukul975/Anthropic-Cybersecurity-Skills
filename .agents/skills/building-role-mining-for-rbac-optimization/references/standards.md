# Role Mining for RBAC Optimization - Standards Reference

## RBAC Standards

### ANSI/INCITS 359-2012 - Core RBAC
- Defines User, Role, Permission, Session abstractions
- Role assignment: users are assigned to roles
- Permission assignment: permissions are assigned to roles
- Role hierarchy: senior roles inherit junior role permissions
- Separation of Duty constraints (static and dynamic)

### NIST RBAC Model (SP 800-162)
- Core RBAC: Basic user-role and role-permission mappings
- Hierarchical RBAC: Role inheritance relationships
- Constrained RBAC: Static and dynamic separation of duties
- Symmetric RBAC: Combined user-centric and permission-centric views

## Identity Governance Standards

### ISO 27001:2022 - A.5.15 Access Control
- Access control policy based on business and security requirements
- Roles determined by job function
- Regular review of access rights
- Formal authorization for privilege changes

### NIST SP 800-53 Rev 5
- AC-2: Account Management
- AC-3: Access Enforcement
- AC-5: Separation of Duties
- AC-6: Least Privilege
- AC-16: Security and Privacy Attributes
- AC-24: Access Control Decisions

## Role Mining Research

### Key Algorithms
- **RoleMiner (Vaidya et al., 2007)**: Iterative role mining minimizing WSC
- **CompleteMiner / FastMiner (Vaidya et al., 2006)**: Complete vs. approximate algorithms
- **ORCA (Schlegelmilch & Steffens, 2005)**: Clustering-based approach
- **Graph Optimization (Lu et al., 2008)**: Graph-based role mining

### Quality Metrics
- Weighted Structural Complexity: min(|UA| + |PA| + |Roles|)
- Boolean Matrix Decomposition error
- Jaccard similarity between mined and original access
- Role coverage percentage
