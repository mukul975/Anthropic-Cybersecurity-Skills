# Identity Verification Workflows

## Workflow 1: Zero Trust Authentication Flow

```
User Initiates Access
    │
    v
┌─────────────────────────┐
│ 1. Pre-Authentication    │
│ - Check IP reputation    │
│ - Rate limit evaluation  │
│ - Bot detection          │
│ - Geo-blocking check     │
└──────────┬──────────────┘
           v
┌─────────────────────────┐
│ 2. Primary Authentication│
│ - FIDO2 key challenge    │
│ - Biometric verification │
│ - Certificate validation │
│ - Passwordless flow      │
└──────────┬──────────────┘
           v
┌─────────────────────────┐
│ 3. Context Assessment    │
│ - Device compliance      │
│ - Network location       │
│ - Time of access         │
│ - Behavioral baseline    │
│ - Previous session state │
└──────────┬──────────────┘
           v
┌─────────────────────────┐
│ 4. Risk Calculation      │
│ - User risk level        │
│ - Sign-in risk level     │
│ - Aggregate score        │
└───┬──────────┬──────┬───┘
    │          │      │
  LOW        MED    HIGH
    │          │      │
    v          v      v
┌──────┐ ┌────────┐ ┌────────┐
│Grant │ │Step-Up │ │Block + │
│Token │ │ Auth   │ │Alert   │
└──────┘ └────────┘ └────────┘
```

## Workflow 2: Continuous Access Evaluation

```
Active Session
    │
    v
┌──────────────────────────────┐
│ Continuous Monitoring Loop    │
│                               │
│  ┌─── Check every N minutes ──┐
│  │                             │
│  │  ┌─────────────────────┐   │
│  │  │ Signal Collection    │   │
│  │  │ - Device compliance  │   │
│  │  │ - User risk change   │   │
│  │  │ - Location shift     │   │
│  │  │ - Behavior anomaly   │   │
│  │  └──────────┬──────────┘   │
│  │             v               │
│  │  ┌─────────────────────┐   │
│  │  │ Critical Events      │   │
│  │  │ - Account disabled   │   │
│  │  │ - Password changed   │   │
│  │  │ - MFA registration   │   │
│  │  │ - Admin revocation   │   │
│  │  └──────────┬──────────┘   │
│  │             v               │
│  │  ┌─────────────────────┐   │
│  │  │ Re-Evaluate Access   │   │
│  │  │ - Recalculate risk   │   │
│  │  │ - Apply policy       │   │
│  │  └───┬─────────┬───────┘   │
│  │      │         │           │
│  │   Continue   Revoke        │
│  │   Session    Token         │
│  └──────┘         │           │
│                   v           │
│           ┌──────────────┐    │
│           │ Force Re-Auth│    │
│           │ or Terminate │    │
│           └──────────────┘    │
└──────────────────────────────┘
```

## Workflow 3: FIDO2 Enrollment

```
Admin Initiates Enrollment Campaign
    │
    v
┌──────────────────────────┐
│ 1. User Notification      │
│ - Email with instructions │
│ - Self-service portal URL │
│ - Deadline for enrollment │
└──────────┬───────────────┘
           v
┌──────────────────────────┐
│ 2. User Self-Service      │
│ - Authenticate with       │
│   existing credentials    │
│ - Register security key   │
│   (YubiKey, Titan key)    │
│ - Register platform auth  │
│   (Windows Hello, TouchID)│
│ - Register backup method  │
└──────────┬───────────────┘
           v
┌──────────────────────────┐
│ 3. Verification           │
│ - Test sign-in with FIDO2 │
│ - Confirm backup works    │
│ - Record key serial/ID    │
└──────────┬───────────────┘
           v
┌──────────────────────────┐
│ 4. Policy Enforcement     │
│ - Enable phishing-resist  │
│   conditional access      │
│ - Disable legacy MFA      │
│ - Monitor compliance rate │
└──────────────────────────┘
```

## Workflow 4: Compromised Identity Response

```
Identity Threat Detected
    │
    v
┌──────────────────────────┐
│ 1. Detection Signal       │
│ - Impossible travel       │
│ - Leaked credentials      │
│ - Token anomaly           │
│ - Behavioral deviation    │
└──────────┬───────────────┘
           v
┌──────────────────────────┐
│ 2. Automated Response     │
│ - Revoke all sessions     │
│ - Disable account         │
│ - Trigger SOAR playbook   │
│ - Notify SOC analyst      │
└──────────┬───────────────┘
           v
┌──────────────────────────┐
│ 3. Investigation          │
│ - Review sign-in logs     │
│ - Check accessed resources│
│ - Correlate with EDR data │
│ - Interview user          │
└──────────┬───────────────┘
           v
┌──────────────────────────┐
│ 4. Remediation            │
│ - Reset all credentials   │
│ - Re-enroll FIDO2 keys    │
│ - Review and restrict     │
│   access permissions      │
│ - Re-enable account       │
│ - Update detection rules  │
└──────────────────────────┘
```
