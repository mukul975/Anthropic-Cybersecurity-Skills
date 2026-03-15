# Workflows: Detecting BEC with AI

## Workflow 1: AI-Powered BEC Detection Pipeline

```
Inbound email arrives
  |
  v
[Feature extraction]
  +-- Sender metadata (domain, IP, authentication)
  +-- Email content (subject, body, NLP features)
  +-- Behavioral context (communication history, timing)
  +-- Relationship graph (sender-recipient pattern)
  |
  v
[Multi-model analysis (parallel)]
  +-- Impostor classifier: Display name/domain impersonation
  +-- NLP model: Writing style vs. sender baseline
  +-- Behavioral model: Request anomaly detection
  +-- Intent classifier: Payment/credential/data request
  |
  v
[Confidence scoring]
  +-- Aggregate model outputs
  +-- Weight by model confidence and context
  +-- Generate overall BEC probability score
  |
  v
[Action]
  +-- Score >= 90%: Auto-quarantine + SOC alert
  +-- Score 70-89%: Warning banner + analyst queue
  +-- Score 50-69%: Warning banner only
  +-- Score < 50%: Deliver normally
```

## Workflow 2: Model Feedback Loop

```
BEC verdict generated
  |
  v
[User/analyst feedback]
  +-- User reports false positive (legitimate email flagged)
  +-- Analyst confirms true positive (BEC caught)
  +-- User reports missed BEC (false negative)
  |
  v
[Feedback integration]
  +-- Update sender trust score
  +-- Retrain model with corrected labels
  +-- Adjust confidence thresholds
  +-- Update behavioral baselines
```
