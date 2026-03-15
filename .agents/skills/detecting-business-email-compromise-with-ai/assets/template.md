# AI-Powered BEC Detection Template

## AI Platform Configuration
| Setting | Value | Status |
|---|---|---|
| Platform | | |
| Integration | API-based (Microsoft Graph) | |
| Baseline training period | 30+ days | |
| Scanning scope | Inbound + Internal + Outbound | |

## Detection Thresholds
| Score Range | Classification | Action |
|---|---|---|
| 90-100% | High-confidence BEC | Auto-quarantine + SOC alert |
| 70-89% | Moderate BEC | Warning banner + analyst queue |
| 50-69% | Low-confidence BEC | Warning banner only |
| < 50% | Likely legitimate | Deliver normally |

## VIP Protection List
| Name | Title | Email | Writing Style Profiled |
|---|---|---|---|
| | CEO | | |
| | CFO | | |
| | CTO | | |

## Model Performance Metrics
| Metric | Target | Current |
|---|---|---|
| Detection accuracy | > 98% | |
| False positive rate | < 0.05% | |
| Mean detection time | < 5 sec | |
| BEC catch rate vs. rules | +25% | |
