# Standards & References: Detecting BEC with AI

## MITRE ATT&CK References
- **T1566.001/002**: Phishing (Spearphishing Attachment/Link)
- **T1534**: Internal Spearphishing
- **T1656**: Impersonation
- **T1586.002**: Compromise Accounts: Email Accounts
- **T1114.003**: Email Collection: Email Forwarding Rule

## AI/ML Techniques for BEC Detection
| Technique | Application | Accuracy |
|---|---|---|
| BERT embeddings + SVC | Email classification | 98.65% |
| Transformer NLP | Writing style analysis | 96%+ |
| Anomaly detection | Behavioral baseline deviation | 94%+ |
| Graph neural networks | Communication pattern analysis | 93%+ |
| Sentiment analysis | Urgency/manipulation detection | 91%+ |

## FBI IC3 BEC Statistics
- $2.9 billion losses reported in 2023
- BEC accounts for 27% of all cybercrime financial losses
- Average loss per BEC incident: $125,000
- 21,832 BEC complaints filed in 2023

## Detection Categories
- **Impostor Detection**: AI identifies display name/domain impersonation
- **Account Takeover Detection**: Behavioral anomalies from compromised accounts
- **Writing Style Analysis**: NLP compares email to sender's historical style
- **Intent Classification**: ML classifies email as payment/credential/data request
- **Relationship Analysis**: Graph analysis of sender-recipient communication patterns
