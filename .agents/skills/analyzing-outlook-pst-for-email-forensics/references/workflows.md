# Workflows - PST Email Forensics
## Workflow: Email Evidence Extraction
```
Acquire PST/OST files from evidence
    |
Hash original files (SHA-256)
    |
Export with pffexport (items + recovered)
    |
Parse email headers for routing
    |
Extract and hash attachments
    |
Search for keywords across messages
    |
Build communication timeline
    |
Document findings with chain of custody
```
