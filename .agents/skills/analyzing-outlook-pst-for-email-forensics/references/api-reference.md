# API Reference: Outlook PST Email Forensics

## pypff (libpff Python bindings)

### Installation
```bash
pip install libpff-python
```

### Opening a PST File
```python
import pypff

pst = pypff.file()
pst.open("mailbox.pst")
root = pst.get_root_folder()
```

### Navigating Folders
```python
for i in range(root.number_of_sub_folders):
    folder = root.get_sub_folder(i)
    print(f"{folder.name}: {folder.number_of_sub_messages} messages")
```

### Extracting Messages
```python
msg = folder.get_sub_message(0)
print(msg.subject)
print(msg.sender_name)
print(msg.delivery_time)
print(msg.transport_headers)
print(msg.plain_text_body)
print(msg.html_body)
```

### Extracting Attachments
```python
for i in range(msg.number_of_attachments):
    att = msg.get_attachment(i)
    print(f"Name: {att.name}, Size: {att.size}")
    data = att.read_buffer(att.size)
```

## pffexport (CLI)

### Syntax
```bash
pffexport mailbox.pst                    # Export all to current dir
pffexport -m all mailbox.pst             # Export all message types
pffexport -t target_dir mailbox.pst      # Export to target directory
pffexport -f text mailbox.pst            # Export as text format
```

### Output Structure
```
Export/
  Inbox/
    Message001/
      Message.txt
      Attachment001.pdf
  Sent Items/
  Deleted Items/
```

## readpst (libpst)

### Syntax
```bash
readpst -o output_dir mailbox.pst        # Extract to dir
readpst -e mailbox.pst                   # Extract attachments
readpst -r mailbox.pst                   # Recursive extraction
readpst -j 4 mailbox.pst                # Parallel (4 threads)
readpst -S mailbox.pst                   # Separate files per message
```

## PST File Structure

| Component | Description |
|-----------|-------------|
| NDB Layer | Node Database - raw data storage |
| LTP Layer | Lists/Tables/Properties - message properties |
| Messaging Layer | Folders, messages, attachments |

## Key Message Properties
| Property | MAPI Tag | Description |
|----------|----------|-------------|
| Subject | PR_SUBJECT (0x0037) | Email subject |
| Sender | PR_SENDER_NAME (0x0C1A) | Sender display name |
| From | PR_SENT_REPRESENTING_EMAIL (0x0065) | Sender email |
| Delivery Time | PR_MESSAGE_DELIVERY_TIME (0x0E06) | When delivered |
| Headers | PR_TRANSPORT_MESSAGE_HEADERS (0x007D) | Full SMTP headers |

## Forensic Considerations
- Deleted Items folder may contain evidence
- Recoverable Items (dumpster) requires special extraction
- Calendar/Contacts may contain relevant data
- Journal entries can provide timeline evidence
