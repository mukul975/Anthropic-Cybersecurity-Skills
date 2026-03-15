---
name: acquiring-disk-image-with-dd-and-dcfldd
description: Create forensically sound bit-for-bit disk images using dd and dcfldd while preserving evidence integrity through hash verification.
domain: cybersecurity
subdomain: digital-forensics
tags: [forensics, disk-imaging, evidence-acquisition, dd, dcfldd, hash-verification]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Acquiring Disk Image with dd and dcfldd

## When to Use
- When you need to create a forensic copy of a suspect drive for investigation
- During incident response when preserving volatile disk evidence before analysis
- When law enforcement or legal proceedings require a verified bit-for-bit copy
- Before performing any destructive analysis on a storage device
- When acquiring images from physical drives, USB devices, or memory cards

## Prerequisites
- Linux-based forensic workstation (SIFT, Kali, or any Linux distro)
- `dd` (pre-installed on all Linux systems) or `dcfldd` (enhanced forensic version)
- Write-blocker hardware or software write-blocking configured
- Destination drive with sufficient storage (larger than source)
- Root/sudo privileges on the forensic workstation
- SHA-256 or MD5 hashing utilities (`sha256sum`, `md5sum`)

## Workflow

### Step 1: Identify the Target Device and Enable Write Protection

```bash
# List all connected block devices to identify the target
lsblk -o NAME,SIZE,TYPE,MOUNTPOINT,MODEL

# Verify the device details
fdisk -l /dev/sdb

# Enable software write-blocking (if no hardware blocker)
blockdev --setro /dev/sdb

# Verify read-only status
blockdev --getro /dev/sdb
# Output: 1 (means read-only is enabled)

# Alternatively, use udev rules for persistent write-blocking
echo 'SUBSYSTEM=="block", ATTRS{serial}=="WD-WCAV5H861234", ATTR{ro}="1"' > /etc/udev/rules.d/99-writeblock.rules
udevadm control --reload-rules
```

### Step 2: Prepare the Destination and Document the Source

```bash
# Create case directory structure
mkdir -p /cases/case-2024-001/{images,hashes,logs,notes}

# Document source drive information
hdparm -I /dev/sdb > /cases/case-2024-001/notes/source_drive_info.txt

# Record the serial number and model
smartctl -i /dev/sdb >> /cases/case-2024-001/notes/source_drive_info.txt

# Pre-hash the source device
sha256sum /dev/sdb | tee /cases/case-2024-001/hashes/source_hash_before.txt
```

### Step 3: Acquire the Image Using dd

```bash
# Basic dd acquisition with progress and error handling
dd if=/dev/sdb of=/cases/case-2024-001/images/evidence.dd \
   bs=4096 \
   conv=noerror,sync \
   status=progress 2>&1 | tee /cases/case-2024-001/logs/dd_acquisition.log

# For compressed images to save space
dd if=/dev/sdb bs=4096 conv=noerror,sync status=progress | \
   gzip -c > /cases/case-2024-001/images/evidence.dd.gz

# Using dd with a specific count for partial acquisition
dd if=/dev/sdb of=/cases/case-2024-001/images/first_1gb.dd \
   bs=1M count=1024 status=progress
```

### Step 4: Acquire Using dcfldd (Preferred Forensic Method)

```bash
# Install dcfldd if not present
apt-get install dcfldd

# Acquire image with built-in hashing and split output
dcfldd if=/dev/sdb \
   of=/cases/case-2024-001/images/evidence.dd \
   hash=sha256,md5 \
   hashwindow=1G \
   hashlog=/cases/case-2024-001/hashes/acquisition_hashes.txt \
   bs=4096 \
   conv=noerror,sync \
   errlog=/cases/case-2024-001/logs/dcfldd_errors.log

# Split large images into manageable segments
dcfldd if=/dev/sdb \
   of=/cases/case-2024-001/images/evidence.dd \
   hash=sha256 \
   hashlog=/cases/case-2024-001/hashes/split_hashes.txt \
   bs=4096 \
   split=2G \
   splitformat=aa

# Acquire with verification pass
dcfldd if=/dev/sdb \
   of=/cases/case-2024-001/images/evidence.dd \
   hash=sha256 \
   hashlog=/cases/case-2024-001/hashes/verification.txt \
   vf=/cases/case-2024-001/images/evidence.dd \
   verifylog=/cases/case-2024-001/logs/verify.log
```

### Step 5: Verify Image Integrity

```bash
# Hash the acquired image
sha256sum /cases/case-2024-001/images/evidence.dd | \
   tee /cases/case-2024-001/hashes/image_hash.txt

# Compare source and image hashes
diff <(sha256sum /dev/sdb | awk '{print $1}') \
     <(sha256sum /cases/case-2024-001/images/evidence.dd | awk '{print $1}')

# If using split images, verify each segment
sha256sum /cases/case-2024-001/images/evidence.dd.* | \
   tee /cases/case-2024-001/hashes/split_image_hashes.txt

# Re-hash source to confirm no changes occurred
sha256sum /dev/sdb | tee /cases/case-2024-001/hashes/source_hash_after.txt
diff /cases/case-2024-001/hashes/source_hash_before.txt \
     /cases/case-2024-001/hashes/source_hash_after.txt
```

### Step 6: Document the Acquisition Process

```bash
# Generate acquisition report
cat << 'EOF' > /cases/case-2024-001/notes/acquisition_report.txt
DISK IMAGE ACQUISITION REPORT
==============================
Case Number: 2024-001
Date/Time: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
Examiner: [Name]

Source Device: /dev/sdb
Model: [from hdparm output]
Serial: [from hdparm output]
Size: [from fdisk output]

Acquisition Tool: dcfldd v1.9.1
Block Size: 4096
Write Blocker: [Hardware/Software model]

Image File: evidence.dd
Image Hash (SHA-256): [from hash file]
Source Hash (SHA-256): [from hash file]
Hash Match: YES/NO

Errors During Acquisition: [from error log]
EOF

# Compress logs for archival
tar -czf /cases/case-2024-001/acquisition_package.tar.gz \
   /cases/case-2024-001/hashes/ \
   /cases/case-2024-001/logs/ \
   /cases/case-2024-001/notes/
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| Bit-for-bit copy | Exact replica of source including unallocated space and slack space |
| Write blocker | Hardware or software mechanism preventing writes to evidence media |
| Hash verification | Cryptographic hash comparing source and image to prove integrity |
| Block size (bs) | Transfer chunk size affecting speed; 4096 or 64K typical for forensics |
| conv=noerror,sync | Continue on read errors and pad with zeros to maintain offset alignment |
| Chain of custody | Documented trail proving evidence has not been tampered with |
| Split imaging | Breaking large images into smaller files for storage and transport |
| Raw/dd format | Bit-for-bit image format without metadata container overhead |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| dd | Standard Unix disk duplication utility for raw imaging |
| dcfldd | DoD Computer Forensics Laboratory enhanced version of dd with hashing |
| dc3dd | Another forensic dd variant from the DoD Cyber Crime Center |
| sha256sum | SHA-256 hash calculation for integrity verification |
| blockdev | Linux command to set block device read-only mode |
| hdparm | Drive identification and parameter reporting |
| smartctl | S.M.A.R.T. data retrieval for drive health and identification |
| lsblk | Block device enumeration and identification |

## Common Scenarios

**Scenario 1: Acquiring a Suspect Laptop Hard Drive**
Connect the drive via a Tableau T35u hardware write-blocker, identify as `/dev/sdb`, use dcfldd with SHA-256 hashing, split into 4GB segments for DVD archival, verify hashes match, document in case notes.

**Scenario 2: Imaging a USB Flash Drive from a Compromised Workstation**
Use software write-blocking with `blockdev --setro`, acquire with dcfldd including MD5 and SHA-256 dual hashing, image is small enough for single file, verify and store on encrypted case drive.

**Scenario 3: Remote Acquisition Over Network**
Use dd piped through netcat or ssh for remote acquisition: `ssh root@remote "dd if=/dev/sda bs=4096" | dd of=remote_image.dd bs=4096`, hash both ends independently to verify transfer integrity.

**Scenario 4: Acquiring from a Failing Drive**
Use `ddrescue` first to recover readable sectors, then use dd with `conv=noerror,sync` to fill gaps with zeros, document which sectors were unreadable in the error log.

## Output Format

```
Acquisition Summary:
  Source:       /dev/sdb (500GB Western Digital WD5000AAKX)
  Destination:  /cases/case-2024-001/images/evidence.dd
  Tool:         dcfldd 1.9.1
  Block Size:   4096 bytes
  Duration:     2h 15m 32s
  Bytes Copied: 500,107,862,016
  Errors:       0 bad sectors
  Source SHA-256:  a3f2b8c9d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1
  Image SHA-256:   a3f2b8c9d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1
  Verification:    PASSED - Hashes match
```
