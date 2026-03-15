---
name: performing-cloud-storage-forensic-acquisition
description: Perform forensic acquisition and analysis of cloud storage services including Google Drive, OneDrive, Dropbox, and Box by collecting both API-based remote data and local sync client artifacts from endpoint devices.
domain: cybersecurity
subdomain: digital-forensics
tags: [cloud-forensics, google-drive, onedrive, dropbox, box, cloud-acquisition, api-forensics, sync-client, endpoint-artifacts, magnet-axiom]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Performing Cloud Storage Forensic Acquisition

## Overview

Cloud storage forensic acquisition involves collecting digital evidence from services like Google Drive, OneDrive, Dropbox, and Box through both API-based remote acquisition and local endpoint artifact analysis. Modern investigations must address the challenge that cloud-synced files may exist in multiple states: locally synchronized, cloud-only (on-demand), cached, and deleted. Endpoint devices that have synchronized with cloud storage contain a wealth of metadata about locally synced files, files present only in the cloud, and even deleted items recoverable from cache folders. API-based acquisition using service-specific APIs provides direct access to remote data with valid credentials and proper legal authorization.

## Prerequisites

- Legal authorization (warrant, consent, or corporate policy) for cloud data access
- Valid user credentials or administrative access tokens
- Magnet AXIOM Cloud, Cellebrite Cloud Analyzer, or equivalent tool
- KAPE with cloud storage target files
- Python 3.8+ with google-api-python-client, msal, dropbox SDK
- Network connectivity for API-based acquisition

## Acquisition Methods

### Method 1: API-Based Remote Acquisition

#### Google Drive API Acquisition

```python
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload
import io
import os
import json
from datetime import datetime


class GoogleDriveForensicAcquisition:
    """Forensically acquire files and metadata from Google Drive via API."""

    def __init__(self, credentials_path: str, output_dir: str):
        self.creds = Credentials.from_authorized_user_file(credentials_path)
        self.service = build("drive", "v3", credentials=self.creds)
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.acquisition_log = []

    def list_all_files(self, include_trashed: bool = True) -> list:
        """List all files including trashed items."""
        files = []
        page_token = None
        query = "" if include_trashed else "trashed = false"

        while True:
            results = self.service.files().list(
                q=query,
                pageSize=1000,
                fields="nextPageToken, files(id, name, mimeType, size, "
                       "createdTime, modifiedTime, trashed, trashedTime, "
                       "owners, sharingUser, permissions, md5Checksum, "
                       "parents, webViewLink, driveId)",
                pageToken=page_token
            ).execute()

            files.extend(results.get("files", []))
            page_token = results.get("nextPageToken")
            if not page_token:
                break

        return files

    def download_file(self, file_id: str, file_name: str, mime_type: str) -> str:
        """Download a file from Google Drive preserving forensic integrity."""
        output_path = os.path.join(self.output_dir, file_name)

        if mime_type.startswith("application/vnd.google-apps"):
            export_formats = {
                "application/vnd.google-apps.document": "application/pdf",
                "application/vnd.google-apps.spreadsheet": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                "application/vnd.google-apps.presentation": "application/pdf",
            }
            export_mime = export_formats.get(mime_type, "application/pdf")
            request = self.service.files().export_media(fileId=file_id, mimeType=export_mime)
        else:
            request = self.service.files().get_media(fileId=file_id)

        with io.FileIO(output_path, "wb") as fh:
            downloader = MediaIoBaseDownload(fh, request)
            done = False
            while not done:
                _, done = downloader.next_chunk()

        self.acquisition_log.append({
            "timestamp": datetime.utcnow().isoformat(),
            "file_id": file_id,
            "file_name": file_name,
            "output_path": output_path,
            "action": "downloaded"
        })
        return output_path

    def get_activity_log(self, file_id: str) -> list:
        """Retrieve activity/revision history for a specific file."""
        revisions = self.service.revisions().list(
            fileId=file_id,
            fields="revisions(id, modifiedTime, lastModifyingUser, size, md5Checksum)"
        ).execute()
        return revisions.get("revisions", [])

    def export_acquisition_report(self) -> str:
        """Export acquisition log for chain of custody documentation."""
        report_path = os.path.join(self.output_dir, "acquisition_log.json")
        with open(report_path, "w") as f:
            json.dump({
                "acquisition_start": self.acquisition_log[0]["timestamp"] if self.acquisition_log else None,
                "acquisition_end": datetime.utcnow().isoformat(),
                "total_files": len(self.acquisition_log),
                "entries": self.acquisition_log
            }, f, indent=2)
        return report_path
```

#### OneDrive / Microsoft 365 API Acquisition

```python
import msal
import requests
import os
import json
from datetime import datetime


class OneDriveForensicAcquisition:
    """Forensically acquire files and metadata from OneDrive via Microsoft Graph API."""

    def __init__(self, client_id: str, tenant_id: str, client_secret: str, output_dir: str):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

        authority = f"https://login.microsoftonline.com/{tenant_id}"
        self.app = msal.ConfidentialClientApplication(
            client_id, authority=authority, client_credential=client_secret
        )
        token_result = self.app.acquire_token_for_client(
            scopes=["https://graph.microsoft.com/.default"]
        )
        self.access_token = token_result.get("access_token")
        self.headers = {"Authorization": f"Bearer {self.access_token}"}
        self.base_url = "https://graph.microsoft.com/v1.0"

    def list_user_files(self, user_id: str) -> list:
        """List all files in user's OneDrive."""
        url = f"{self.base_url}/users/{user_id}/drive/root/children"
        files = []
        while url:
            response = requests.get(url, headers=self.headers)
            data = response.json()
            files.extend(data.get("value", []))
            url = data.get("@odata.nextLink")
        return files

    def download_file(self, user_id: str, item_id: str, filename: str) -> str:
        """Download a file from OneDrive."""
        url = f"{self.base_url}/users/{user_id}/drive/items/{item_id}/content"
        response = requests.get(url, headers=self.headers, stream=True)
        output_path = os.path.join(self.output_dir, filename)
        with open(output_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        return output_path

    def get_deleted_items(self, user_id: str) -> list:
        """Retrieve items from OneDrive recycle bin."""
        url = f"{self.base_url}/users/{user_id}/drive/special/recyclebin/children"
        response = requests.get(url, headers=self.headers)
        return response.json().get("value", [])
```

### Method 2: Local Endpoint Artifact Collection

#### KAPE Targets for Cloud Storage

```powershell
# Collect all cloud storage artifacts using KAPE
kape.exe --tsource C: --tdest C:\Output\CloudArtifacts --target GoogleDrive,OneDrive,Dropbox,Box

# OneDrive artifacts
# %USERPROFILE%\AppData\Local\Microsoft\OneDrive\logs\
# %USERPROFILE%\AppData\Local\Microsoft\OneDrive\settings\
# %USERPROFILE%\OneDrive\

# Google Drive artifacts
# %USERPROFILE%\AppData\Local\Google\DriveFS\
# Contains metadata SQLite databases and cached files

# Dropbox artifacts
# %USERPROFILE%\AppData\Local\Dropbox\
# %USERPROFILE%\Dropbox\.dropbox.cache\
# Contains filecache.dbx (encrypted SQLite), host.dbx, config.dbx
```

#### OneDrive Local Database Analysis

```python
import sqlite3
import os

def analyze_onedrive_sync_engine(db_path: str) -> list:
    """Analyze OneDrive SyncEngineDatabase for file metadata."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Query for all tracked files including cloud-only items
    cursor.execute("""
        SELECT fileName, fileSize, lastChange,
               resourceID, parentResourceID, eTag
        FROM od_ClientFile_Records
        ORDER BY lastChange DESC
    """)

    files = []
    for row in cursor.fetchall():
        files.append({
            "filename": row[0],
            "size": row[1],
            "last_change": row[2],
            "resource_id": row[3],
            "parent_id": row[4],
            "etag": row[5]
        })

    conn.close()
    return files
```

## Cloud Storage Artifacts Summary

| Service | Local Database | Cache Location | Log Files |
|---------|---------------|----------------|-----------|
| OneDrive | SyncEngineDatabase.db | %LOCALAPPDATA%\Microsoft\OneDrive\cache\ | %LOCALAPPDATA%\Microsoft\OneDrive\logs\ |
| Google Drive | metadata_sqlite_db | %LOCALAPPDATA%\Google\DriveFS\{account}\content_cache\ | %LOCALAPPDATA%\Google\DriveFS\Logs\ |
| Dropbox | filecache.dbx (encrypted) | %APPDATA%\Dropbox\.dropbox.cache\ | %APPDATA%\Dropbox\logs\ |
| Box | sync_db | %LOCALAPPDATA%\Box\Box\cache\ | %LOCALAPPDATA%\Box\Box\logs\ |

## References

- SANS Cloud Storage Acquisition: https://www.sans.org/blog/cloud-storage-acquisition-from-endpoint-devices
- Magnet AXIOM Cloud: https://www.magnetforensics.com/blog/how-to-acquire-and-analyze-cloud-data-with-magnet-axiom/
- AWS Cloud Forensics Framework: https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/cyber-forensics.html
- API-Based Forensic Acquisition of Cloud Drives: https://arxiv.org/abs/1603.06542
