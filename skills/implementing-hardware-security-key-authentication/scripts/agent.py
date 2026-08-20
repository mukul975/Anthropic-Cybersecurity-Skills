#!/usr/bin/env python3
"""FIDO2/WebAuthn Hardware Security Key Authentication Server.

Implements a complete WebAuthn relying party with registration ceremonies,
authentication flows, YubiKey enrollment management, and passkey support
using the python-fido2 library.

For authorized deployment and security testing only.
"""

import argparse
import hashlib
import json
import logging
import os
import secrets
import sqlite3
import sys
from base64 import urlsafe_b64encode
from datetime import datetime, timezone

from flask import Flask, abort, jsonify, request, session, render_template_string

from fido2.server import Fido2Server
from fido2.webauthn import (
    AttestationConveyancePreference,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Database layer
# ---------------------------------------------------------------------------

def init_database(db_path: str) -> sqlite3.Connection:
    """Initialize SQLite database for credential and user storage."""
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_handle BLOB UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            display_name TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            passkey_only INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            credential_id BLOB UNIQUE NOT NULL,
            public_key BLOB NOT NULL,
            sign_count INTEGER NOT NULL DEFAULT 0,
            aaguid TEXT,
            label TEXT,
            transports TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            last_used TEXT,
            is_discoverable INTEGER DEFAULT 0,
            is_revoked INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS auth_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            credential_id BLOB,
            event_type TEXT NOT NULL,
            success INTEGER NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            details TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS recovery_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            code_hash TEXT UNIQUE NOT NULL,
            used INTEGER DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_creds_user ON credentials(user_id);
        CREATE INDEX IF NOT EXISTS idx_creds_cred_id ON credentials(credential_id);
        CREATE INDEX IF NOT EXISTS idx_events_user ON auth_events(user_id);
    """)
    conn.commit()
    return conn


# ---------------------------------------------------------------------------
# User management
# ---------------------------------------------------------------------------

def create_user(conn: sqlite3.Connection, username: str, display_name: str) -> dict:
    """Create a new user with a random user handle."""
    user_handle = secrets.token_bytes(32)
    try:
        conn.execute(
            "INSERT INTO users (user_handle, username, display_name) VALUES (?, ?, ?)",
            (user_handle, username, display_name),
        )
        conn.commit()
        user_id = conn.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()[0]
        logger.info("Created user: %s (ID: %d)", username, user_id)
        return {
            "id": user_id,
            "user_handle": user_handle,
            "username": username,
            "display_name": display_name,
        }
    except sqlite3.IntegrityError:
        logger.warning("User already exists: %s", username)
        return get_user_by_username(conn, username)


def get_user_by_username(conn: sqlite3.Connection, username: str) -> dict | None:
    """Retrieve user by username."""
    row = conn.execute(
        "SELECT id, user_handle, username, display_name, passkey_only FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    if not row:
        return None
    return {
        "id": row[0],
        "user_handle": row[1],
        "username": row[2],
        "display_name": row[3],
        "passkey_only": bool(row[4]),
    }


def get_user_by_handle(conn: sqlite3.Connection, user_handle: bytes) -> dict | None:
    """Retrieve user by user handle (for discoverable credential flows)."""
    row = conn.execute(
        "SELECT id, user_handle, username, display_name, passkey_only FROM users WHERE user_handle = ?",
        (user_handle,),
    ).fetchone()
    if not row:
        return None
    return {
        "id": row[0],
        "user_handle": row[1],
        "username": row[2],
        "display_name": row[3],
        "passkey_only": bool(row[4]),
    }


# ---------------------------------------------------------------------------
# Credential management
# ---------------------------------------------------------------------------

def store_credential(
    conn: sqlite3.Connection,
    user_id: int,
    credential_id: bytes,
    public_key: bytes,
    sign_count: int,
    aaguid: str = None,
    label: str = None,
    transports: list[str] = None,
    is_discoverable: bool = False,
) -> int:
    """Store a new WebAuthn credential in the database."""
    cursor = conn.execute(
        """INSERT INTO credentials
           (user_id, credential_id, public_key, sign_count, aaguid, label,
            transports, is_discoverable)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            user_id, credential_id, public_key, sign_count,
            aaguid, label,
            json.dumps(transports) if transports else None,
            1 if is_discoverable else 0,
        ),
    )
    conn.commit()
    cred_id = cursor.lastrowid
    logger.info(
        "Stored credential for user %d: %s (label: %s)",
        user_id, urlsafe_b64encode(credential_id).decode(), label,
    )
    return cred_id


def get_user_credentials(conn: sqlite3.Connection, user_id: int) -> list[dict]:
    """Get all active credentials for a user."""
    rows = conn.execute(
        """SELECT id, credential_id, public_key, sign_count, aaguid, label,
                  transports, created_at, last_used, is_discoverable
           FROM credentials
           WHERE user_id = ? AND is_revoked = 0""",
        (user_id,),
    ).fetchall()
    creds = []
    for row in rows:
        creds.append({
            "db_id": row[0],
            "credential_id": row[1],
            "public_key": row[2],
            "sign_count": row[3],
            "aaguid": row[4],
            "label": row[5],
            "transports": json.loads(row[6]) if row[6] else [],
            "created_at": row[7],
            "last_used": row[8],
            "is_discoverable": bool(row[9]),
        })
    return creds


def get_all_credentials(conn: sqlite3.Connection) -> list[dict]:
    """Get all active credentials across all users (for discoverable flows)."""
    rows = conn.execute(
        """SELECT c.credential_id, c.public_key, c.sign_count, u.user_handle
           FROM credentials c JOIN users u ON c.user_id = u.id
           WHERE c.is_revoked = 0"""
    ).fetchall()
    return [
        {
            "credential_id": r[0],
            "public_key": r[1],
            "sign_count": r[2],
            "user_handle": r[3],
        }
        for r in rows
    ]


def revoke_credential(conn: sqlite3.Connection, credential_db_id: int, user_id: int) -> bool:
    """Revoke a credential (soft delete)."""
    cursor = conn.execute(
        "UPDATE credentials SET is_revoked = 1 WHERE id = ? AND user_id = ?",
        (credential_db_id, user_id),
    )
    conn.commit()
    return cursor.rowcount > 0


def update_sign_count(conn: sqlite3.Connection, credential_id: bytes, new_count: int):
    """Update the sign count and last-used timestamp after authentication."""
    conn.execute(
        "UPDATE credentials SET sign_count = ?, last_used = datetime('now') WHERE credential_id = ?",
        (new_count, credential_id),
    )
    conn.commit()


# ---------------------------------------------------------------------------
# Recovery codes
# ---------------------------------------------------------------------------

def generate_recovery_codes(conn: sqlite3.Connection, user_id: int, count: int = 8) -> list[str]:
    """Generate one-time recovery codes for account recovery."""
    # Invalidate existing codes
    conn.execute("DELETE FROM recovery_codes WHERE user_id = ?", (user_id,))
    codes = []
    for _ in range(count):
        code = secrets.token_hex(4).upper()  # 8-char hex code
        code_hash = hashlib.sha256(code.encode()).hexdigest()
        conn.execute(
            "INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)",
            (user_id, code_hash),
        )
        codes.append(code)
    conn.commit()
    logger.info("Generated %d recovery codes for user %d", count, user_id)
    return codes


def verify_recovery_code(conn: sqlite3.Connection, user_id: int, code: str) -> bool:
    """Verify and consume a recovery code."""
    code_hash = hashlib.sha256(code.strip().upper().encode()).hexdigest()
    row = conn.execute(
        "SELECT id FROM recovery_codes WHERE user_id = ? AND code_hash = ? AND used = 0",
        (user_id, code_hash),
    ).fetchone()
    if not row:
        return False
    conn.execute("UPDATE recovery_codes SET used = 1 WHERE id = ?", (row[0],))
    conn.commit()
    return True


# ---------------------------------------------------------------------------
# Auth event logging
# ---------------------------------------------------------------------------

def log_auth_event(
    conn: sqlite3.Connection,
    user_id: int,
    event_type: str,
    success: bool,
    credential_id: bytes = None,
    ip_address: str = None,
    user_agent: str = None,
    details: str = None,
):
    """Log an authentication event for auditing."""
    conn.execute(
        """INSERT INTO auth_events
           (user_id, credential_id, event_type, success, ip_address, user_agent, details)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (user_id, credential_id, event_type, 1 if success else 0,
         ip_address, user_agent, details),
    )
    conn.commit()


# ---------------------------------------------------------------------------
# Credential data helpers for python-fido2
# ---------------------------------------------------------------------------

def build_credential_descriptors(creds: list[dict]) -> list:
    """Build PublicKeyCredentialDescriptor list from stored credentials."""
    descriptors = []
    for c in creds:
        desc = PublicKeyCredentialDescriptor(
            type="public-key",
            id=c["credential_id"],
        )
        descriptors.append(desc)
    return descriptors


def reconstruct_credential_data(creds: list[dict]):
    """Reconstruct AttestedCredentialData objects from stored credentials.

    The python-fido2 library's Fido2Server.authenticate_complete expects
    credential data objects that contain credential_id and public_key.
    We rebuild them from our database records.
    """
    from fido2.webauthn import AttestedCredentialData
    result = []
    for c in creds:
        cred_data = AttestedCredentialData.create(
            aaguid=bytes.fromhex(c["aaguid"]) if c.get("aaguid") else b"\x00" * 16,
            credential_id=c["credential_id"],
            public_key=c["public_key"],
        )
        result.append(cred_data)
    return result


# ---------------------------------------------------------------------------
# Flask application factory
# ---------------------------------------------------------------------------

INDEX_HTML = """<!DOCTYPE html>
<html>
<head>
    <title>FIDO2 WebAuthn Demo</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
               max-width: 700px; margin: 40px auto; padding: 0 20px; }
        h1 { color: #333; }
        .section { background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 8px;
                   padding: 20px; margin: 20px 0; }
        input { padding: 8px 12px; margin: 5px; border: 1px solid #ced4da; border-radius: 4px; }
        button { padding: 8px 16px; margin: 5px; border: none; border-radius: 4px;
                 cursor: pointer; font-weight: 500; }
        .btn-primary { background: #0d6efd; color: white; }
        .btn-success { background: #198754; color: white; }
        .btn-danger { background: #dc3545; color: white; }
        #status { margin-top: 20px; padding: 10px; border-radius: 4px; display: none; }
        .success { background: #d1e7dd; color: #0f5132; display: block !important; }
        .error { background: #f8d7da; color: #842029; display: block !important; }
        .info { background: #cff4fc; color: #055160; display: block !important; }
    </style>
</head>
<body>
    <h1>FIDO2 / WebAuthn Authentication</h1>

    <div class="section">
        <h2>Register</h2>
        <input type="text" id="reg-username" placeholder="Username" />
        <input type="text" id="reg-display" placeholder="Display Name" />
        <br/>
        <label><input type="checkbox" id="reg-resident" /> Discoverable credential (passkey)</label>
        <br/>
        <button class="btn-primary" onclick="doRegister()">Register Security Key</button>
    </div>

    <div class="section">
        <h2>Authenticate</h2>
        <input type="text" id="auth-username" placeholder="Username (optional for passkeys)" />
        <button class="btn-success" onclick="doAuthenticate()">Authenticate</button>
    </div>

    <div id="status"></div>

    <script>
        function b64encode(buf) {
            return btoa(String.fromCharCode(...new Uint8Array(buf)))
                .replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
        }
        function b64decode(str) {
            str = str.replace(/-/g, '+').replace(/_/g, '/');
            while (str.length % 4) str += '=';
            return Uint8Array.from(atob(str), c => c.charCodeAt(0)).buffer;
        }
        function showStatus(msg, type) {
            const el = document.getElementById('status');
            el.textContent = msg;
            el.className = type;
        }

        async function doRegister() {
            const username = document.getElementById('reg-username').value;
            const displayName = document.getElementById('reg-display').value || username;
            const resident = document.getElementById('reg-resident').checked;
            if (!username) { showStatus('Username required', 'error'); return; }

            try {
                showStatus('Starting registration...', 'info');
                const beginResp = await fetch('/api/register/begin', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({username, display_name: displayName, resident_key: resident})
                });
                if (!beginResp.ok) throw new Error(await beginResp.text());
                const options = await beginResp.json();

                // Decode binary fields
                options.publicKey.challenge = b64decode(options.publicKey.challenge);
                options.publicKey.user.id = b64decode(options.publicKey.user.id);
                if (options.publicKey.excludeCredentials) {
                    options.publicKey.excludeCredentials.forEach(c => { c.id = b64decode(c.id); });
                }

                showStatus('Touch your security key...', 'info');
                const credential = await navigator.credentials.create(options);

                const completeResp = await fetch('/api/register/complete', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        id: credential.id,
                        rawId: b64encode(credential.rawId),
                        type: credential.type,
                        response: {
                            attestationObject: b64encode(credential.response.attestationObject),
                            clientDataJSON: b64encode(credential.response.clientDataJSON),
                        }
                    })
                });
                if (!completeResp.ok) throw new Error(await completeResp.text());
                const result = await completeResp.json();
                showStatus('Registration successful! ' + (result.recovery_codes ?
                    'Recovery codes: ' + result.recovery_codes.join(', ') : ''), 'success');
            } catch (err) {
                showStatus('Registration failed: ' + err.message, 'error');
            }
        }

        async function doAuthenticate() {
            const username = document.getElementById('auth-username').value;
            try {
                showStatus('Starting authentication...', 'info');
                const beginResp = await fetch('/api/authenticate/begin', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({username: username || null})
                });
                if (!beginResp.ok) throw new Error(await beginResp.text());
                const options = await beginResp.json();

                options.publicKey.challenge = b64decode(options.publicKey.challenge);
                if (options.publicKey.allowCredentials) {
                    options.publicKey.allowCredentials.forEach(c => { c.id = b64decode(c.id); });
                }

                showStatus('Touch your security key...', 'info');
                const assertion = await navigator.credentials.get(options);

                const completeResp = await fetch('/api/authenticate/complete', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        id: assertion.id,
                        rawId: b64encode(assertion.rawId),
                        type: assertion.type,
                        response: {
                            authenticatorData: b64encode(assertion.response.authenticatorData),
                            clientDataJSON: b64encode(assertion.response.clientDataJSON),
                            signature: b64encode(assertion.response.signature),
                            userHandle: assertion.response.userHandle ?
                                b64encode(assertion.response.userHandle) : null,
                        }
                    })
                });
                if (!completeResp.ok) throw new Error(await completeResp.text());
                const result = await completeResp.json();
                showStatus('Authentication successful! Welcome, ' + result.username, 'success');
            } catch (err) {
                showStatus('Authentication failed: ' + err.message, 'error');
            }
        }
    </script>
</body>
</html>"""


def create_app(
    rp_id: str,
    rp_name: str,
    db_path: str,
    attestation: str = "none",
    user_verification: str = "preferred",
) -> Flask:
    """Create and configure the Flask application with WebAuthn endpoints."""
    app = Flask(__name__)
    app.secret_key = os.urandom(32)
    app.config["SESSION_COOKIE_SECURE"] = rp_id != "localhost"
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Strict"

    rp = PublicKeyCredentialRpEntity(name=rp_name, id=rp_id)
    server = Fido2Server(rp)
    conn = init_database(db_path)

    attestation_pref = {
        "none": AttestationConveyancePreference.NONE,
        "indirect": AttestationConveyancePreference.INDIRECT,
        "direct": AttestationConveyancePreference.DIRECT,
        "enterprise": AttestationConveyancePreference.ENTERPRISE,
    }.get(attestation, AttestationConveyancePreference.NONE)

    uv_pref = {
        "required": UserVerificationRequirement.REQUIRED,
        "preferred": UserVerificationRequirement.PREFERRED,
        "discouraged": UserVerificationRequirement.DISCOURAGED,
    }.get(user_verification, UserVerificationRequirement.PREFERRED)

    @app.route("/")
    def index():
        return render_template_string(INDEX_HTML)

    # ------ Registration endpoints ------

    @app.route("/api/register/begin", methods=["POST"])
    def register_begin():
        data = request.get_json()
        if not data or not data.get("username"):
            abort(400, "username required")
        username = data["username"]
        display_name = data.get("display_name", username)
        resident_key = data.get("resident_key", False)

        user = get_user_by_username(conn, username)
        if not user:
            user = create_user(conn, username, display_name)

        # Get existing credentials to exclude
        existing_creds = get_user_credentials(conn, user["id"])
        exclude_list = build_credential_descriptors(existing_creds)

        resident_req = (
            ResidentKeyRequirement.REQUIRED if resident_key
            else ResidentKeyRequirement.DISCOURAGED
        )

        registration_data, state = server.register_begin(
            PublicKeyCredentialUserEntity(
                id=user["user_handle"],
                name=user["username"],
                display_name=user["display_name"],
            ),
            credentials=reconstruct_credential_data(existing_creds) if existing_creds else [],
            user_verification=uv_pref,
            authenticator_attachment=None,
            resident_key_requirement=resident_req,
        )
        session["reg_state"] = state
        session["reg_user_id"] = user["id"]
        session["reg_resident"] = resident_key

        # Serialize for JSON response
        options = dict(registration_data)
        return jsonify(options)

    @app.route("/api/register/complete", methods=["POST"])
    def register_complete():
        data = request.get_json()
        if not data:
            abort(400, "No credential response")

        state = session.pop("reg_state", None)
        user_id = session.pop("reg_user_id", None)
        is_resident = session.pop("reg_resident", False)
        if not state or not user_id:
            abort(400, "No pending registration")

        try:
            auth_data = server.register_complete(state, data)
        except Exception as exc:
            logger.warning("Registration verification failed: %s", exc)
            log_auth_event(
                conn, user_id, "registration", False,
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent", ""),
                details=str(exc),
            )
            abort(400, f"Registration failed: {exc}")

        cred_data = auth_data.credential_data
        aaguid_hex = cred_data.aaguid.hex() if hasattr(cred_data, "aaguid") else None

        store_credential(
            conn,
            user_id=user_id,
            credential_id=cred_data.credential_id,
            public_key=cred_data.public_key,
            sign_count=auth_data.sign_count if hasattr(auth_data, "sign_count") else 0,
            aaguid=aaguid_hex,
            label=data.get("label", f"Key registered {datetime.now(timezone.utc).strftime('%Y-%m-%d')}"),
            is_discoverable=is_resident,
        )

        log_auth_event(
            conn, user_id, "registration", True,
            credential_id=cred_data.credential_id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent", ""),
        )

        # Generate recovery codes on first credential registration
        user_creds = get_user_credentials(conn, user_id)
        response_data = {"status": "OK"}
        if len(user_creds) == 1:
            codes = generate_recovery_codes(conn, user_id)
            response_data["recovery_codes"] = codes
            response_data["message"] = "Save these recovery codes securely. They will not be shown again."

        return jsonify(response_data)

    # ------ Authentication endpoints ------

    @app.route("/api/authenticate/begin", methods=["POST"])
    def authenticate_begin():
        data = request.get_json() or {}
        username = data.get("username")

        if username:
            user = get_user_by_username(conn, username)
            if not user:
                abort(404, "User not found")
            existing_creds = get_user_credentials(conn, user["id"])
            if not existing_creds:
                abort(404, "No credentials registered")
            cred_data = reconstruct_credential_data(existing_creds)
            session["auth_user_id"] = user["id"]
        else:
            # Discoverable credential flow (passwordless)
            cred_data = []
            session["auth_user_id"] = None

        auth_data, state = server.authenticate_begin(
            credentials=cred_data if cred_data else None,
            user_verification=uv_pref,
        )
        session["auth_state"] = state

        options = dict(auth_data)
        return jsonify(options)

    @app.route("/api/authenticate/complete", methods=["POST"])
    def authenticate_complete():
        data = request.get_json()
        if not data:
            abort(400, "No assertion response")

        state = session.pop("auth_state", None)
        expected_user_id = session.pop("auth_user_id", None)
        if not state:
            abort(400, "No pending authentication")

        # Gather all credentials that could match
        if expected_user_id:
            user_creds = get_user_credentials(conn, expected_user_id)
            cred_data = reconstruct_credential_data(user_creds)
        else:
            # For discoverable credentials, gather all credentials
            all_creds = get_all_credentials(conn)
            user_creds = all_creds
            cred_data = reconstruct_credential_data(all_creds)

        try:
            auth_result = server.authenticate_complete(
                state,
                credentials=cred_data,
                response=data,
            )
        except Exception as exc:
            logger.warning("Authentication verification failed: %s", exc)
            if expected_user_id:
                log_auth_event(
                    conn, expected_user_id, "authentication", False,
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get("User-Agent", ""),
                    details=str(exc),
                )
            abort(401, f"Authentication failed: {exc}")

        # Find the credential that was used
        used_cred_id = auth_result.credential_id
        new_sign_count = auth_result.new_sign_count

        # Detect sign count regression (possible cloned key)
        for c in user_creds:
            if c["credential_id"] == used_cred_id:
                if new_sign_count <= c["sign_count"] and new_sign_count != 0:
                    logger.warning(
                        "SECURITY: Sign count regression for credential %s "
                        "(stored: %d, received: %d) -- possible cloned key!",
                        urlsafe_b64encode(used_cred_id).decode(),
                        c["sign_count"], new_sign_count,
                    )
                break

        update_sign_count(conn, used_cred_id, new_sign_count)

        # Determine user from credential for discoverable flows
        if expected_user_id:
            user_id = expected_user_id
        else:
            # Look up user by credential
            row = conn.execute(
                "SELECT user_id FROM credentials WHERE credential_id = ?",
                (used_cred_id,),
            ).fetchone()
            user_id = row[0] if row else None

        if user_id:
            user = conn.execute(
                "SELECT username, display_name FROM users WHERE id = ?", (user_id,)
            ).fetchone()
            username = user[0] if user else "unknown"
            log_auth_event(
                conn, user_id, "authentication", True,
                credential_id=used_cred_id,
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent", ""),
            )
        else:
            username = "unknown"

        session["authenticated_user"] = username
        return jsonify({"status": "OK", "username": username})

    # ------ Key management endpoints ------

    @app.route("/api/keys", methods=["GET"])
    def list_keys():
        username = session.get("authenticated_user")
        if not username:
            abort(401, "Not authenticated")
        user = get_user_by_username(conn, username)
        if not user:
            abort(404, "User not found")
        creds = get_user_credentials(conn, user["id"])
        return jsonify([
            {
                "id": c["db_id"],
                "label": c["label"],
                "aaguid": c["aaguid"],
                "created_at": c["created_at"],
                "last_used": c["last_used"],
                "sign_count": c["sign_count"],
                "is_discoverable": c["is_discoverable"],
                "credential_id_b64": urlsafe_b64encode(c["credential_id"]).decode(),
            }
            for c in creds
        ])

    @app.route("/api/keys/<int:key_id>/revoke", methods=["POST"])
    def revoke_key(key_id):
        username = session.get("authenticated_user")
        if not username:
            abort(401, "Not authenticated")
        user = get_user_by_username(conn, username)
        if not user:
            abort(404, "User not found")

        # Ensure at least one credential remains
        creds = get_user_credentials(conn, user["id"])
        if len(creds) <= 1:
            abort(400, "Cannot revoke last credential")

        if revoke_credential(conn, key_id, user["id"]):
            log_auth_event(
                conn, user["id"], "key_revocation", True,
                ip_address=request.remote_addr,
                details=f"Revoked key ID {key_id}",
            )
            return jsonify({"status": "OK", "message": f"Key {key_id} revoked"})
        abort(404, "Key not found")

    @app.route("/api/keys/<int:key_id>/label", methods=["PUT"])
    def update_key_label(key_id):
        username = session.get("authenticated_user")
        if not username:
            abort(401, "Not authenticated")
        user = get_user_by_username(conn, username)
        if not user:
            abort(404)
        data = request.get_json() or {}
        label = data.get("label", "")
        if not label:
            abort(400, "label required")
        conn.execute(
            "UPDATE credentials SET label = ? WHERE id = ? AND user_id = ?",
            (label, key_id, user["id"]),
        )
        conn.commit()
        return jsonify({"status": "OK"})

    # ------ Recovery endpoint ------

    @app.route("/api/recover", methods=["POST"])
    def recover_account():
        data = request.get_json() or {}
        username = data.get("username")
        code = data.get("recovery_code")
        if not username or not code:
            abort(400, "username and recovery_code required")
        user = get_user_by_username(conn, username)
        if not user:
            abort(404, "User not found")
        if verify_recovery_code(conn, user["id"], code):
            session["authenticated_user"] = username
            session["recovery_mode"] = True
            log_auth_event(
                conn, user["id"], "recovery", True,
                ip_address=request.remote_addr,
                details="Authenticated via recovery code",
            )
            return jsonify({
                "status": "OK",
                "message": "Recovery successful. Please register a new security key immediately.",
            })
        log_auth_event(
            conn, user["id"], "recovery", False,
            ip_address=request.remote_addr,
            details="Invalid recovery code",
        )
        abort(401, "Invalid recovery code")

    # ------ Admin/reporting endpoints ------

    @app.route("/api/admin/stats", methods=["GET"])
    def admin_stats():
        total_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        total_creds = conn.execute(
            "SELECT COUNT(*) FROM credentials WHERE is_revoked = 0"
        ).fetchone()[0]
        users_with_backup = conn.execute(
            """SELECT COUNT(DISTINCT user_id) FROM credentials
               WHERE is_revoked = 0
               GROUP BY user_id HAVING COUNT(*) >= 2"""
        ).fetchall()
        recent_auths = conn.execute(
            """SELECT COUNT(*) FROM auth_events
               WHERE event_type = 'authentication' AND success = 1
               AND created_at >= datetime('now', '-30 days')"""
        ).fetchone()[0]
        auth_failures = conn.execute(
            """SELECT COUNT(*) FROM auth_events
               WHERE event_type = 'authentication' AND success = 0
               AND created_at >= datetime('now', '-30 days')"""
        ).fetchone()[0]
        sign_count_warnings = conn.execute(
            """SELECT COUNT(*) FROM auth_events
               WHERE details LIKE '%sign count regression%'
               AND created_at >= datetime('now', '-30 days')"""
        ).fetchone()[0]

        # AAGUID distribution (authenticator model breakdown)
        aaguid_dist = conn.execute(
            """SELECT aaguid, COUNT(*) as cnt
               FROM credentials WHERE is_revoked = 0 AND aaguid IS NOT NULL
               GROUP BY aaguid ORDER BY cnt DESC"""
        ).fetchall()

        return jsonify({
            "total_users": total_users,
            "total_active_credentials": total_creds,
            "users_with_backup_key": len(users_with_backup),
            "auth_last_30_days": recent_auths,
            "auth_failures_last_30_days": auth_failures,
            "sign_count_regressions_30d": sign_count_warnings,
            "authenticator_models": [
                {"aaguid": r[0], "count": r[1]} for r in aaguid_dist
            ],
        })

    @app.route("/api/admin/audit-log", methods=["GET"])
    def audit_log():
        limit = request.args.get("limit", 100, type=int)
        rows = conn.execute(
            """SELECT ae.created_at, u.username, ae.event_type, ae.success,
                      ae.ip_address, ae.details
               FROM auth_events ae JOIN users u ON ae.user_id = u.id
               ORDER BY ae.created_at DESC LIMIT ?""",
            (min(limit, 1000),),
        ).fetchall()
        return jsonify([
            {
                "timestamp": r[0], "username": r[1], "event": r[2],
                "success": bool(r[3]), "ip": r[4], "details": r[5],
            }
            for r in rows
        ])

    return app


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="FIDO2/WebAuthn Hardware Security Key Authentication Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start development server on localhost
  python agent.py --rp-id localhost --rp-name "My App" --port 5000

  # Production mode with strict user verification
  python agent.py --rp-id auth.example.com --rp-name "Example Corp" \\
      --user-verification required --attestation direct --db prod_keys.db

  # Require discoverable credentials (passkeys)
  python agent.py --rp-id example.com --rp-name "Example" --port 8443
        """,
    )
    parser.add_argument("--rp-id", default="localhost", help="Relying Party ID (domain, default: localhost)")
    parser.add_argument("--rp-name", default="FIDO2 Demo", help="Relying Party display name")
    parser.add_argument("--host", default="localhost", help="Server bind address (default: localhost)")
    parser.add_argument("--port", type=int, default=5000, help="Server port (default: 5000)")
    parser.add_argument("--db", default="webauthn.db", help="SQLite database path (default: webauthn.db)")
    parser.add_argument(
        "--attestation", choices=["none", "indirect", "direct", "enterprise"],
        default="none", help="Attestation conveyance preference (default: none)",
    )
    parser.add_argument(
        "--user-verification", choices=["required", "preferred", "discouraged"],
        default="preferred", help="User verification requirement (default: preferred)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    logger.info("Starting FIDO2 WebAuthn server")
    logger.info("  RP ID:    %s", args.rp_id)
    logger.info("  RP Name:  %s", args.rp_name)
    logger.info("  Host:     %s:%d", args.host, args.port)
    logger.info("  Database: %s", args.db)
    logger.info("  Attestation: %s", args.attestation)
    logger.info("  User Verification: %s", args.user_verification)

    app = create_app(
        rp_id=args.rp_id,
        rp_name=args.rp_name,
        db_path=args.db,
        attestation=args.attestation,
        user_verification=args.user_verification,
    )

    if args.rp_id != "localhost":
        logger.warning(
            "Running without TLS. In production, place behind a TLS-terminating "
            "reverse proxy (nginx, Caddy) -- WebAuthn requires HTTPS."
        )

    app.run(host=args.host, port=args.port, debug=args.verbose)


if __name__ == "__main__":
    main()
