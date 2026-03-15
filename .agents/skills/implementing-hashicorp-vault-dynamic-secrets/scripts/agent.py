#!/usr/bin/env python3
"""HashiCorp Vault dynamic secrets management agent using hvac client."""

import json
import sys
import argparse
from datetime import datetime

try:
    import hvac
    from hvac.exceptions import VaultError
except ImportError:
    print("Install hvac: pip install hvac")
    sys.exit(1)


def connect_vault(url, token=None, role_id=None, secret_id=None):
    """Connect to Vault using token or AppRole authentication."""
    client = hvac.Client(url=url)
    if token:
        client.token = token
    elif role_id and secret_id:
        resp = client.auth.approle.login(role_id=role_id, secret_id=secret_id)
        client.token = resp["auth"]["client_token"]
    if not client.is_authenticated():
        print("[!] Vault authentication failed")
        sys.exit(1)
    return client


def enable_database_secrets_engine(client, path="database"):
    """Enable the database secrets engine."""
    try:
        client.sys.enable_secrets_engine(backend_type="database", path=path)
        return {"engine": "database", "path": path, "status": "enabled"}
    except VaultError as e:
        if "already in use" in str(e):
            return {"engine": "database", "path": path, "status": "already_enabled"}
        return {"error": str(e)}


def configure_postgres_connection(client, name, connection_url, username, password,
                                  path="database"):
    """Configure a PostgreSQL database connection in Vault."""
    try:
        client.secrets.database.configure(
            name=name, plugin_name="postgresql-database-plugin",
            connection_url=connection_url,
            allowed_roles=["*"],
            username=username, password=password,
            mount_point=path)
        return {"connection": name, "status": "configured"}
    except VaultError as e:
        return {"error": str(e)}


def create_database_role(client, role_name, db_name, creation_statements,
                         default_ttl="1h", max_ttl="24h", path="database"):
    """Create a dynamic database role for credential generation."""
    try:
        client.secrets.database.create_role(
            name=role_name, db_name=db_name,
            creation_statements=creation_statements,
            default_ttl=default_ttl, max_ttl=max_ttl,
            mount_point=path)
        return {"role": role_name, "ttl": default_ttl, "status": "created"}
    except VaultError as e:
        return {"error": str(e)}


def generate_database_credentials(client, role_name, path="database"):
    """Generate dynamic database credentials for a role."""
    try:
        resp = client.secrets.database.generate_credentials(
            name=role_name, mount_point=path)
        return {
            "username": resp["data"]["username"],
            "password": resp["data"]["password"],
            "lease_id": resp["lease_id"],
            "lease_duration": resp["lease_duration"],
            "renewable": resp["renewable"],
        }
    except VaultError as e:
        return {"error": str(e)}


def enable_aws_secrets_engine(client, path="aws"):
    """Enable the AWS secrets engine for dynamic IAM credentials."""
    try:
        client.sys.enable_secrets_engine(backend_type="aws", path=path)
        return {"engine": "aws", "path": path, "status": "enabled"}
    except VaultError as e:
        if "already in use" in str(e):
            return {"engine": "aws", "path": path, "status": "already_enabled"}
        return {"error": str(e)}


def configure_aws_root(client, access_key, secret_key, region="us-east-1", path="aws"):
    """Configure AWS root credentials for dynamic IAM generation."""
    try:
        client.secrets.aws.configure_root_iam_credentials(
            access_key=access_key, secret_key=secret_key, region=region,
            mount_point=path)
        return {"status": "configured", "region": region}
    except VaultError as e:
        return {"error": str(e)}


def create_aws_role(client, role_name, policy_arns, credential_type="iam_user",
                    default_ttl="1h", path="aws"):
    """Create an AWS dynamic role for generating IAM credentials."""
    try:
        client.secrets.aws.create_or_update_role(
            name=role_name, credential_type=credential_type,
            policy_arns=policy_arns, default_sts_ttl=default_ttl,
            mount_point=path)
        return {"role": role_name, "type": credential_type, "status": "created"}
    except VaultError as e:
        return {"error": str(e)}


def generate_aws_credentials(client, role_name, path="aws"):
    """Generate dynamic AWS credentials for a role."""
    try:
        resp = client.secrets.aws.generate_credentials(
            name=role_name, mount_point=path)
        return {
            "access_key": resp["data"]["access_key"],
            "secret_key": resp["data"]["secret_key"],
            "security_token": resp["data"].get("security_token"),
            "lease_id": resp["lease_id"],
            "lease_duration": resp["lease_duration"],
        }
    except VaultError as e:
        return {"error": str(e)}


def enable_pki_engine(client, path="pki"):
    """Enable PKI secrets engine for dynamic certificate generation."""
    try:
        client.sys.enable_secrets_engine(backend_type="pki", path=path)
        client.sys.tune_mount_configuration(path=path, max_lease_ttl="87600h")
        return {"engine": "pki", "path": path, "status": "enabled"}
    except VaultError as e:
        if "already in use" in str(e):
            return {"engine": "pki", "path": path, "status": "already_enabled"}
        return {"error": str(e)}


def list_leases(client, prefix="database/creds/"):
    """List active leases for dynamic secrets."""
    try:
        resp = client.sys.list_leases(prefix=prefix)
        return resp.get("data", {}).get("keys", [])
    except VaultError as e:
        return [str(e)]


def revoke_lease(client, lease_id):
    """Revoke a specific lease to immediately invalidate credentials."""
    try:
        client.sys.revoke_lease(lease_id=lease_id)
        return {"lease_id": lease_id, "status": "revoked"}
    except VaultError as e:
        return {"error": str(e)}


def run_vault_audit(client):
    """Run Vault dynamic secrets audit."""
    print(f"\n{'='*60}")
    print(f"  HASHICORP VAULT DYNAMIC SECRETS AUDIT")
    print(f"  Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"{'='*60}\n")

    health = client.sys.read_health_status(method="GET")
    print(f"--- VAULT STATUS ---")
    print(f"  Initialized: {health.get('initialized')}")
    print(f"  Sealed: {health.get('sealed')}")
    print(f"  Version: {health.get('version')}")

    mounts = client.sys.list_mounted_secrets_engines()
    print(f"\n--- SECRETS ENGINES ---")
    for path, config in mounts.get("data", mounts).items():
        if isinstance(config, dict):
            print(f"  {path}: {config.get('type', 'unknown')}")

    auth_methods = client.sys.list_auth_methods()
    print(f"\n--- AUTH METHODS ---")
    for path, config in auth_methods.get("data", auth_methods).items():
        if isinstance(config, dict):
            print(f"  {path}: {config.get('type', 'unknown')}")

    print(f"\n{'='*60}\n")
    return {"sealed": health.get("sealed"), "version": health.get("version")}


def main():
    parser = argparse.ArgumentParser(description="HashiCorp Vault Dynamic Secrets Agent")
    parser.add_argument("--vault-url", default="http://127.0.0.1:8200", help="Vault URL")
    parser.add_argument("--token", help="Vault token")
    parser.add_argument("--role-id", help="AppRole role ID")
    parser.add_argument("--secret-id", help="AppRole secret ID")
    parser.add_argument("--audit", action="store_true", help="Run Vault audit")
    parser.add_argument("--gen-db-creds", help="Generate DB credentials for role")
    parser.add_argument("--gen-aws-creds", help="Generate AWS credentials for role")
    parser.add_argument("--revoke", help="Revoke lease by ID")
    parser.add_argument("--output", help="Save report to JSON")
    args = parser.parse_args()

    client = connect_vault(args.vault_url, args.token, args.role_id, args.secret_id)

    if args.audit:
        report = run_vault_audit(client)
        if args.output:
            with open(args.output, "w") as f:
                json.dump(report, f, indent=2, default=str)
    elif args.gen_db_creds:
        creds = generate_database_credentials(client, args.gen_db_creds)
        print(json.dumps(creds, indent=2))
    elif args.gen_aws_creds:
        creds = generate_aws_credentials(client, args.gen_aws_creds)
        print(json.dumps(creds, indent=2))
    elif args.revoke:
        result = revoke_lease(client, args.revoke)
        print(json.dumps(result, indent=2))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
