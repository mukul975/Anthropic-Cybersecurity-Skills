#!/usr/bin/env python3
"""HashiCorp Vault secrets management agent.

Manages secrets lifecycle using the HashiCorp Vault KV v2 secrets engine
via the hvac Python library. Supports reading, writing, listing, deleting
secrets, and auditing secret access patterns.
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone

try:
    import hvac
except ImportError:
    print("[!] 'hvac' library required: pip install hvac", file=sys.stderr)
    sys.exit(1)


def get_vault_client(addr=None, token=None, namespace=None):
    """Create and authenticate a Vault client."""
    vault_addr = addr or os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
    vault_token = token or os.environ.get("VAULT_TOKEN", "")
    vault_ns = namespace or os.environ.get("VAULT_NAMESPACE")

    if not vault_token:
        print("[!] Set VAULT_TOKEN env var or use --token", file=sys.stderr)
        sys.exit(1)

    client = hvac.Client(url=vault_addr, token=vault_token, namespace=vault_ns)
    if not client.is_authenticated():
        print("[!] Vault authentication failed", file=sys.stderr)
        sys.exit(1)
    print(f"[+] Connected to Vault at {vault_addr}")
    return client


def write_secret(client, path, data, mount_point="secret"):
    """Write or update a secret in KV v2."""
    print(f"[*] Writing secret to {mount_point}/{path}")
    response = client.secrets.kv.v2.create_or_update_secret(
        path=path, secret=data, mount_point=mount_point,
    )
    version = response.get("data", {}).get("version", "unknown")
    print(f"[+] Secret written (version: {version})")
    return {"path": path, "version": version, "action": "write"}


def read_secret(client, path, mount_point="secret", version=None):
    """Read a secret from KV v2."""
    print(f"[*] Reading secret from {mount_point}/{path}")
    kwargs = {"path": path, "mount_point": mount_point}
    if version:
        kwargs["version"] = version
    response = client.secrets.kv.v2.read_secret_version(**kwargs)
    secret_data = response.get("data", {}).get("data", {})
    metadata = response.get("data", {}).get("metadata", {})
    print(f"[+] Secret read (version: {metadata.get('version', '?')}, "
          f"created: {metadata.get('created_time', 'unknown')})")
    masked = {k: v[:3] + "***" if isinstance(v, str) and len(v) > 3 else "***"
              for k, v in secret_data.items()}
    return {
        "path": path,
        "keys": list(secret_data.keys()),
        "masked_values": masked,
        "version": metadata.get("version"),
        "created_time": metadata.get("created_time"),
        "deletion_time": metadata.get("deletion_time"),
        "destroyed": metadata.get("destroyed"),
    }


def list_secrets(client, path="", mount_point="secret"):
    """List secret paths under a given prefix."""
    print(f"[*] Listing secrets under {mount_point}/{path}")
    try:
        response = client.secrets.kv.v2.list_secrets(
            path=path, mount_point=mount_point
        )
        keys = response.get("data", {}).get("keys", [])
        print(f"[+] Found {len(keys)} entries")
        for key in keys:
            marker = "/" if key.endswith("/") else " "
            print(f"    {marker} {key}")
        return {"path": path, "entries": keys, "count": len(keys)}
    except hvac.exceptions.InvalidPath:
        print(f"[*] No secrets found at {mount_point}/{path}")
        return {"path": path, "entries": [], "count": 0}


def delete_secret(client, path, mount_point="secret", versions=None, destroy=False):
    """Delete or destroy a secret."""
    if destroy and versions:
        print(f"[*] Permanently destroying versions {versions} at {mount_point}/{path}")
        client.secrets.kv.v2.destroy_secret_versions(
            path=path, versions=versions, mount_point=mount_point
        )
        print(f"[+] Versions {versions} permanently destroyed")
        return {"path": path, "action": "destroy", "versions": versions}
    elif versions:
        print(f"[*] Soft-deleting versions {versions} at {mount_point}/{path}")
        client.secrets.kv.v2.delete_secret_versions(
            path=path, versions=versions, mount_point=mount_point
        )
        print(f"[+] Versions {versions} soft-deleted (recoverable)")
        return {"path": path, "action": "soft_delete", "versions": versions}
    else:
        print(f"[*] Deleting latest version at {mount_point}/{path}")
        client.secrets.kv.v2.delete_latest_version_of_secret(
            path=path, mount_point=mount_point
        )
        print("[+] Latest version deleted")
        return {"path": path, "action": "delete_latest"}


def read_metadata(client, path, mount_point="secret"):
    """Read secret metadata including version history."""
    print(f"[*] Reading metadata for {mount_point}/{path}")
    response = client.secrets.kv.v2.read_secret_metadata(
        path=path, mount_point=mount_point
    )
    meta = response.get("data", {})
    versions = meta.get("versions", {})
    print(f"[+] {len(versions)} version(s), max_versions: {meta.get('max_versions', 0)}")
    version_info = []
    for ver_num, ver_data in sorted(versions.items(), key=lambda x: int(x[0])):
        version_info.append({
            "version": int(ver_num),
            "created_time": ver_data.get("created_time"),
            "deletion_time": ver_data.get("deletion_time"),
            "destroyed": ver_data.get("destroyed", False),
        })
    return {
        "path": path,
        "current_version": meta.get("current_version"),
        "max_versions": meta.get("max_versions"),
        "cas_required": meta.get("cas_required"),
        "created_time": meta.get("created_time"),
        "updated_time": meta.get("updated_time"),
        "versions": version_info,
    }


def audit_secrets(client, mount_point="secret", path_prefix=""):
    """Audit all secrets under a path, reporting metadata and age."""
    print(f"[*] Auditing secrets under {mount_point}/{path_prefix}")
    audit_results = []

    def _recurse(current_path):
        try:
            resp = client.secrets.kv.v2.list_secrets(
                path=current_path, mount_point=mount_point
            )
        except hvac.exceptions.InvalidPath:
            return
        keys = resp.get("data", {}).get("keys", [])
        for key in keys:
            full_path = f"{current_path}{key}" if current_path else key
            if key.endswith("/"):
                _recurse(full_path)
            else:
                try:
                    meta_resp = client.secrets.kv.v2.read_secret_metadata(
                        path=full_path, mount_point=mount_point
                    )
                    meta = meta_resp.get("data", {})
                    audit_results.append({
                        "path": full_path,
                        "current_version": meta.get("current_version"),
                        "created_time": meta.get("created_time"),
                        "updated_time": meta.get("updated_time"),
                        "version_count": len(meta.get("versions", {})),
                    })
                except Exception as e:
                    audit_results.append({"path": full_path, "error": str(e)})

    _recurse(path_prefix)
    print(f"[+] Audited {len(audit_results)} secret(s)")
    for item in audit_results:
        if "error" in item:
            print(f"    [ERR] {item['path']}: {item['error']}")
        else:
            print(f"    {item['path']:40s} v{item['current_version']} "
                  f"(updated: {str(item.get('updated_time', 'N/A'))[:19]})")
    return audit_results


def main():
    parser = argparse.ArgumentParser(
        description="HashiCorp Vault secrets management agent"
    )
    sub = parser.add_subparsers(dest="command", help="Action to perform")

    p_write = sub.add_parser("write", help="Write a secret")
    p_write.add_argument("--path", required=True, help="Secret path")
    p_write.add_argument("--data", required=True, help='JSON data')
    p_write.add_argument("--mount", default="secret", help="KV mount point")

    p_read = sub.add_parser("read", help="Read a secret")
    p_read.add_argument("--path", required=True)
    p_read.add_argument("--version", type=int, help="Specific version")
    p_read.add_argument("--mount", default="secret")

    p_list = sub.add_parser("list", help="List secrets")
    p_list.add_argument("--path", default="")
    p_list.add_argument("--mount", default="secret")

    p_del = sub.add_parser("delete", help="Delete a secret")
    p_del.add_argument("--path", required=True)
    p_del.add_argument("--versions", type=int, nargs="+")
    p_del.add_argument("--destroy", action="store_true")
    p_del.add_argument("--mount", default="secret")

    p_meta = sub.add_parser("metadata", help="Read secret metadata")
    p_meta.add_argument("--path", required=True)
    p_meta.add_argument("--mount", default="secret")

    p_audit = sub.add_parser("audit", help="Audit all secrets")
    p_audit.add_argument("--path", default="")
    p_audit.add_argument("--mount", default="secret")

    parser.add_argument("--addr", help="Vault address (or VAULT_ADDR env)")
    parser.add_argument("--token", help="Vault token (or VAULT_TOKEN env)")
    parser.add_argument("--namespace", help="Vault namespace")
    parser.add_argument("--output", "-o", help="Output JSON report")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    client = get_vault_client(args.addr, args.token, args.namespace)

    if args.command == "write":
        secret_data = json.loads(args.data)
        result = write_secret(client, args.path, secret_data, args.mount)
    elif args.command == "read":
        result = read_secret(client, args.path, args.mount,
                             getattr(args, "version", None))
    elif args.command == "list":
        result = list_secrets(client, args.path, args.mount)
    elif args.command == "delete":
        result = delete_secret(client, args.path, args.mount,
                               getattr(args, "versions", None),
                               getattr(args, "destroy", False))
    elif args.command == "metadata":
        result = read_metadata(client, args.path, args.mount)
    elif args.command == "audit":
        result = audit_secrets(client, args.mount, args.path)
    else:
        parser.print_help()
        sys.exit(1)

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": "HashiCorp Vault",
        "command": args.command,
        "result": result,
    }

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n[+] Report saved to {args.output}")
    elif args.verbose:
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
