#!/usr/bin/env python3
"""
Authenticated Vulnerability Scan Credential Validator and Manager

Pre-validates scanner credentials against target hosts before launching
vulnerability scans to ensure maximum authenticated coverage.

Requirements:
    pip install paramiko pywinrm pysnmp pandas

Usage:
    python process.py validate --targets targets.txt --creds creds.json
    python process.py report --nessus-file scan_results.nessus
"""

import argparse
import json
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

import pandas as pd

try:
    import paramiko
except ImportError:
    paramiko = None

try:
    import winrm
except ImportError:
    winrm = None


class CredentialValidator:
    """Validate scanner credentials against target hosts."""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.results = []

    def check_port(self, host: str, port: int) -> bool:
        """Check if a TCP port is open on the target host."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except (socket.error, OSError):
            return False

    def validate_ssh(self, host: str, username: str, password: str = None,
                     key_file: str = None, port: int = 22) -> dict:
        """Validate SSH credentials against a target host."""
        result = {
            "host": host, "protocol": "SSH", "port": port,
            "username": username, "status": "UNKNOWN", "details": ""
        }

        if not paramiko:
            result["status"] = "SKIP"
            result["details"] = "paramiko not installed"
            return result

        if not self.check_port(host, port):
            result["status"] = "FAIL"
            result["details"] = f"Port {port} not reachable"
            return result

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            connect_kwargs = {
                "hostname": host, "port": port, "username": username,
                "timeout": self.timeout, "allow_agent": False, "look_for_keys": False
            }

            if key_file:
                connect_kwargs["key_filename"] = key_file
            elif password:
                connect_kwargs["password"] = password
            else:
                result["status"] = "FAIL"
                result["details"] = "No password or key file provided"
                return result

            client.connect(**connect_kwargs)

            # Test command execution
            _, stdout, stderr = client.exec_command("id && uname -a", timeout=10)
            output = stdout.read().decode().strip()
            error = stderr.read().decode().strip()

            # Test sudo access
            _, stdout_sudo, stderr_sudo = client.exec_command(
                "sudo -n id 2>&1", timeout=10
            )
            sudo_output = stdout_sudo.read().decode().strip()

            has_sudo = "uid=0" in sudo_output
            client.close()

            result["status"] = "SUCCESS"
            result["details"] = f"Auth OK. Sudo: {'Yes' if has_sudo else 'No'}. {output[:100]}"
            result["has_sudo"] = has_sudo

        except paramiko.AuthenticationException:
            result["status"] = "FAIL"
            result["details"] = "Authentication failed - invalid credentials"
        except paramiko.SSHException as e:
            result["status"] = "FAIL"
            result["details"] = f"SSH error: {str(e)[:100]}"
        except Exception as e:
            result["status"] = "FAIL"
            result["details"] = f"Connection error: {str(e)[:100]}"

        return result

    def validate_winrm(self, host: str, username: str, password: str,
                       port: int = 5985, use_ssl: bool = False) -> dict:
        """Validate WinRM credentials against a Windows target."""
        result = {
            "host": host, "protocol": "WinRM", "port": port,
            "username": username, "status": "UNKNOWN", "details": ""
        }

        if not winrm:
            result["status"] = "SKIP"
            result["details"] = "pywinrm not installed"
            return result

        check_port = 5986 if use_ssl else port
        if not self.check_port(host, check_port):
            result["status"] = "FAIL"
            result["details"] = f"Port {check_port} not reachable"
            return result

        try:
            scheme = "https" if use_ssl else "http"
            session = winrm.Session(
                f"{scheme}://{host}:{check_port}/wsman",
                auth=(username, password),
                transport="ntlm",
                server_cert_validation="ignore" if use_ssl else "validate"
            )
            r = session.run_cmd("whoami")
            output = r.std_out.decode().strip()

            # Check admin privileges
            r_admin = session.run_cmd("net", ["localgroup", "Administrators"])
            admin_output = r_admin.std_out.decode()

            is_admin = username.split("\\")[-1].lower() in admin_output.lower()

            result["status"] = "SUCCESS"
            result["details"] = f"Auth OK as {output}. Admin: {'Yes' if is_admin else 'No'}"
            result["is_admin"] = is_admin

        except Exception as e:
            result["status"] = "FAIL"
            result["details"] = f"WinRM error: {str(e)[:150]}"

        return result

    def validate_smb(self, host: str, username: str, password: str,
                     domain: str = "", port: int = 445) -> dict:
        """Validate SMB credentials against a Windows target."""
        result = {
            "host": host, "protocol": "SMB", "port": port,
            "username": username, "status": "UNKNOWN", "details": ""
        }

        if not self.check_port(host, port):
            result["status"] = "FAIL"
            result["details"] = f"Port {port} not reachable"
            return result

        try:
            from impacket.smbconnection import SMBConnection
            conn = SMBConnection(host, host, sess_port=port)
            conn.login(username, password, domain)
            shares = conn.listShares()
            share_names = [s["shi1_netname"].rstrip("\x00") for s in shares]
            conn.logoff()

            result["status"] = "SUCCESS"
            result["details"] = f"Auth OK. Shares: {', '.join(share_names[:5])}"

        except ImportError:
            result["status"] = "SKIP"
            result["details"] = "impacket not installed"
        except Exception as e:
            result["status"] = "FAIL"
            result["details"] = f"SMB error: {str(e)[:150]}"

        return result

    def validate_snmpv3(self, host: str, username: str, auth_password: str,
                        priv_password: str, port: int = 161) -> dict:
        """Validate SNMPv3 credentials against a target."""
        result = {
            "host": host, "protocol": "SNMPv3", "port": port,
            "username": username, "status": "UNKNOWN", "details": ""
        }

        try:
            from pysnmp.hlapi import (
                SnmpEngine, UsmUserData, UdpTransportTarget,
                ContextData, ObjectType, ObjectIdentity, getCmd,
                usmHMACSHAAuthProtocol, usmAesCfb128Protocol
            )

            iterator = getCmd(
                SnmpEngine(),
                UsmUserData(username, auth_password, priv_password,
                            authProtocol=usmHMACSHAAuthProtocol,
                            privProtocol=usmAesCfb128Protocol),
                UdpTransportTarget((host, port), timeout=self.timeout),
                ContextData(),
                ObjectType(ObjectIdentity("SNMPv2-MIB", "sysDescr", 0))
            )

            errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

            if errorIndication:
                result["status"] = "FAIL"
                result["details"] = f"SNMP error: {errorIndication}"
            elif errorStatus:
                result["status"] = "FAIL"
                result["details"] = f"SNMP status: {errorStatus.prettyPrint()}"
            else:
                for varBind in varBinds:
                    result["status"] = "SUCCESS"
                    result["details"] = f"Auth OK. sysDescr: {str(varBind[1])[:100]}"

        except ImportError:
            result["status"] = "SKIP"
            result["details"] = "pysnmp not installed"
        except Exception as e:
            result["status"] = "FAIL"
            result["details"] = f"SNMP error: {str(e)[:150]}"

        return result

    def validate_all(self, targets: list, credentials: dict, max_workers: int = 20) -> list:
        """Validate credentials against all targets in parallel."""
        self.results = []
        tasks = []

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            for target in targets:
                host = target.strip()
                if not host:
                    continue

                # SSH validation
                if "ssh" in credentials:
                    cred = credentials["ssh"]
                    tasks.append(executor.submit(
                        self.validate_ssh, host, cred["username"],
                        cred.get("password"), cred.get("key_file"),
                        cred.get("port", 22)
                    ))

                # WinRM validation
                if "winrm" in credentials:
                    cred = credentials["winrm"]
                    tasks.append(executor.submit(
                        self.validate_winrm, host, cred["username"],
                        cred["password"], cred.get("port", 5985),
                        cred.get("use_ssl", False)
                    ))

                # SMB validation
                if "smb" in credentials:
                    cred = credentials["smb"]
                    tasks.append(executor.submit(
                        self.validate_smb, host, cred["username"],
                        cred["password"], cred.get("domain", ""),
                        cred.get("port", 445)
                    ))

                # SNMPv3 validation
                if "snmpv3" in credentials:
                    cred = credentials["snmpv3"]
                    tasks.append(executor.submit(
                        self.validate_snmpv3, host, cred["username"],
                        cred["auth_password"], cred["priv_password"],
                        cred.get("port", 161)
                    ))

            for future in as_completed(tasks):
                try:
                    result = future.result()
                    self.results.append(result)
                    status_icon = "[+]" if result["status"] == "SUCCESS" else "[-]"
                    print(f"  {status_icon} {result['host']}:{result['port']} "
                          f"({result['protocol']}) - {result['status']}: {result['details'][:80]}")
                except Exception as e:
                    print(f"  [!] Validation error: {e}")

        return self.results

    def generate_report(self, output_path: str = None) -> pd.DataFrame:
        """Generate validation report."""
        df = pd.DataFrame(self.results)

        if df.empty:
            print("[-] No validation results to report")
            return df

        print("\n" + "=" * 70)
        print("CREDENTIAL VALIDATION SUMMARY")
        print("=" * 70)

        total = len(df)
        success = len(df[df["status"] == "SUCCESS"])
        fail = len(df[df["status"] == "FAIL"])
        skip = len(df[df["status"] == "SKIP"])

        print(f"Total Checks:  {total}")
        print(f"  SUCCESS:     {success} ({success/total*100:.1f}%)")
        print(f"  FAIL:        {fail} ({fail/total*100:.1f}%)")
        print(f"  SKIPPED:     {skip} ({skip/total*100:.1f}%)")

        if success / max(total, 1) < 0.90:
            print("\n[WARNING] Credential success rate below 90% - investigate failures before scanning")

        # Protocol breakdown
        print("\nBy Protocol:")
        for proto in df["protocol"].unique():
            proto_df = df[df["protocol"] == proto]
            proto_success = len(proto_df[proto_df["status"] == "SUCCESS"])
            print(f"  {proto}: {proto_success}/{len(proto_df)} "
                  f"({proto_success/len(proto_df)*100:.1f}%)")

        # Failed hosts
        failures = df[df["status"] == "FAIL"]
        if not failures.empty:
            print(f"\nFailed Hosts ({len(failures)}):")
            for _, row in failures.iterrows():
                print(f"  {row['host']}:{row['port']} ({row['protocol']}): {row['details'][:80]}")

        if output_path:
            df.to_csv(output_path, index=False)
            print(f"\n[+] Report saved to: {output_path}")

        return df


def main():
    parser = argparse.ArgumentParser(description="Authenticated Scan Credential Validator")
    subparsers = parser.add_subparsers(dest="command")

    # Validate command
    val_parser = subparsers.add_parser("validate", help="Validate credentials against targets")
    val_parser.add_argument("--targets", required=True, help="File with target IPs (one per line)")
    val_parser.add_argument("--creds", required=True, help="JSON file with credentials")
    val_parser.add_argument("--output", default=None, help="Output CSV report path")
    val_parser.add_argument("--workers", type=int, default=20, help="Max parallel workers")
    val_parser.add_argument("--timeout", type=int, default=10, help="Connection timeout seconds")

    args = parser.parse_args()

    if args.command == "validate":
        with open(args.targets) as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        with open(args.creds) as f:
            credentials = json.load(f)

        print(f"[*] Validating credentials against {len(targets)} targets")
        print(f"[*] Protocols: {', '.join(credentials.keys())}")

        validator = CredentialValidator(timeout=args.timeout)
        validator.validate_all(targets, credentials, max_workers=args.workers)

        output = args.output or f"cred_validation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        validator.generate_report(output)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
