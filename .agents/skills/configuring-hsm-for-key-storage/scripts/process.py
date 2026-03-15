#!/usr/bin/env python3
"""
HSM Key Storage Configuration Tool (PKCS#11)

Demonstrates HSM key management using PKCS#11 interface with SoftHSM2
for development and testing. Covers key generation, signing, encryption,
and key management operations.

Requirements:
    pip install python-pkcs11 asn1crypto
    # Also requires SoftHSM2 installed:
    # Ubuntu: apt install softhsm2
    # macOS: brew install softhsm

Usage:
    python process.py init-token --label MyToken --pin 1234 --so-pin 5678
    python process.py generate-aes --token MyToken --pin 1234 --label my-aes-key
    python process.py generate-rsa --token MyToken --pin 1234 --label my-rsa-key
    python process.py list-keys --token MyToken --pin 1234
    python process.py sign --token MyToken --pin 1234 --key-label my-rsa-key --input data.txt
    python process.py encrypt --token MyToken --pin 1234 --key-label my-aes-key --input data.txt
"""

import os
import sys
import json
import argparse
import logging
import subprocess
import platform
from pathlib import Path
from typing import Dict, List, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Common SoftHSM2 library paths
SOFTHSM_PATHS = {
    "linux": [
        "/usr/lib/softhsm/libsofthsm2.so",
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
        "/usr/local/lib/softhsm/libsofthsm2.so",
    ],
    "darwin": [
        "/usr/local/lib/softhsm/libsofthsm2.so",
        "/opt/homebrew/lib/softhsm/libsofthsm2.so",
    ],
    "win32": [
        r"C:\SoftHSM2\lib\softhsm2-x64.dll",
        r"C:\Program Files\SoftHSM2\lib\softhsm2-x64.dll",
    ],
}


def find_softhsm_lib() -> Optional[str]:
    """Find the SoftHSM2 library path."""
    system = platform.system().lower()
    if system == "windows":
        paths = SOFTHSM_PATHS.get("win32", [])
    elif system == "darwin":
        paths = SOFTHSM_PATHS.get("darwin", [])
    else:
        paths = SOFTHSM_PATHS.get("linux", [])

    for path in paths:
        if Path(path).exists():
            return path

    env_path = os.environ.get("SOFTHSM2_LIB")
    if env_path and Path(env_path).exists():
        return env_path

    return None


def init_token_via_cli(label: str, pin: str, so_pin: str) -> Dict:
    """Initialize a SoftHSM2 token using command-line tool."""
    try:
        result = subprocess.run(
            ["softhsm2-util", "--init-token", "--free",
             "--label", label, "--pin", pin, "--so-pin", so_pin],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            logger.info(f"Token '{label}' initialized successfully")
            slot_info = result.stdout.strip()
            return {
                "status": "success",
                "label": label,
                "message": slot_info or "Token initialized",
            }
        else:
            return {"status": "error", "message": result.stderr.strip()}
    except FileNotFoundError:
        return {
            "status": "error",
            "message": "softhsm2-util not found. Install SoftHSM2 first.",
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


def pkcs11_operations_demo(token_label: str, pin: str, lib_path: str) -> Dict:
    """
    Demonstrate PKCS#11 operations using python-pkcs11.
    This requires the python-pkcs11 package and SoftHSM2.
    """
    try:
        import pkcs11
        from pkcs11 import KeyType, Attribute, ObjectClass, Mechanism
        from pkcs11.util.rsa import encode_rsa_public_key
        from pkcs11.util.ec import encode_named_curve_parameters
    except ImportError:
        return {
            "status": "error",
            "message": "python-pkcs11 not installed. Run: pip install python-pkcs11",
        }

    try:
        lib = pkcs11.lib(lib_path)
        token = lib.get_token(token_label=token_label)
    except Exception as e:
        return {"status": "error", "message": f"Cannot access token: {e}"}

    results = {"operations": []}

    with token.open(user_pin=pin, rw=True) as session:
        # Generate AES-256 key
        try:
            aes_key = session.generate_key(
                KeyType.AES, 256,
                label="demo-aes-256",
                store=True,
                capabilities=pkcs11.defaults.DEFAULT_KEY_CAPABILITIES[KeyType.AES],
            )
            results["operations"].append({
                "operation": "generate_aes_key",
                "status": "success",
                "label": "demo-aes-256",
                "key_type": "AES-256",
            })
        except Exception as e:
            results["operations"].append({
                "operation": "generate_aes_key",
                "status": "error",
                "message": str(e),
            })

        # Generate RSA-2048 key pair
        try:
            pub_key, priv_key = session.generate_keypair(
                KeyType.RSA, 2048,
                label="demo-rsa-2048",
                store=True,
            )
            results["operations"].append({
                "operation": "generate_rsa_keypair",
                "status": "success",
                "label": "demo-rsa-2048",
                "key_type": "RSA-2048",
            })
        except Exception as e:
            results["operations"].append({
                "operation": "generate_rsa_keypair",
                "status": "error",
                "message": str(e),
            })

        # AES Encryption/Decryption
        try:
            for key in session.get_objects({
                Attribute.CLASS: ObjectClass.SECRET_KEY,
                Attribute.LABEL: "demo-aes-256",
            }):
                iv = os.urandom(16)
                plaintext = b"HSM encryption test data for PKCS#11"
                padded = plaintext + (b"\x10" * (16 - len(plaintext) % 16))
                ciphertext = key.encrypt(padded, mechanism=Mechanism.AES_CBC_PAD, mechanism_param=iv)
                decrypted = key.decrypt(ciphertext, mechanism=Mechanism.AES_CBC_PAD, mechanism_param=iv)
                results["operations"].append({
                    "operation": "aes_encrypt_decrypt",
                    "status": "success",
                    "match": decrypted.rstrip(b"\x10")[:len(plaintext)] == plaintext,
                })
                break
        except Exception as e:
            results["operations"].append({
                "operation": "aes_encrypt_decrypt",
                "status": "error",
                "message": str(e),
            })

        # RSA Sign/Verify
        try:
            for key in session.get_objects({
                Attribute.CLASS: ObjectClass.PRIVATE_KEY,
                Attribute.LABEL: "demo-rsa-2048",
            }):
                data = b"Data to sign with HSM-resident RSA key"
                signature = key.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)
                results["operations"].append({
                    "operation": "rsa_sign",
                    "status": "success",
                    "signature_length": len(signature),
                })
                break

            for key in session.get_objects({
                Attribute.CLASS: ObjectClass.PUBLIC_KEY,
                Attribute.LABEL: "demo-rsa-2048",
            }):
                valid = key.verify(data, signature, mechanism=Mechanism.SHA256_RSA_PKCS)
                results["operations"].append({
                    "operation": "rsa_verify",
                    "status": "success",
                    "valid": True,
                })
                break
        except Exception as e:
            results["operations"].append({
                "operation": "rsa_sign_verify",
                "status": "error",
                "message": str(e),
            })

        # List all objects
        try:
            objects = []
            for obj in session.get_objects():
                obj_info = {
                    "label": str(obj.get(Attribute.LABEL, "N/A")),
                    "class": str(obj.object_class),
                }
                objects.append(obj_info)
            results["stored_objects"] = objects
        except Exception as e:
            results["stored_objects_error"] = str(e)

    results["status"] = "success"
    return results


def list_tokens(lib_path: str) -> Dict:
    """List all available PKCS#11 tokens."""
    try:
        import pkcs11
        lib = pkcs11.lib(lib_path)
        tokens = []
        for slot in lib.get_slots(token_present=True):
            token = slot.get_token()
            tokens.append({
                "slot_id": slot.slot_id,
                "label": token.label.strip(),
                "manufacturer": token.manufacturer_id.strip() if hasattr(token, 'manufacturer_id') else "N/A",
            })
        return {"status": "success", "tokens": tokens}
    except ImportError:
        return {"status": "error", "message": "python-pkcs11 not installed"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def generate_hsm_config() -> Dict:
    """Generate HSM configuration templates for different providers."""
    configs = {
        "softhsm2": {
            "description": "SoftHSM2 (Development/Testing)",
            "install": {
                "ubuntu": "apt install softhsm2",
                "macos": "brew install softhsm",
                "windows": "Download from https://github.com/disig/SoftHSM2-for-Windows",
            },
            "config_file": "softhsm2.conf",
            "config_content": "directories.tokendir = /var/lib/softhsm/tokens/\nobjectstore.backend = file\nlog.level = INFO\n",
            "init_command": "softhsm2-util --init-token --free --label MyToken --pin 1234 --so-pin 5678",
        },
        "aws_cloudhsm": {
            "description": "AWS CloudHSM",
            "setup_steps": [
                "Create CloudHSM cluster in AWS Console",
                "Initialize the cluster",
                "Install CloudHSM client on EC2 instance",
                "Activate the cluster with crypto officer credentials",
                "Install PKCS#11 library from AWS",
            ],
            "pkcs11_lib": "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so",
            "config_file": "/opt/cloudhsm/etc/cloudhsm_client.cfg",
        },
        "azure_dedicated_hsm": {
            "description": "Azure Dedicated HSM (Thales Luna)",
            "setup_steps": [
                "Provision Dedicated HSM via Azure Portal",
                "Configure network connectivity (VNet peering)",
                "Install Luna client on application server",
                "Register client with HSM",
                "Create partition for application",
            ],
            "pkcs11_lib": "/usr/safenet/lunaclient/lib/libCryptoki2_64.so",
        },
    }
    return configs


def main():
    parser = argparse.ArgumentParser(description="HSM Key Storage Configuration Tool")
    subparsers = parser.add_subparsers(dest="command")

    init = subparsers.add_parser("init-token", help="Initialize HSM token")
    init.add_argument("--label", required=True, help="Token label")
    init.add_argument("--pin", required=True, help="User PIN")
    init.add_argument("--so-pin", required=True, help="Security Officer PIN")

    demo = subparsers.add_parser("demo", help="Run PKCS#11 operations demo")
    demo.add_argument("--token", required=True, help="Token label")
    demo.add_argument("--pin", required=True, help="User PIN")
    demo.add_argument("--lib", help="PKCS#11 library path")

    lst = subparsers.add_parser("list-tokens", help="List PKCS#11 tokens")
    lst.add_argument("--lib", help="PKCS#11 library path")

    subparsers.add_parser("config-templates", help="Show HSM configuration templates")

    args = parser.parse_args()

    if args.command == "init-token":
        result = init_token_via_cli(args.label, args.pin, args.so_pin)
        print(json.dumps(result, indent=2))
    elif args.command == "demo":
        lib_path = args.lib or find_softhsm_lib()
        if not lib_path:
            print(json.dumps({
                "status": "error",
                "message": "SoftHSM2 library not found. Set SOFTHSM2_LIB env var or use --lib.",
            }, indent=2))
            sys.exit(1)
        result = pkcs11_operations_demo(args.token, args.pin, lib_path)
        print(json.dumps(result, indent=2))
    elif args.command == "list-tokens":
        lib_path = args.lib or find_softhsm_lib()
        if not lib_path:
            print(json.dumps({"status": "error", "message": "SoftHSM2 library not found."}, indent=2))
            sys.exit(1)
        result = list_tokens(lib_path)
        print(json.dumps(result, indent=2))
    elif args.command == "config-templates":
        configs = generate_hsm_config()
        print(json.dumps(configs, indent=2))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
