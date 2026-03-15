#!/usr/bin/env python3
"""Agent for Hardware Security Module integration via PKCS#11 interface."""

import json
import argparse
from datetime import datetime

try:
    import pkcs11
    from pkcs11 import KeyType, ObjectClass, Mechanism
    from pkcs11.util.rsa import encode_rsa_public_key
except ImportError:
    pkcs11 = None


def load_library(lib_path):
    """Load PKCS#11 shared library."""
    if not pkcs11:
        raise RuntimeError("python-pkcs11 not installed: pip install python-pkcs11")
    return pkcs11.lib(lib_path)


def enumerate_slots(lib):
    """List all available PKCS#11 slots and token info."""
    slots = []
    for slot in lib.get_slots(token_present=True):
        token = slot.get_token()
        mechs = slot.get_mechanisms()
        slots.append({
            "slot_id": slot.slot_id,
            "slot_description": slot.slot_description.strip() if hasattr(slot, 'slot_description') else str(slot),
            "token_label": token.label.strip(),
            "token_manufacturer": token.manufacturer_id.strip(),
            "token_model": token.model.strip(),
            "token_serial": token.serial.strip(),
            "token_initialized": token.flags & pkcs11.TokenFlag.TOKEN_INITIALIZED != 0,
            "mechanism_count": len(list(mechs)),
            "supported_mechanisms": sorted([m.name for m in mechs])[:30],
        })
    return slots


def list_objects(lib, token_label, pin):
    """List all cryptographic objects stored on the HSM token."""
    token = lib.get_token(token_label=token_label)
    with token.open(user_pin=pin) as session:
        objects = []
        for obj in session.get_objects():
            obj_info = {
                "object_class": obj.object_class.name if hasattr(obj.object_class, 'name') else str(obj.object_class),
                "label": getattr(obj, 'label', 'N/A'),
            }
            if hasattr(obj, 'key_type'):
                obj_info["key_type"] = obj.key_type.name if hasattr(obj.key_type, 'name') else str(obj.key_type)
            if hasattr(obj, 'key_length'):
                obj_info["key_length"] = obj.key_length
            if hasattr(obj, 'id'):
                obj_info["id"] = obj.id.hex() if isinstance(obj.id, bytes) else str(obj.id)
            objects.append(obj_info)
        return objects


def generate_rsa_keypair(lib, token_label, pin, key_label="agent-rsa-2048", bits=2048):
    """Generate an RSA key pair on the HSM."""
    token = lib.get_token(token_label=token_label)
    with token.open(rw=True, user_pin=pin) as session:
        pub, priv = session.generate_keypair(
            KeyType.RSA, bits,
            store=True,
            label=key_label,
        )
        return {
            "action": "generate_rsa_keypair",
            "key_label": key_label,
            "key_size": bits,
            "public_key_class": pub.object_class.name,
            "private_key_class": priv.object_class.name,
            "status": "SUCCESS",
        }


def generate_ec_keypair(lib, token_label, pin, key_label="agent-ec-p256"):
    """Generate an EC P-256 key pair on the HSM."""
    token = lib.get_token(token_label=token_label)
    with token.open(rw=True, user_pin=pin) as session:
        ecparams = session.create_domain_parameters(
            KeyType.EC,
            {pkcs11.Attribute.EC_PARAMS: pkcs11.util.ec.encode_named_curve_parameters("secp256r1")},
            local=True,
        )
        pub, priv = ecparams.generate_keypair(store=True, label=key_label)
        return {
            "action": "generate_ec_keypair",
            "key_label": key_label,
            "curve": "secp256r1 (P-256)",
            "public_key_class": pub.object_class.name,
            "private_key_class": priv.object_class.name,
            "status": "SUCCESS",
        }


def sign_and_verify(lib, token_label, pin, key_label, data=b"HSM test message"):
    """Sign data with an RSA private key and verify with the public key."""
    token = lib.get_token(token_label=token_label)
    with token.open(user_pin=pin) as session:
        priv_keys = list(session.get_objects({
            pkcs11.Attribute.CLASS: ObjectClass.PRIVATE_KEY,
            pkcs11.Attribute.LABEL: key_label,
        }))
        if not priv_keys:
            return {"error": f"Private key '{key_label}' not found"}
        priv = priv_keys[0]
        signature = priv.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)

        pub_keys = list(session.get_objects({
            pkcs11.Attribute.CLASS: ObjectClass.PUBLIC_KEY,
            pkcs11.Attribute.LABEL: key_label,
        }))
        if not pub_keys:
            return {"error": f"Public key '{key_label}' not found"}
        pub = pub_keys[0]
        try:
            pub.verify(data, signature, mechanism=Mechanism.SHA256_RSA_PKCS)
            verified = True
        except Exception:
            verified = False

        return {
            "action": "sign_and_verify",
            "key_label": key_label,
            "data_length": len(data),
            "signature_length": len(signature),
            "signature_hex": signature[:32].hex() + "...",
            "mechanism": "SHA256_RSA_PKCS",
            "verified": verified,
        }


def query_mechanisms(lib, token_label):
    """List all supported mechanisms for the token's slot."""
    token = lib.get_token(token_label=token_label)
    slot = token.slot
    mechs = []
    for m in slot.get_mechanisms():
        info = slot.get_mechanism_info(m)
        mechs.append({
            "mechanism": m.name,
            "min_key_size": info.min_key_size if hasattr(info, 'min_key_size') else None,
            "max_key_size": info.max_key_size if hasattr(info, 'max_key_size') else None,
        })
    return mechs


def full_audit(lib, token_label, pin):
    """Run comprehensive HSM compliance audit."""
    slots = enumerate_slots(lib)
    objects = list_objects(lib, token_label, pin)
    mechanisms = query_mechanisms(lib, token_label)
    rsa_keys = [o for o in objects if o.get("key_type") == "RSA"]
    ec_keys = [o for o in objects if o.get("key_type") == "EC"]
    weak_keys = [o for o in objects if o.get("key_type") == "RSA" and (o.get("key_length") or 2048) < 2048]
    fips_mechs = {"RSA_PKCS", "SHA256_RSA_PKCS", "SHA384_RSA_PKCS", "SHA512_RSA_PKCS",
                  "ECDSA", "ECDSA_SHA256", "AES_CBC", "AES_GCM", "SHA256", "SHA384", "SHA512"}
    supported_names = {m["mechanism"] for m in mechanisms}
    fips_coverage = len(fips_mechs & supported_names)
    return {
        "audit_type": "HSM PKCS#11 Compliance Audit",
        "timestamp": datetime.utcnow().isoformat(),
        "slots": slots,
        "stored_objects": len(objects),
        "objects": objects[:30],
        "rsa_key_count": len(rsa_keys),
        "ec_key_count": len(ec_keys),
        "weak_rsa_keys": len(weak_keys),
        "total_mechanisms": len(mechanisms),
        "fips_mechanism_coverage": f"{fips_coverage}/{len(fips_mechs)}",
        "compliance": "PASS" if not weak_keys and fips_coverage >= 6 else "REVIEW",
    }


def main():
    parser = argparse.ArgumentParser(description="HSM PKCS#11 Integration Agent")
    parser.add_argument("--lib", required=True, help="Path to PKCS#11 shared library")
    parser.add_argument("--token", required=True, help="Token label")
    parser.add_argument("--pin", required=True, help="User PIN")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("slots", help="Enumerate PKCS#11 slots and tokens")
    sub.add_parser("objects", help="List stored cryptographic objects")
    p_rsa = sub.add_parser("gen-rsa", help="Generate RSA key pair")
    p_rsa.add_argument("--label", default="agent-rsa-2048")
    p_rsa.add_argument("--bits", type=int, default=2048)
    p_ec = sub.add_parser("gen-ec", help="Generate EC P-256 key pair")
    p_ec.add_argument("--label", default="agent-ec-p256")
    p_sign = sub.add_parser("sign-verify", help="Sign and verify test data")
    p_sign.add_argument("--key-label", required=True)
    sub.add_parser("mechanisms", help="List supported mechanisms")
    sub.add_parser("full", help="Full HSM compliance audit")
    args = parser.parse_args()

    lib = load_library(args.lib)

    if args.command == "slots":
        result = enumerate_slots(lib)
    elif args.command == "objects":
        result = list_objects(lib, args.token, args.pin)
    elif args.command == "gen-rsa":
        result = generate_rsa_keypair(lib, args.token, args.pin, args.label, args.bits)
    elif args.command == "gen-ec":
        result = generate_ec_keypair(lib, args.token, args.pin, args.label)
    elif args.command == "sign-verify":
        result = sign_and_verify(lib, args.token, args.pin, args.key_label)
    elif args.command == "mechanisms":
        result = query_mechanisms(lib, args.token)
    elif args.command == "full":
        result = full_audit(lib, args.token, args.pin)
    else:
        parser.print_help()
        return
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
