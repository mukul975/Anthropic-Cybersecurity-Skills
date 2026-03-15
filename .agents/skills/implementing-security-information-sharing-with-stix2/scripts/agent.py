#!/usr/bin/env python3
"""STIX 2.1 threat intelligence sharing agent.

Creates, validates, and exports STIX 2.1 objects including indicators,
malware, campaigns, and relationships using the stix2 Python library.
"""

import argparse
import json
import sys
import datetime
import uuid

try:
    import stix2
    from stix2 import Indicator, Malware, Campaign, Relationship, Bundle
    from stix2 import ThreatActor, Identity, Sighting, AttackPattern
    HAS_STIX2 = True
except ImportError:
    HAS_STIX2 = False

try:
    from taxii2client.v21 import Collection, Server
    HAS_TAXII = True
except ImportError:
    HAS_TAXII = False


IDENTITY = None
if HAS_STIX2:
    IDENTITY = Identity(
        id="identity--f165a29e-a997-5f8a-a63b-4b72b9f2f963",
        name="Security Operations Center",
        identity_class="organization",
    )


def create_indicator(value, indicator_type="ipv4-addr", confidence=80, tlp="TLP:AMBER"):
    """Create a STIX 2.1 Indicator object."""
    if not HAS_STIX2:
        return {"error": "stix2 not installed. pip install stix2"}
    pattern_map = {
        "ipv4-addr": f"[ipv4-addr:value = '{value}']",
        "domain-name": f"[domain-name:value = '{value}']",
        "url": f"[url:value = '{value}']",
        "file-sha256": f"[file:hashes.'SHA-256' = '{value}']",
        "file-md5": f"[file:hashes.MD5 = '{value}']",
        "email-addr": f"[email-addr:value = '{value}']",
    }
    pattern = pattern_map.get(indicator_type, f"[ipv4-addr:value = '{value}']")
    marking = stix2.TLP_AMBER if tlp == "TLP:AMBER" else stix2.TLP_GREEN
    return Indicator(
        name=f"Malicious {indicator_type}: {value}",
        pattern=pattern,
        pattern_type="stix",
        valid_from=datetime.datetime.now(datetime.timezone.utc),
        confidence=confidence,
        created_by_ref=IDENTITY.id,
        object_marking_refs=[marking],
    )


def create_malware(name, malware_types=None, is_family=True, description=""):
    """Create a STIX 2.1 Malware object."""
    if not HAS_STIX2:
        return {"error": "stix2 not installed"}
    return Malware(
        name=name,
        malware_types=malware_types or ["ransomware"],
        is_family=is_family,
        description=description or f"Malware family: {name}",
        created_by_ref=IDENTITY.id,
    )


def create_campaign(name, description="", first_seen=None):
    """Create a STIX 2.1 Campaign object."""
    if not HAS_STIX2:
        return {"error": "stix2 not installed"}
    kwargs = {"name": name, "description": description or f"Campaign: {name}",
              "created_by_ref": IDENTITY.id}
    if first_seen:
        kwargs["first_seen"] = first_seen
    return Campaign(**kwargs)


def create_relationship(source, target, relationship_type="indicates"):
    """Create a STIX 2.1 Relationship."""
    if not HAS_STIX2:
        return {"error": "stix2 not installed"}
    return Relationship(
        source_ref=source.id if hasattr(source, "id") else source,
        target_ref=target.id if hasattr(target, "id") else target,
        relationship_type=relationship_type,
        created_by_ref=IDENTITY.id,
    )


def build_threat_report(indicators, malware_obj=None, campaign_obj=None):
    """Build a STIX 2.1 Bundle with all objects and relationships."""
    if not HAS_STIX2:
        return {"error": "stix2 not installed"}
    objects = [IDENTITY] + list(indicators)
    relationships = []

    if malware_obj:
        objects.append(malware_obj)
        for ind in indicators:
            rel = create_relationship(ind, malware_obj, "indicates")
            relationships.append(rel)

    if campaign_obj:
        objects.append(campaign_obj)
        if malware_obj:
            rel = create_relationship(campaign_obj, malware_obj, "uses")
            relationships.append(rel)

    objects.extend(relationships)
    bundle = Bundle(objects=objects)
    return bundle


def publish_to_taxii(bundle, collection_url, username=None, password=None):
    """Publish STIX bundle to TAXII 2.1 collection."""
    if not HAS_TAXII:
        return {"error": "taxii2-client not installed. pip install taxii2-client"}
    try:
        collection = Collection(collection_url, user=username, password=password)
        collection.add_objects(bundle.serialize())
        return {"status": "published", "collection": collection_url,
                "object_count": len(bundle.objects)}
    except Exception as e:
        return {"error": str(e)}


def validate_bundle(bundle_json):
    """Validate a STIX 2.1 bundle."""
    if not HAS_STIX2:
        return {"error": "stix2 not installed"}
    try:
        parsed = stix2.parse(bundle_json, allow_custom=True)
        return {"valid": True, "type": parsed.type,
                "object_count": len(parsed.objects) if hasattr(parsed, "objects") else 1}
    except Exception as e:
        return {"valid": False, "error": str(e)}


def main():
    parser = argparse.ArgumentParser(description="STIX 2.1 threat intelligence sharing agent")
    parser.add_argument("--create-indicator", help="Create indicator from value (e.g. 198.51.100.42)")
    parser.add_argument("--type", default="ipv4-addr", help="Indicator type (default: ipv4-addr)")
    parser.add_argument("--malware", help="Create malware object with this name")
    parser.add_argument("--campaign", help="Create campaign object with this name")
    parser.add_argument("--validate", help="Validate a STIX JSON file")
    parser.add_argument("--output", "-o", help="Output STIX bundle JSON path")
    args = parser.parse_args()

    print("[*] STIX 2.1 Threat Intelligence Sharing Agent")
    print(f"    stix2 available: {HAS_STIX2}")
    print(f"    taxii2-client available: {HAS_TAXII}")

    if args.validate:
        with open(args.validate) as f:
            result = validate_bundle(f.read())
        print(json.dumps(result, indent=2))
        sys.exit(0)

    if not HAS_STIX2:
        print("[!] Install stix2: pip install stix2")
        sys.exit(1)

    indicators = []
    if args.create_indicator:
        ind = create_indicator(args.create_indicator, args.type)
        indicators.append(ind)
        print(f"[+] Created indicator: {ind.name}")
    else:
        demo_iocs = [("198.51.100.42", "ipv4-addr"), ("evil.example.com", "domain-name"),
                     ("a" * 64, "file-sha256")]
        for val, itype in demo_iocs:
            indicators.append(create_indicator(val, itype))
        print(f"[DEMO] Created {len(indicators)} sample indicators")

    malware_obj = create_malware(args.malware) if args.malware else create_malware("DemoRAT", ["trojan"])
    campaign_obj = create_campaign(args.campaign) if args.campaign else None
    bundle = build_threat_report(indicators, malware_obj, campaign_obj)

    print(f"\n[*] Bundle: {bundle.id}")
    print(f"    Objects: {len(bundle.objects)}")
    for obj in bundle.objects:
        print(f"    - {obj.type}: {getattr(obj, 'name', getattr(obj, 'id', ''))}")

    if args.output:
        with open(args.output, "w") as f:
            f.write(bundle.serialize(pretty=True))
        print(f"[*] Bundle saved to {args.output}")

    print(json.dumps({"objects": len(bundle.objects), "stix_version": "2.1"}, indent=2))


if __name__ == "__main__":
    main()
