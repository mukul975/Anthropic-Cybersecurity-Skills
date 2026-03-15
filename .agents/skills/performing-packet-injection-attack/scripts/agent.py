#!/usr/bin/env python3
"""Agent for performing packet injection testing.

Crafts and sends test packets using Scapy for authorized security
assessments to validate IDS rules, firewall configurations, and
anti-spoofing controls.
"""

from scapy.all import (
    IP, TCP, UDP, ICMP, DNS, DNSQR, Raw,
    sr1, send, fragment, conf,
)
import json
import sys
from datetime import datetime


class PacketInjectionAgent:
    """Performs authorized packet injection tests using Scapy."""

    def __init__(self, target_ip, interface=None):
        self.target_ip = target_ip
        if interface:
            conf.iface = interface
        self.results = []

    def _record_result(self, test_name, technique, sent, response_info):
        """Record a test result."""
        result = {
            "test": test_name,
            "technique": technique,
            "target": self.target_ip,
            "timestamp": datetime.utcnow().isoformat(),
            "response": response_info,
        }
        self.results.append(result)
        return result

    def test_tcp_syn(self, port=80):
        """Send TCP SYN packet to test port state."""
        pkt = IP(dst=self.target_ip) / TCP(dport=port, flags="S", seq=1000)
        resp = sr1(pkt, timeout=3, verbose=0)
        if resp and resp.haslayer(TCP):
            flags = resp[TCP].flags
            state = "open" if flags == "SA" else "closed" if flags == "RA" else str(flags)
            return self._record_result("TCP SYN", "port_scan", True, {"port": port, "state": state})
        return self._record_result("TCP SYN", "port_scan", True, {"port": port, "state": "filtered"})

    def test_xmas_scan(self, port=80):
        """Send XMAS packet (FIN+PSH+URG flags) to test IDS detection."""
        pkt = IP(dst=self.target_ip) / TCP(dport=port, flags="FPU")
        send(pkt, verbose=0)
        return self._record_result("XMAS Scan", "T1046", True,
                                   {"flags": "FPU", "expected_ids": "XMAS scan detection"})

    def test_null_scan(self, port=80):
        """Send NULL packet (no flags) to test IDS detection."""
        pkt = IP(dst=self.target_ip) / TCP(dport=port, flags="")
        send(pkt, verbose=0)
        return self._record_result("NULL Scan", "T1046", True,
                                   {"flags": "none", "expected_ids": "NULL scan detection"})

    def test_invalid_flags(self, port=80):
        """Send packets with invalid TCP flag combinations."""
        results = []
        flag_combos = [("SYN+FIN", "SF"), ("SYN+RST", "SR"), ("ALL", "FSRPAUEC")]
        for name, flags in flag_combos:
            pkt = IP(dst=self.target_ip) / TCP(dport=port, flags=flags)
            send(pkt, verbose=0)
            results.append(self._record_result(
                f"Invalid Flags: {name}", "protocol_anomaly", True,
                {"flags": flags, "expected_ids": f"Invalid TCP flags: {name}"}
            ))
        return results

    def test_spoofed_source(self, spoofed_ip="192.0.2.100", port=80):
        """Send packet with spoofed source IP to test anti-spoofing."""
        pkt = IP(src=spoofed_ip, dst=self.target_ip) / TCP(dport=port, flags="S")
        send(pkt, verbose=0)
        return self._record_result("IP Spoofing", "anti_spoofing", True,
                                   {"spoofed_src": spoofed_ip, "expected": "Blocked by BCP38/uRPF"})

    def test_land_attack(self, port=80):
        """Send LAND attack packet (src==dst) to test protection."""
        pkt = IP(src=self.target_ip, dst=self.target_ip) / TCP(sport=port, dport=port, flags="S")
        send(pkt, verbose=0)
        return self._record_result("LAND Attack", "land_attack", True,
                                   {"src_eq_dst": True, "expected": "Dropped by OS/firewall"})

    def test_fragmentation_overlap(self, port=80):
        """Send overlapping IP fragments to test reassembly handling."""
        frag1 = IP(dst=self.target_ip, flags="MF", frag=0) / TCP(dport=port, flags="S") / Raw(load="A" * 24)
        frag2 = IP(dst=self.target_ip, frag=2) / Raw(load="B" * 24)
        send(frag1, verbose=0)
        send(frag2, verbose=0)
        return self._record_result("Fragment Overlap", "fragmentation", True,
                                   {"fragments": 2, "expected_ids": "Fragment overlap detection"})

    def test_icmp_payload(self):
        """Send ICMP with custom payload to test content inspection."""
        pkt = IP(dst=self.target_ip) / ICMP(type=8) / Raw(load="SECURITY_TEST_PAYLOAD")
        resp = sr1(pkt, timeout=3, verbose=0)
        return self._record_result("ICMP Custom Payload", "icmp_test", True,
                                   {"response": "echo_reply" if resp else "no_response"})

    def test_dns_query(self, domain="test.example.com"):
        """Send DNS query to test DNS filtering."""
        pkt = IP(dst=self.target_ip) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
        resp = sr1(pkt, timeout=3, verbose=0)
        return self._record_result("DNS Query", "dns_test", True,
                                   {"domain": domain, "response": "received" if resp else "blocked"})

    def test_low_ttl_evasion(self, ttl=3, port=80):
        """Send low-TTL packet to test IDS evasion detection."""
        pkt = IP(dst=self.target_ip, ttl=ttl) / TCP(dport=port, flags="S")
        send(pkt, verbose=0)
        return self._record_result("Low TTL Evasion", "ttl_evasion", True,
                                   {"ttl": ttl, "expected": "Packet expires before target"})

    def run_full_test_suite(self):
        """Run all packet injection tests."""
        self.test_tcp_syn()
        self.test_xmas_scan()
        self.test_null_scan()
        self.test_invalid_flags()
        self.test_spoofed_source()
        self.test_land_attack()
        self.test_fragmentation_overlap()
        self.test_icmp_payload()
        self.test_low_ttl_evasion()

        report = {
            "target": self.target_ip,
            "test_date": datetime.utcnow().isoformat(),
            "total_tests": len(self.results),
            "results": self.results,
        }
        return report


def main():
    if len(sys.argv) < 2:
        print("Usage: agent.py <target_ip> [interface] [test]")
        print("Tests: syn, xmas, null, flags, spoof, land, frag, icmp, all")
        sys.exit(1)

    target_ip = sys.argv[1]
    interface = sys.argv[2] if len(sys.argv) > 2 else None
    test = sys.argv[3] if len(sys.argv) > 3 else "all"

    agent = PacketInjectionAgent(target_ip, interface)

    if test == "all":
        report = agent.run_full_test_suite()
    elif test == "syn":
        agent.test_tcp_syn()
        report = {"results": agent.results}
    elif test == "xmas":
        agent.test_xmas_scan()
        report = {"results": agent.results}
    else:
        report = agent.run_full_test_suite()

    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
