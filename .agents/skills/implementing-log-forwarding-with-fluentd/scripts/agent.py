#!/usr/bin/env python3
"""Fluentd/Fluent Bit log forwarding configuration generator and tester."""

import json
import argparse
import socket
import struct
import time
from datetime import datetime

try:
    from fluent import sender, event
    HAS_FLUENT = True
except ImportError:
    HAS_FLUENT = False


def generate_fluentbit_config(inputs, output_host="127.0.0.1", output_port=24224):
    """Generate Fluent Bit configuration for log collection and forwarding."""
    sections = ["[SERVICE]\n    Flush        5\n    Daemon       Off\n    Log_Level    info\n    Parsers_File parsers.conf\n"]

    input_configs = {
        "syslog": "[INPUT]\n    Name         syslog\n    Tag          syslog.*\n    Listen       0.0.0.0\n    Port         5140\n    Mode         udp\n    Parser       syslog-rfc3164\n",
        "tail": "[INPUT]\n    Name         tail\n    Tag          file.*\n    Path         /var/log/*.log\n    DB           /var/log/flb_tail.db\n    Read_from_Head True\n    Refresh_Interval 10\n",
        "systemd": "[INPUT]\n    Name         systemd\n    Tag          systemd.*\n    Systemd_Filter _SYSTEMD_UNIT=sshd.service\n    Read_From_Tail On\n",
        "tcp": "[INPUT]\n    Name         tcp\n    Tag          tcp.*\n    Listen       0.0.0.0\n    Port         5170\n    Format       json\n",
    }

    for inp in inputs:
        if inp in input_configs:
            sections.append(input_configs[inp])

    sections.append(
        "[FILTER]\n"
        "    Name         record_modifier\n"
        "    Match        *\n"
        "    Record       hostname ${HOSTNAME}\n"
        "    Record       environment production\n"
    )
    sections.append(
        "[FILTER]\n"
        "    Name         grep\n"
        "    Match        syslog.*\n"
        "    Exclude      message ^healthcheck\n"
    )
    sections.append(
        f"[OUTPUT]\n"
        f"    Name         forward\n"
        f"    Match        *\n"
        f"    Host         {output_host}\n"
        f"    Port         {output_port}\n"
        f"    Retry_Limit  5\n"
    )
    return "\n".join(sections)


def generate_fluentd_config(outputs, bind_port=24224):
    """Generate Fluentd aggregator configuration."""
    sections = [
        f"<source>\n"
        f"  @type forward\n"
        f"  port {bind_port}\n"
        f"  bind 0.0.0.0\n"
        f"  <security>\n"
        f"    shared_key fluentd_secure_key_change_me\n"
        f"    self_hostname aggregator.local\n"
        f"  </security>\n"
        f"</source>\n",
    ]

    sections.append(
        "<filter **>\n"
        "  @type record_transformer\n"
        "  <record>\n"
        "    received_at ${time}\n"
        "    aggregator_host \"#{Socket.gethostname}\"\n"
        "  </record>\n"
        "</filter>\n"
    )

    output_configs = {
        "elasticsearch": (
            '<match **>\n'
            '  @type elasticsearch\n'
            '  host elasticsearch.local\n'
            '  port 9200\n'
            '  logstash_format true\n'
            '  logstash_prefix fluentd\n'
            '  include_tag_key true\n'
            '  <buffer>\n'
            '    @type file\n'
            '    path /var/log/fluentd/buffer/es\n'
            '    flush_interval 10s\n'
            '    chunk_limit_size 8MB\n'
            '    retry_max_interval 30\n'
            '    retry_forever true\n'
            '  </buffer>\n'
            '</match>\n'
        ),
        "s3": (
            '<match **>\n'
            '  @type s3\n'
            '  s3_bucket security-logs-bucket\n'
            '  s3_region us-east-1\n'
            '  path logs/\n'
            '  time_slice_format %Y%m%d%H\n'
            '  <buffer time>\n'
            '    @type file\n'
            '    path /var/log/fluentd/buffer/s3\n'
            '    timekey 3600\n'
            '    timekey_wait 10m\n'
            '  </buffer>\n'
            '</match>\n'
        ),
        "splunk": (
            '<match **>\n'
            '  @type splunk_hec\n'
            '  hec_host splunk.local\n'
            '  hec_port 8088\n'
            '  hec_token YOUR_HEC_TOKEN\n'
            '  index main\n'
            '  source fluentd\n'
            '  <buffer>\n'
            '    @type memory\n'
            '    flush_interval 5s\n'
            '  </buffer>\n'
            '</match>\n'
        ),
    }

    for out in outputs:
        if out in output_configs:
            sections.append(output_configs[out])

    return "\n".join(sections)


def validate_config(config_text, config_type="fluentbit"):
    """Validate configuration syntax for common issues."""
    errors = []
    lines = config_text.split("\n")
    open_sections = 0
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            if config_type == "fluentbit":
                valid_sections = {"[SERVICE]", "[INPUT]", "[FILTER]", "[OUTPUT]", "[PARSER]"}
                if stripped not in valid_sections:
                    errors.append(f"Line {i}: Unknown section '{stripped}'")
        if stripped.startswith("<") and not stripped.startswith("</"):
            open_sections += 1
        if stripped.startswith("</"):
            open_sections -= 1
        if open_sections < 0:
            errors.append(f"Line {i}: Unexpected closing tag")

    if config_type == "fluentd" and open_sections != 0:
        errors.append(f"Unclosed XML-style tags: {open_sections} still open")

    return {"valid": len(errors) == 0, "errors": errors}


def send_test_event(host="127.0.0.1", port=24224, tag="test.event"):
    """Send a test log event to Fluentd/Fluent Bit via forward protocol."""
    if HAS_FLUENT:
        fluentd_sender = sender.FluentSender(tag, host=host, port=port)
        test_data = {
            "message": "Log forwarding test event",
            "level": "info",
            "source": "fluentd-agent",
            "timestamp": datetime.utcnow().isoformat(),
        }
        result = fluentd_sender.emit("test", test_data)
        fluentd_sender.close()
        return {"sent": result, "tag": f"{tag}.test", "data": test_data}

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        import msgpack
        timestamp = int(time.time())
        record = {"message": "test event", "source": "agent"}
        packed = msgpack.packb([tag, timestamp, record])
        sock.sendall(packed)
        sock.close()
        return {"sent": True, "method": "raw_msgpack"}
    except Exception as e:
        return {"sent": False, "error": str(e)}


def generate_report(fb_config, fd_config, fb_valid, fd_valid, test_result):
    """Generate deployment report."""
    return {
        "report_time": datetime.utcnow().isoformat(),
        "fluent_bit_config_lines": len(fb_config.split("\n")),
        "fluentd_config_lines": len(fd_config.split("\n")),
        "fluent_bit_validation": fb_valid,
        "fluentd_validation": fd_valid,
        "test_event_result": test_result,
        "topology": {
            "forwarders": "Fluent Bit (endpoints)",
            "aggregator": "Fluentd (central)",
            "protocol": "Forward (TCP:24224)",
        },
    }


def main():
    parser = argparse.ArgumentParser(description="Fluentd/Fluent Bit Log Forwarding Agent")
    parser.add_argument("--inputs", nargs="+", default=["syslog", "tail"],
                        choices=["syslog", "tail", "systemd", "tcp"],
                        help="Fluent Bit input plugins to enable")
    parser.add_argument("--outputs", nargs="+", default=["elasticsearch"],
                        choices=["elasticsearch", "s3", "splunk"],
                        help="Fluentd output destinations")
    parser.add_argument("--aggregator-host", default="127.0.0.1")
    parser.add_argument("--aggregator-port", type=int, default=24224)
    parser.add_argument("--test-send", action="store_true", help="Send a test event")
    parser.add_argument("--output", default="fluentd_report.json")
    parser.add_argument("--write-configs", action="store_true", help="Write config files to disk")
    args = parser.parse_args()

    fb_config = generate_fluentbit_config(args.inputs, args.aggregator_host, args.aggregator_port)
    fd_config = generate_fluentd_config(args.outputs, args.aggregator_port)
    fb_valid = validate_config(fb_config, "fluentbit")
    fd_valid = validate_config(fd_config, "fluentd")

    test_result = {}
    if args.test_send:
        test_result = send_test_event(args.aggregator_host, args.aggregator_port)

    if args.write_configs:
        with open("fluent-bit.conf", "w") as f:
            f.write(fb_config)
        with open("fluentd.conf", "w") as f:
            f.write(fd_config)
        print("[+] Written fluent-bit.conf and fluentd.conf")

    report = generate_report(fb_config, fd_config, fb_valid, fd_valid, test_result)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[+] Fluent Bit: {len(args.inputs)} inputs, validation={'PASS' if fb_valid['valid'] else 'FAIL'}")
    print(f"[+] Fluentd: {len(args.outputs)} outputs, validation={'PASS' if fd_valid['valid'] else 'FAIL'}")
    print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
