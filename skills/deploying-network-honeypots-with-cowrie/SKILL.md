\---

name: deploying-network-honeypots-with-cowrie

description: >-

&#x20; Deploy, configure, and monitor Cowrie SSH/Telnet network honeypots using Docker to capture brute-force attempts,

&#x20; log attacker commands, and collect dropped malware payloads for threat intelligence.

domain: cybersecurity

subdomain: deception-technology

tags: \[deception, honeypot, cowrie, ssh, telnet, threat-intelligence, malware-capture, active-defense]

atlas\_techniques: \[]

d3fend\_techniques: \[D3-DEC]

nist\_ai\_rmf: \[]

nist\_csf: \[DE.CM-01, DE.AE-02, ID.RA-03]

version: "1.0"

author: Pravesh

license: Apache-2.0

\---



\## When to Use

Trigger this skill when:

\- Deploying decoy SSH or Telnet services on internal or perimeter networks to detect unauthorized lateral movement or external scanning.

\- Capturing attacker IP addresses, brute-force credentials, and interactive TTY session logs for threat intelligence.

\- Intercepting and isolating automated malware payloads (e.g., Mirai, botnet scripts) dropped via `curl`, `wget`, or SFTP/SCP.



\## Prerequisites

\- Linux host with Docker and Docker Compose installed.

\- Administrative (`sudo` or `root`) access to bind host network ports or configure IPTables redirects.

\- Basic understanding of JSON log parsing tools (`jq`) and log shipping pipelines (SIEM/ELK).



\## Workflow



\### Step 1: Deploy Cowrie via Docker

Deploy a containerized Cowrie instance exposing SSH (port 2222) and Telnet (port 2223) to avoid conflicts with host SSH services.



```bash

\# Pull official Cowrie image

docker pull cowrie/cowrie:latest



\# Create host persistent volumes for logs and captured downloads

mkdir -p /var/log/cowrie /var/lib/cowrie/downloads /var/lib/cowrie/tty



\# Start Cowrie container with volume mounts

docker run -d \\

&#x20; --name cowrie-honeypot \\

&#x20; --restart unless-stopped \\

&#x20; -p 2222:2222 \\

&#x20; -p 2223:2223 \\

&#x20; -v /var/log/cowrie:/cowrie/var/log/cowrie \\

&#x20; -v /var/lib/cowrie/downloads:/cowrie/var/lib/cowrie/downloads \\

&#x20; -v /var/lib/cowrie/tty:/cowrie/var/lib/cowrie/tty \\

&#x20; cowrie/cowrie:latest

Step 2: Route Production Port 22 Traffic to Decoy (Optional)

# Redirect incoming host port 22 traffic to Cowrie container on port 2222
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
sudo iptables -t nat -A PREROUTING -p tcp --dport 23 -j REDIRECT --to-port 2223

Step 3: Monitor and Parse Structured JSON Logs
Cowrie records all login attempts, executed commands, and network downloads in " /var/log/cowrie/cowrie.json "

# View real-time authentication attempts (successful and failed)
tail -f /var/log/cowrie/cowrie.json | jq -c 'select(.eventid=="cowrie.login.success" or .eventid=="cowrie.login.failed") | {timestamp, src_ip, username, password, eventid}'

# Extract all executed terminal commands from interactive session logs
jq -s '.[] | select(.eventid=="cowrie.command.input") | {timestamp, session, src_ip, input}' /var/log/cowrie/cowrie.json

# List downloaded binary payloads and their calculated SHA-256 hashes
jq -s '.[] | select(.eventid=="cowrie.session.file_download") | {timestamp, src_ip, url, shasum, outfile}' /var/log/cowrie/cowrie.json

Step 4: Replay Attacker Interactive Sessions
Session log files are recorded in UML format under the tty/ directory and can be replayed using Cowrie's playlog utility or rendered using Python tools.

# Replay a captured attacker session file inside the container
docker exec -it cowrie-honeypot playlog /cowrie/var/lib/cowrie/tty/<session_file_id>

------

Verification
Test connectivity from an external or separate test host:

Bash
ssh -p 2222 root@<honeypot_ip>
Enter mock credentials (e.g., root / 123456).

Run test decoy commands in the fake shell (uname -a, cat /etc/passwd, wget http://example.com/test.sh).

Check /var/log/cowrie/cowrie.json to verify that cowrie.login.success, cowrie.command.input, and session events were generated.




