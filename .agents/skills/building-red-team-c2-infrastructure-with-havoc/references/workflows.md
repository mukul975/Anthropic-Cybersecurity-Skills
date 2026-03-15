# Workflows: Havoc C2 Infrastructure Deployment

## Infrastructure Deployment Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│              HAVOC C2 DEPLOYMENT WORKFLOW                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. DOMAIN & INFRASTRUCTURE PREPARATION (Week -4)                │
│     ├── Register domain names (aged 30+ days)                    │
│     ├── Submit domains for categorization (Bluecoat, Fortiguard) │
│     ├── Provision VPS instances (Teamserver + Redirector)        │
│     ├── Obtain SSL certificates (Let's Encrypt)                  │
│     └── Configure DNS A records                                  │
│                                                                  │
│  2. TEAMSERVER SETUP (Day 1)                                     │
│     ├── Install dependencies on Ubuntu VPS                       │
│     ├── Clone and build Havoc from source                        │
│     ├── Create teamserver profile (havoc.yaotl)                  │
│     │   ├── Configure operator credentials                       │
│     │   ├── Define listeners (HTTPS, SMB)                        │
│     │   ├── Set Demon agent parameters                           │
│     │   └── Configure malleable traffic profiles                 │
│     ├── Harden teamserver (iptables, fail2ban)                   │
│     └── Start teamserver with verbose logging                    │
│                                                                  │
│  3. REDIRECTOR CONFIGURATION (Day 1-2)                           │
│     ├── Install Nginx on redirector VPS                          │
│     ├── Configure SSL termination                                │
│     ├── Set up reverse proxy rules                               │
│     │   ├── Forward C2 URIs to teamserver                        │
│     │   └── Redirect non-matching traffic to legit site          │
│     ├── Configure access logging                                 │
│     └── Test end-to-end connectivity                             │
│                                                                  │
│  4. PAYLOAD DEVELOPMENT (Day 2-3)                                │
│     ├── Generate Demon shellcode via Havoc Client                │
│     ├── Develop custom loader (C/Rust/Nim)                       │
│     │   ├── AES-encrypt shellcode                                │
│     │   ├── Implement sleep obfuscation                          │
│     │   ├── Add sandbox checks                                   │
│     │   └── Use indirect syscalls                                │
│     ├── Test against AV/EDR in lab                               │
│     └── Package for delivery vector                              │
│                                                                  │
│  5. OPERATIONAL TESTING (Day 3-4)                                │
│     ├── Test beacon callback through full chain                  │
│     ├── Verify redirector filtering                              │
│     ├── Test sleep/jitter behavior                               │
│     ├── Validate post-exploitation modules                       │
│     └── Confirm kill switch functionality                        │
│                                                                  │
│  6. OPERATIONAL USE (Engagement period)                          │
│     ├── Deploy payloads via approved vectors                     │
│     ├── Manage sessions through Havoc Client                     │
│     ├── Execute post-exploitation tasks                          │
│     ├── Maintain operator logs                                   │
│     └── Monitor infrastructure health                            │
│                                                                  │
│  7. TEAR-DOWN (Post-engagement)                                  │
│     ├── Remove all implants from target systems                  │
│     ├── Archive engagement logs                                  │
│     ├── Destroy VPS instances                                    │
│     ├── Release domain names                                     │
│     └── Provide IOCs to client for deconfliction                 │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Havoc Listener Configuration Decision Tree

```
Select Listener Type
│
├── External (Internet-facing targets)?
│   ├── HTTPS Listener
│   │   ├── Use valid SSL certificate
│   │   ├── Configure malleable URIs
│   │   ├── Set User-Agent to match target
│   │   └── Route through redirector
│   └── HTTP Listener (lab only)
│       └── Never use in production operations
│
├── Internal (post-initial access)?
│   ├── SMB Listener (named pipe)
│   │   ├── For workstation-to-workstation pivoting
│   │   └── No direct internet connectivity needed
│   └── TCP Listener
│       └── For direct internal connections
│
└── Advanced?
    └── External C2 Listener
        ├── Custom protocol over DNS
        ├── Domain fronting via CDN
        └── Third-party service channels
```

## Terraform Deployment Template

```hcl
# main.tf - Automated Havoc C2 Infrastructure
provider "aws" {
  region = "us-east-1"
}

resource "aws_instance" "teamserver" {
  ami           = "ami-0c7217cdde317cfec"  # Ubuntu 22.04
  instance_type = "t3.medium"
  key_name      = var.ssh_key_name

  vpc_security_group_ids = [aws_security_group.teamserver_sg.id]

  user_data = file("scripts/install_havoc.sh")

  tags = {
    Name = "havoc-teamserver"
  }
}

resource "aws_instance" "redirector" {
  ami           = "ami-0c7217cdde317cfec"
  instance_type = "t3.micro"
  key_name      = var.ssh_key_name

  vpc_security_group_ids = [aws_security_group.redirector_sg.id]

  user_data = file("scripts/install_redirector.sh")

  tags = {
    Name = "havoc-redirector"
  }
}

resource "aws_security_group" "teamserver_sg" {
  name = "havoc-teamserver-sg"

  ingress {
    from_port   = 40056
    to_port     = 40056
    protocol    = "tcp"
    cidr_blocks = [var.operator_ip]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_instance.redirector.public_ip]
  }
}

resource "aws_security_group" "redirector_sg" {
  name = "havoc-redirector-sg"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
```

## OPSEC Checklist

- [ ] Domains aged 30+ days before use
- [ ] Domains categorized in web proxies
- [ ] Valid SSL certificates installed
- [ ] Teamserver port (40056) firewalled to operator IPs only
- [ ] Redirector configured to filter non-C2 traffic
- [ ] Malleable C2 profile customized (URIs, headers, user-agent)
- [ ] Demon sleep set to 10+ seconds with 30%+ jitter
- [ ] Payload tested against target AV/EDR in lab
- [ ] Kill date set on all payloads
- [ ] Operator logs enabled and encrypted
- [ ] Emergency deconfliction process documented
