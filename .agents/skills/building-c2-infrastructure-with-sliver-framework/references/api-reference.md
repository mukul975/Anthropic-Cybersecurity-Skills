# API Reference: Sliver C2 Framework

## Sliver CLI Commands
| Command | Description |
|---------|-------------|
| `generate --mtls host:port` | Generate session implant |
| `generate beacon --mtls host:port` | Generate beacon implant |
| `mtls --lhost IP --lport PORT` | Start mTLS listener |
| `https --lhost IP --lport PORT` | Start HTTPS listener |
| `dns --domains domain.com` | Start DNS listener |
| `sessions` | List active sessions |
| `beacons` | List active beacons |
| `use SESSION_ID` | Interact with session |

## Generate Options
| Flag | Description |
|------|-------------|
| `--name` | Implant name |
| `--os` | Target OS (windows/linux/darwin) |
| `--arch` | Architecture (amd64/386/arm64) |
| `--format` | exe/shellcode/shared-lib |
| `--seconds` | Beacon callback interval |
| `--jitter` | Beacon jitter percentage |
| `--mtls` | mTLS C2 endpoint |
| `--https` | HTTPS C2 endpoint |
| `--dns` | DNS C2 domain |

## Listener Types
| Type | Port | Use Case |
|------|------|----------|
| mTLS | 8888 | Encrypted, reliable |
| HTTPS | 443 | Blends with web traffic |
| DNS | 53 | Bypasses network filters |
| WireGuard | 51820 | VPN-based C2 |

## Post-Exploitation
```
execute-assembly     # .NET assembly in memory
sideload             # DLL sideloading
shell                # Interactive shell
upload/download      # File transfer
portfwd              # Port forwarding
socks5               # SOCKS5 proxy
```

## Sliver gRPC API (Protobuf)
```python
import grpc
from sliverpb import client_pb2_grpc
channel = grpc.secure_channel("localhost:31337", credentials)
stub = client_pb2_grpc.SliverRPCStub(channel)
```
