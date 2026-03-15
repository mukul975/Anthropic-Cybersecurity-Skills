# Active Breach Containment API Reference

## CrowdStrike Falcon - Host Containment

```bash
# Contain a host (network isolation)
curl -X POST "https://api.crowdstrike.com/devices/entities/devices-actions/v2?action_name=contain" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ids": ["device_id_here"]}'

# Lift containment
curl -X POST "https://api.crowdstrike.com/devices/entities/devices-actions/v2?action_name=lift_containment" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"ids": ["device_id_here"]}'
```

## Microsoft Defender for Endpoint - Isolation

```powershell
# Isolate machine via API
$body = @{ Comment = "Breach containment INC-2025-001"; IsolationType = "Full" } | ConvertTo-Json
Invoke-RestMethod -Uri "https://api.securitycenter.microsoft.com/api/machines/$machineId/isolate" `
  -Method Post -Headers @{Authorization = "Bearer $token"} -Body $body -ContentType "application/json"

# Release from isolation
Invoke-RestMethod -Uri "https://api.securitycenter.microsoft.com/api/machines/$machineId/unisolate" `
  -Method Post -Headers @{Authorization = "Bearer $token"} `
  -Body (@{Comment = "Containment lifted"} | ConvertTo-Json) -ContentType "application/json"
```

## Active Directory - Credential Actions

```powershell
# Disable compromised account
Disable-ADAccount -Identity "jsmith"

# Reset password
Set-ADAccountPassword -Identity "jsmith" -Reset -NewPassword (ConvertTo-SecureString "NewP@ss!" -AsPlainText -Force)

# Revoke Azure AD sessions
Revoke-AzureADUserAllRefreshToken -ObjectId "user-object-id"

# KRBTGT double reset (first reset)
Reset-KrbtgtKeys -Server DC01 -Force
```

## Network Containment - iptables

```bash
# Block C2 IP
iptables -A INPUT -s 185.220.x.x -j DROP
iptables -A OUTPUT -d 185.220.x.x -j DROP

# Isolate host from network (allow management only)
iptables -A FORWARD -s 10.10.5.12 -d 10.10.0.1 -j ACCEPT
iptables -A FORWARD -s 10.10.5.12 -j DROP

# Block SMB lateral movement
iptables -A FORWARD -p tcp --dport 445 -j DROP
```

## DNS Sinkholing

```bash
# Add sinkhole entry
echo "127.0.0.1 evil.example.com" >> /etc/hosts

# Unbound DNS sinkhole
unbound-control local_zone "evil.example.com" redirect
unbound-control local_data "evil.example.com A 10.0.0.99"
```

## Evidence Collection

```bash
# Memory dump (Linux)
sudo dd if=/proc/kcore of=/evidence/memory.raw bs=1M

# Volatile data collection
ps auxww > /evidence/processes.txt
ss -tunap > /evidence/network.txt
cat /proc/net/arp > /evidence/arp.txt
```
