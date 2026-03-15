# API Reference: Stuxnet-Style ICS Attack Detection

## Modbus TCP Protocol

### Frame Structure
| Offset | Size | Field |
|--------|------|-------|
| 0 | 2 | Transaction ID |
| 2 | 2 | Protocol ID (0x0000) |
| 4 | 2 | Length |
| 6 | 1 | Unit ID |
| 7 | 1 | Function Code |
| 8+ | var | Data |

### Write Function Codes (Attack-Relevant)
| Code | Name | Risk |
|------|------|------|
| 5 | Write Single Coil | Medium |
| 6 | Write Single Register | Medium |
| 15 | Write Multiple Coils | High |
| 16 | Write Multiple Registers | High |
| 22 | Mask Write Register | High |

## Siemens S7comm Protocol

### S7 Parameter Functions
| Code | Name |
|------|------|
| 0x04 | Read Variable |
| 0x05 | Write Variable |
| 0x1A | Request Download |
| 0x1B | Download Block |
| 0x1C | Download Ended |
| 0x28 | PLC Control (Start/Stop) |

## Wireshark/tshark Filters

### Modbus write operations
```bash
tshark -r capture.pcap -Y "modbus.func_code >= 5 && modbus.func_code <= 16"
```

### S7comm block downloads
```bash
tshark -r capture.pcap -Y "s7comm.param.func == 0x1a || s7comm.param.func == 0x1b"
```

### S7comm PLC stop/start
```bash
tshark -r capture.pcap -Y "s7comm.param.func == 0x28"
```

## Stuxnet IOC Signatures

### YARA Rule
```yara
rule Stuxnet_Driver {
    meta:
        description = "Stuxnet rootkit driver"
    strings:
        $mrxcls = "mrxcls.sys" ascii
        $mrxnet = "mrxnet.sys" ascii
        $mutex = "{A3BD0EA3-CD10-4258-8784-2F53E56E2010}"
    condition:
        any of them
}
```

### Registry Keys
```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MS-DOS Emulation
HKLM\SYSTEM\CurrentControlSet\Services\MRxCls
HKLM\SYSTEM\CurrentControlSet\Services\MRxNet
```

## Siemens Step 7 Project Structure

### Organization Blocks
| Block | Purpose |
|-------|---------|
| OB1 | Main program cycle |
| OB35 | 100ms cyclic interrupt |
| OB100 | Startup |

### File Extensions
| Extension | Content |
|-----------|---------|
| `.awl` | Statement List source |
| `.mc7` | Compiled machine code |
| `.s7p` | Project file |

## Snort/Suricata Rules for ICS
```
alert tcp any any -> any 502 (msg:"Modbus Write Multiple Registers";
  content:"|00 00|"; offset:2; depth:2;
  byte_test:1,=,16,7; sid:1000001;)
```
