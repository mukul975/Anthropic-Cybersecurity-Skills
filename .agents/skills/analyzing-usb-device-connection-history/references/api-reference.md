# API Reference: Analyzing USB Device Connection History

## regipy (Python Registry Parser)

### Open and Parse Registry Hive

```python
from regipy.registry import RegistryHive

reg = RegistryHive("/path/to/SYSTEM")
key = reg.get_key("ControlSet001\\Enum\\USBSTOR")
for subkey in key.iter_subkeys():
    print(subkey.name, subkey.header.last_modified)
    for val in subkey.iter_values():
        print(f"  {val.name} = {val.value}")
```

### Key Registry Paths for USB Forensics

| Path | Hive | Description |
|------|------|-------------|
| `ControlSet00X\Enum\USBSTOR` | SYSTEM | USB mass storage device identifiers |
| `MountedDevices` | SYSTEM | Drive letter to device mapping |
| `ControlSet00X\Enum\USB` | SYSTEM | All USB devices (not just storage) |
| `Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2` | NTUSER.DAT | Per-user volume access history |

### Determine Active ControlSet

```python
select_key = reg.get_key("Select")
current = select_key.get_value("Current")
controlset = f"ControlSet{current:03d}"
```

## python-evtx (Event Log Parsing)

```python
from evtx import PyEvtxParser
import json

parser = PyEvtxParser("/path/to/System.evtx")
for record in parser.records_json():
    data = json.loads(record["data"])
    event_id = data["Event"]["System"]["EventID"]
    if event_id in (20001, 20003):  # USB plug events
        print(record["timestamp"], event_id)
```

## SetupAPI Log Parsing

```python
import re
with open("setupapi.dev.log", "r", errors="ignore") as f:
    content = f.read()
pattern = r"Section start (\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})"
for match in re.finditer(pattern, content):
    print("First install:", match.group(1))
```

## USB Forensic Registry Keys

| Key | Data |
|-----|------|
| `USBSTOR\Disk&Ven_X&Prod_Y&Rev_Z\Serial` | Device class and serial |
| `FriendlyName` value | Human-readable device name |
| `DeviceContainers` (SOFTWARE) | Device metadata with timestamps |
| `EMDMgmt` (SOFTWARE) | ReadyBoost device serial/volume info |

### References

- regipy: https://pypi.org/project/regipy/
- python-evtx: https://pypi.org/project/evtx/
- SANS USB forensics: https://www.sans.org/blog/usb-device-tracking-artifacts/
