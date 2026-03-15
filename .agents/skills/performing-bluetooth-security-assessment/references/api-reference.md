# BLE Security Assessment API Reference

## Bleak Python Library (v0.21+)

### Device Discovery
```python
from bleak import BleakScanner

# Scan with advertisement data
devices = await BleakScanner.discover(timeout=10.0, return_adv=True)
# Returns: dict[str, tuple[BLEDevice, AdvertisementData]]

# Find specific device
device = await BleakScanner.find_device_by_name("DeviceName", timeout=10.0)
device = await BleakScanner.find_device_by_address("AA:BB:CC:DD:EE:FF", timeout=10.0)
```

### GATT Client Operations
```python
from bleak import BleakClient

async with BleakClient(address, timeout=15.0) as client:
    # Enumerate services
    for service in client.services:
        print(service.uuid, service.description)
        for char in service.characteristics:
            print(char.uuid, char.properties, char.descriptors)

    # Read characteristic
    value = await client.read_gatt_char("00002a19-0000-1000-8000-00805f9b34fb")

    # Write characteristic
    await client.write_gatt_char(char_uuid, bytearray([0x01, 0x02]))

    # Subscribe to notifications
    await client.start_notify(char_uuid, callback)
    await client.stop_notify(char_uuid)
```

## Common GATT Service UUIDs

| UUID (16-bit) | Service Name |
|---------------|-------------|
| `0x180D` | Heart Rate |
| `0x1810` | Blood Pressure |
| `0x1808` | Glucose |
| `0x180F` | Battery Service |
| `0x180A` | Device Information |
| `0x1812` | Human Interface Device |
| `0x1811` | Alert Notification |
| `0x1802` | Immediate Alert |
| `0x1803` | Link Loss |

## BLE Security Modes

| Mode | Level | Description |
|------|-------|-------------|
| LE Security Mode 1 | Level 1 | No security (no auth, no encryption) |
| LE Security Mode 1 | Level 2 | Unauthenticated pairing with encryption |
| LE Security Mode 1 | Level 3 | Authenticated pairing with encryption |
| LE Security Mode 1 | Level 4 | Authenticated LE Secure Connections |
| LE Security Mode 2 | Level 1 | Unauthenticated data signing |
| LE Security Mode 2 | Level 2 | Authenticated data signing |

## Linux BlueZ Commands

```bash
# Scan for BLE devices
sudo hcitool lescan

# Device info
sudo hcitool leinfo AA:BB:CC:DD:EE:FF

# Interactive GATT tool
gatttool -b AA:BB:CC:DD:EE:FF -I
> connect
> primary          # List services
> characteristics  # List characteristics
> char-read-hnd 0x000e

# btmgmt commands
sudo btmgmt info
sudo btmgmt find -l
sudo btmgmt pair -c 3 -t 0 AA:BB:CC:DD:EE:FF
```
