# API Reference: Ransomware Encryption Mechanism Analysis

## PyCryptodome - Encryption Testing

### AES Decryption
```python
from Crypto.Cipher import AES

# AES-CBC
cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = cipher.decrypt(ciphertext)

# AES-CTR
cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
plaintext = cipher.decrypt(ciphertext)

# AES-ECB (weak mode used by some ransomware)
cipher = AES.new(key, AES.MODE_ECB)
plaintext = cipher.decrypt(ciphertext)
```

### ChaCha20 Decryption
```python
from Crypto.Cipher import ChaCha20
cipher = ChaCha20.new(key=key, nonce=nonce)
plaintext = cipher.decrypt(ciphertext)
```

### RSA Key Analysis
```python
from Crypto.PublicKey import RSA
key = RSA.import_key(open("pubkey.pem").read())
print(f"Key size: {key.size_in_bits()} bits")
print(f"Modulus (n): {key.n}")
print(f"Exponent (e): {key.e}")
```

## pefile - Crypto API Import Detection

### Syntax
```python
import pefile
pe = pefile.PE("ransomware.exe")
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    for imp in entry.imports:
        print(f"{entry.dll.decode()} -> {imp.name}")
```

### Key Windows Crypto APIs
| API | Purpose |
|-----|---------|
| `CryptAcquireContext` | Initialize crypto provider |
| `CryptGenRandom` | CSPRNG random bytes |
| `CryptGenKey` | Generate symmetric key |
| `CryptEncrypt` | Encrypt data via CryptoAPI |
| `CryptImportKey` | Import key blob |
| `BCryptOpenAlgorithmProvider` | CNG algorithm handle |
| `BCryptEncrypt` | CNG encryption |
| `BCryptGenerateKeyPair` | CNG asymmetric keygen |

## Volatility 3 - Key Recovery from Memory

### Syntax
```bash
vol3 -f memory.dmp windows.yarascan --yara-rule "aes_key"
vol3 -f memory.dmp windows.malfind
vol3 -f memory.dmp windows.pslist
vol3 -f memory.dmp windows.handles --pid <PID>
```

### AES Key Schedule YARA Rule
```yara
rule AES_Key_Schedule {
    strings:
        $sbox = { 63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76 }
    condition:
        $sbox
}
```

## Entropy Analysis Thresholds

| Range | Interpretation |
|-------|---------------|
| 0-1 | Empty / uniform data |
| 1-5 | Normal code / plaintext |
| 5-7 | Compressed or obfuscated |
| 7-7.9 | Encrypted (block cipher) |
| 7.9-8.0 | Encrypted (stream cipher / AES-CTR) |

## Known Ransomware Encryption Schemes

| Family | File Cipher | Key Wrapping | Weakness |
|--------|------------|-------------|----------|
| WannaCry | AES-128-CBC | RSA-2048 | Key may persist in memory |
| LockBit 3.0 | AES-256-CTR | RSA-2048 | None known |
| Conti | AES-256-CBC | RSA-4096 | Leaked builder exposes keys |
| REvil | Salsa20 | ECDH | None known |
| STOP/Djvu | AES-256-CFB | RSA-1024 | Offline key variant decryptable |
| Hive | ChaCha20 | RSA-4096 | Master key recovered by FBI |
| BlackCat | AES-256 | RSA-4096 | None known |
| Babuk | ChaCha20 | ECDH (Curve25519) | Leaked source code |
| Akira | ChaCha20 | RSA-4096 | None known |
| Phobos | AES-256-CBC | RSA-1024 | Weak RSA key size |

## File Structure Patterns

### Common Ransomware File Layout
```
[encrypted_data][encrypted_aes_key(256B)][iv(16B)][magic_marker(4-8B)]
```

### Identifying Appended Metadata
```python
with open("file.locked", "rb") as f:
    f.seek(-280, 2)  # Seek 280 bytes from end
    tail = f.read()
    rsa_blob = tail[:256]   # RSA-2048 encrypted key
    iv = tail[256:272]      # AES IV (16 bytes)
    marker = tail[272:]     # Ransomware magic marker
```

## NoMoreRansom / ID Ransomware

### Identification
```
Upload encrypted file + ransom note to:
  https://id-ransomware.malwarehunterteam.com/
```

### Free Decryptors
```
Check for available decryptors:
  https://www.nomoreransom.org/en/decryption-tools.html
```

## Ghidra - Reverse Engineering Crypto Routines

### Crypto Identification Steps
```
1. Search > For Strings > "AES", "RSA", "Crypt", "encrypt"
2. Search > For Bytes > AES S-Box: 63 7c 77 7b f2 6b
3. Imports > advapi32.dll / bcrypt.dll for Crypto API calls
4. Trace CryptEncrypt xrefs to find encryption routine
5. Identify key buffer size (16=AES-128, 32=AES-256)
6. Check for CryptGenRandom vs time()/GetTickCount seed
```
