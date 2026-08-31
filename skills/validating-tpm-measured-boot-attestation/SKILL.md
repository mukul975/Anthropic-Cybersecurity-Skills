---
name: validating-tpm-measured-boot-attestation
description: 'Verifies TPM 2.0 measured-boot integrity and remote attestation with tpm2-tools -- reading PCRs (tpm2_pcrread), replaying the boot event log, generating and checking signed quotes (tpm2_quote/tpm2_checkquote), and sealing secrets to a PCR policy. Use when confirming a system booted trusted firmware/kernel for Zero Trust device posture, detecting boot-chain tampering via PCR drift, or building a golden-value baseline for fleet attestation. Do not use for detecting Secure Boot bypasses and revoked bootloaders via dbx - use detecting-secure-boot-bypass.'
domain: cybersecurity
subdomain: hardware-firmware-security
tags:
- hardware-firmware-security
- tpm
- measured-boot
- remote-attestation
- pcr
- tpm2-tools
- integrity-verification
- trusted-computing
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- PR.PS-01
mitre_attack:
- T1542
---
# Validating TPM Measured Boot and Attestation

> **Legal Notice:** Perform TPM operations only on systems you own or are authorized to assess. Some operations (clearing the TPM, taking ownership, defining NV indices) are destructive or can lock the device. This skill is for defensive integrity verification and authorized assessment.

## Overview

A Trusted Platform Module (TPM 2.0) is a hardware root of trust that supports **measured boot**: each stage of the boot chain hashes ("measures") the next stage and *extends* that measurement into a Platform Configuration Register (PCR) before handing off control. PCRs cannot be set arbitrarily — they can only be extended (`new = hash(old || measurement)`), so the final PCR value is a tamper-evident summary of everything that executed. The TCG firmware profile assigns specific meanings: UEFI firmware code/config measure into **PCR 0–7** (PCR 7 specifically captures Secure Boot policy), bootloaders measure the kernel into **PCR 8–9**, and Linux IMA measures executables into **PCR 10**.

Two complementary verifications matter. **Local validation** reads current PCRs (`tpm2_pcrread`) and replays the TPM event log (`tpm2_eventlog` on `/sys/kernel/security/tpm0/binary_bios_measurements`) to confirm the recorded measurements reproduce the live PCR values — proving the log is authentic and revealing exactly *what* changed if a value drifts from baseline. **Remote attestation** has the TPM produce a signed quote (`tpm2_quote`) over selected PCRs using an Attestation Key (AK), with a fresh nonce to prevent replay; a verifier then independently checks the signature and PCR digest (`tpm2_checkquote`) and compares against a golden/expected value. This lets a server cryptographically establish that a remote machine booted approved firmware and kernel before granting access, sealing secrets, or admitting it to a Zero Trust network.

This skill provides the full `tpm2-tools` workflow for enrolling an AK, capturing and verifying quotes, replaying event logs, sealing/unsealing data to a PCR policy, and building a golden-value baseline for fleet attestation.

## When to Use

- Establishing that endpoints/servers booted a known-good firmware and kernel before granting access (Zero Trust device posture).
- Detecting boot-chain tampering (bootkits, unauthorized firmware/kernel changes) via PCR drift from a baseline.
- Verifying measured-boot integrity after a Secure Boot or firmware incident.
- Sealing secrets (disk keys, credentials) to a measured-boot state so they only release on a trusted boot.
- Building or auditing a remote-attestation service (e.g., Keylime, custom verifier).

## Prerequisites

- A system with a TPM 2.0 device and the resource manager:
  ```bash
  sudo apt install tpm2-tools tpm2-abrmd        # Debian/Ubuntu
  sudo dnf install tpm2-tools tpm2-abrmd        # Fedora/RHEL
  ```
- Access to the TPM (`/dev/tpm0` / `/dev/tpmrm0`) and the kernel measurement log at `/sys/kernel/security/tpm0/binary_bios_measurements`.
- Root for reading some sysfs entries and for NV/AK operations.
- For remote attestation: a verifier host and a transport for the quote/nonce exchange.

## Objectives

- Read and interpret PCR banks and their TCG-assigned meanings.
- Verify the TPM event log reproduces live PCR values (event-log replay).
- Create an Attestation Key and produce a nonce-bound signed quote.
- Independently verify the quote signature and PCR digest on a verifier.
- Establish golden PCR baselines and detect drift across a fleet.
- Optionally seal/unseal a secret to a measured-boot PCR policy.

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Relevance |
|--------------|----------------|-----------|
| T1542 | Pre-OS Boot | Measured boot detects pre-OS tampering this technique relies on. |
| T1542.001 | Pre-OS Boot: System Firmware | PCR 0–7 drift reveals unauthorized firmware modification. |
| T1542.003 | Pre-OS Boot: Bootkit | Bootloader/kernel measurements (PCR 8–10) expose bootkit changes. |
| T1014 | Rootkit | IMA measurements (PCR 10) and quote verification surface concealed tampering. |
| T1601.001 | Modify System Image: Patch System Image | Attestation against golden values flags unauthorized image patches. |

## Workflow

### 1. Confirm the TPM is present and read its properties
```bash
tpm2_getcap properties-fixed | grep -i manufacturer
tpm2_getcap pcrs                 # list supported PCR banks (sha1, sha256, ...)
```

### 2. Read current PCR values
PCR 7 = Secure Boot policy; PCR 0–7 = firmware; PCR 8–9 = bootloader/kernel; PCR 10 = IMA.
```bash
tpm2_pcrread sha256                       # all sha256 PCRs
tpm2_pcrread sha256:0,1,2,3,4,5,6,7       # firmware + Secure Boot policy
tpm2_pcrread sha256:7                      # Secure Boot policy only
```

### 3. Replay the TPM event log against live PCRs
Confirm the recorded log reproduces the current PCR values (authenticity check).
```bash
tpm2_eventlog /sys/kernel/security/tpm0/binary_bios_measurements > eventlog.yaml
# The YAML includes a "pcrs" section with the calculated values — compare to step 2.
# Any mismatch means the event log and the live PCRs disagree (tampering or stale log).
```

### 4. Create a primary key and an Attestation Key (AK)
The AK signs quotes; its public part is shared with the verifier out-of-band.
```bash
tpm2_createprimary -C e -g sha256 -G rsa -c primary.ctx
tpm2_create -C primary.ctx -G rsa -u ak.pub -r ak.priv \
  -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|sign'
tpm2_load -C primary.ctx -u ak.pub -r ak.priv -c ak.ctx
tpm2_readpublic -c ak.ctx -o ak.pem -f pem      # export AK public key for the verifier
```

### 5. Produce a nonce-bound quote (attestor side)
The verifier supplies a fresh random nonce to defeat replay.
```bash
NONCE=$(openssl rand -hex 20)
tpm2_quote -c ak.ctx -l sha256:0,1,2,3,4,5,6,7,8,9 \
  -q "$NONCE" -m quote.msg -s quote.sig -o quote.pcrs -g sha256
# Send quote.msg, quote.sig, quote.pcrs (and the nonce) to the verifier.
```

### 6. Verify the quote (verifier side)
Independently validate the signature, nonce, and PCR digest with the AK public key.
```bash
tpm2_checkquote -u ak.pem -m quote.msg -s quote.sig -f quote.pcrs \
  -q "$NONCE" -g sha256
# Exit 0 + matching PCR digest == authentic, fresh, untampered quote.
```

### 7. Build and compare against a golden baseline
Compare attested PCRs to known-good values captured from a trusted reference build.
```bash
# Capture golden values on a trusted reference machine:
tpm2_pcrread sha256:0,7 > golden_pcrs.txt
# On each attested host, diff the quote's PCR section against golden_pcrs.txt.
diff <(grep -A8 'sha256' quote.pcrs) golden_pcrs.txt
```

### 8. Seal a secret to a measured-boot policy (optional)
Bind a secret so the TPM only releases it when PCRs match the trusted state.
```bash
tpm2_createpolicy --policy-pcr -l sha256:7 -L pcr7.policy -f pcr7.dat
echo -n "diskkey" | tpm2_create -C primary.ctx -L pcr7.policy \
  -i - -u sealed.pub -r sealed.priv
tpm2_load -C primary.ctx -u sealed.pub -r sealed.priv -c sealed.ctx
# Unseal succeeds only while PCR 7 matches the sealed policy:
tpm2_unseal -c sealed.ctx -p pcr:sha256:7
```

### 9. Inspect IMA runtime measurements (PCR 10)
If IMA is enabled, the runtime measurement list extends PCR 10.
```bash
tpm2_pcrread sha256:10
head -20 /sys/kernel/security/ima/ascii_runtime_measurements
```

### 10. Run the bundled attestation helper
`agent.py` reads PCRs, replays the event log, optionally produces+verifies a quote, and diffs a baseline.
```bash
sudo python scripts/agent.py --pcrs 0,1,2,3,4,5,6,7 --baseline golden_pcrs.json --output attest.json
```

## Tools and Resources

| Tool | Purpose | Source |
|------|---------|--------|
| tpm2-tools | CLI for all TPM 2.0 operations | https://github.com/tpm2-software/tpm2-tools |
| tpm2-tss | TSS2 stack the tools build on | https://github.com/tpm2-software/tpm2-tss |
| Keylime | Scalable remote attestation framework | https://github.com/keylime/keylime |
| TCG PC Client Platform Firmware Profile | PCR usage specification | https://trustedcomputinggroup.org/ |
| Linux IMA docs | Integrity Measurement Architecture | https://sourceforge.net/p/linux-ima/wiki/Home/ |
| RFC 9683 | Remote integrity verification of TPM devices | https://datatracker.ietf.org/doc/html/rfc9683 |

## Validation Criteria

- [ ] TPM 2.0 presence and supported PCR banks confirmed.
- [ ] Current PCR values read for firmware and Secure Boot policy PCRs.
- [ ] Event log replayed and confirmed to reproduce live PCR values.
- [ ] Attestation Key created and its public key exported to the verifier.
- [ ] Nonce-bound quote produced and independently verified with `tpm2_checkquote`.
- [ ] Attested PCRs compared against a golden baseline; drift flagged.
- [ ] (Optional) Secret sealed/unsealed against a PCR policy successfully.
- [ ] IMA runtime measurements reviewed where enabled.
- [ ] Results documented per host with pass/fail and any drift evidence.
