# Standards & Controls: Bypassing SSL Pinning in Flutter Apps

The control under test is secure transport with endpoint identity verification
(certificate pinning). Defeating it during an authorized assessment demonstrates
whether the app's transport security holds up against an on-device attacker.

## Mapped controls

- **OWASP MASVS-NETWORK-1 & -2** — secure network communication and endpoint
  identity verification. A successful pinning bypass on a production build without
  additional integrity controls is also an **OWASP MASVS-RESILIENCE** weakness
  (client-side protections can be removed at runtime).
- **NIST SP 800-52** — guidelines for TLS deployment; pinning is a defense-in-depth
  measure on top of standard TLS validation.
- **NIST CSF 2.0** — `PR.DS-01` / `PR.DS-02` (data-at-rest / data-in-transit
  protection) and `ID.RA-01` (vulnerability identification).
- **MITRE ATT&CK** — `T1557` (Adversary-in-the-Middle) and `T1040` (Network
  Sniffing): the interception technique class exercised, here for authorized
  testing rather than adversary emulation.

## Reporting note

Report the bypass as a finding only when it exposes a concrete risk — e.g. the app
transmits sensitive data that becomes readable, or lacks compensating integrity
controls (attestation, secondary encryption). A pinning bypass on a jailbroken/
rooted device is expected; the severity comes from what it reveals downstream.
