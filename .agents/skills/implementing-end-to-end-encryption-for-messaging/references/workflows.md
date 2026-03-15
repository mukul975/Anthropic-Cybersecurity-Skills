# Workflows - End-to-End Encryption for Messaging

## Workflow 1: X3DH Key Agreement

```
Alice (initiator)                 Server                  Bob (responder)
  |                                 |                         |
  |                                 |<-- Register:            |
  |                                 |    Identity Key (IK_B)  |
  |                                 |    Signed PreKey (SPK_B)|
  |                                 |    One-Time PreKeys     |
  |                                 |                         |
  |-- Fetch Bob's Keys ----------->|                         |
  |<-- IK_B, SPK_B, OPK_B --------|                         |
  |                                 |                         |
  [Compute shared secret]:                                    |
  DH1 = DH(IK_A, SPK_B)                                     |
  DH2 = DH(EK_A, IK_B)                                      |
  DH3 = DH(EK_A, SPK_B)                                     |
  DH4 = DH(EK_A, OPK_B)                                     |
  SK = HKDF(DH1 || DH2 || DH3 || DH4)                      |
  |                                 |                         |
  |-- Send Initial Message ------->|-- Forward to Bob ------>|
  |   (IK_A, EK_A, OPK_id, msg)   |                         |
  |                                 |   [Bob computes same SK]|
```

## Workflow 2: Double Ratchet (Sending)

```
[Message to Send]
      |
[Check: Do we have recipient's new DH public key?]
  YES --> [DH Ratchet Step]
          - Generate new DH key pair
          - Compute DH shared secret
          - Derive new root key + sending chain key via HKDF
  NO  --> [Continue with current sending chain]
      |
[Symmetric Ratchet: Derive message key from sending chain]
(chain_key, message_key) = HMAC(chain_key, constants)
      |
[Encrypt message with AES-256-GCM using message_key]
      |
[Include header: DH public key, previous chain length, message number]
      |
[Delete message_key from memory]
```

## Workflow 3: Double Ratchet (Receiving)

```
[Received Encrypted Message + Header]
      |
[Check DH public key in header]
  [New key?]
    YES --> [DH Ratchet Step]
            - Compute DH shared secret
            - Derive new root key + receiving chain key
    NO  --> [Use current receiving chain]
      |
[Symmetric Ratchet: Derive message key]
      |
[Decrypt message with AES-256-GCM]
      |
[Verify authentication tag]
  FAIL --> Reject message
  PASS --> Return plaintext
      |
[Delete message_key from memory]
```

## Workflow 4: Session Lifecycle

```
[Initial Contact] --> [X3DH Key Exchange]
                            |
                      [Initialize Double Ratchet]
                            |
                      [Exchange Messages]
                      (DH ratchet + symmetric ratchet)
                            |
                      [Periodic DH Ratchet]
                      (every N messages or on reply)
                            |
                      [Session End / Archive]
```
