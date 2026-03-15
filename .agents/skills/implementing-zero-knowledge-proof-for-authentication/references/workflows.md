# Workflows - Zero-Knowledge Proof for Authentication

## Workflow 1: Schnorr Interactive ZKP

```
Prover (knows secret x)              Verifier (knows y = g^x mod p)
      |                                      |
      |-- Commitment: t = g^r mod p -------->|
      |                                      |
      |<-- Challenge: c (random) ------------|
      |                                      |
      |-- Response: s = (r + c*x) mod q ---->|
      |                                      |
      |                              [Verify: g^s == t * y^c mod p]
      |                              [Accept or Reject]
```

## Workflow 2: Non-Interactive ZKP (Fiat-Shamir)

```
Prover:
  1. Choose random r
  2. Compute t = g^r mod p
  3. Compute c = H(g || y || t)  (Fiat-Shamir)
  4. Compute s = (r + c*x) mod q
  5. Send proof (t, s) to verifier

Verifier:
  1. Compute c = H(g || y || t)
  2. Check g^s == t * y^c mod p
```

## Workflow 3: Registration and Authentication

```
[Registration]:
  User --> [Choose password/secret x]
       --> [Compute y = g^x mod p]
       --> [Send y to server]
  Server --> [Store y (public key only)]

[Authentication]:
  User <--> Server: [Run Schnorr protocol]
  Server: [Verifies proof without learning x]
  Server: [Grants session token on success]
```
