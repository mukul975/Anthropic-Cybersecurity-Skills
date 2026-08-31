---
name: auditing-foundry-smart-contract-security
description: 'Pre-deployment security audit of Solidity smart contracts in a Foundry project. Combines static analysis (Slither, Aderyn), symbolic execution (Mythril), and property-based testing (forge fuzz + invariant tests with handlers) to catch reentrancy, access-control, oracle/price manipulation, and arithmetic bugs BEFORE deploying to an EVM chain. Also enforces key hygiene (no plaintext private keys, encrypted cast keystore) and a secure deploy workflow. Use when writing, reviewing, testing, or deploying Solidity/Foundry contracts, building a dApp, or working with forge/cast/anvil, MetaMask, or Web3/DeFi code. Do not use for standalone Slither/Mythril static and symbolic analysis outside a Foundry project - use analyzing-ethereum-smart-contract-vulnerabilities.'
domain: cybersecurity
subdomain: blockchain-security
tags:
  - solidity
  - foundry
  - forge
  - smart-contract
  - slither
  - aderyn
  - mythril
  - reentrancy
  - defi
  - web3
  - invariant-testing
  - audit
version: "1.0"
author: devredious
license: Apache-2.0
based_on: mukul975/analyzing-ethereum-smart-contract-vulnerabilities
swc_registry: https://swcregistry.io/
mitre_attack:
  - T1190
  - T1059
---

# Auditing Foundry Smart Contract Security

## Overview

Deployed smart contracts are **immutable** and custody **real funds**, so a bug
shipped to mainnet cannot be patched — it can only be exploited. Most catastrophic
DeFi losses come from a small set of recurring classes: reentrancy, broken access
control, oracle/price manipulation, and unchecked arithmetic or external calls.

This skill runs a **defense-in-depth, pre-deployment audit** of a Foundry project,
layering four independent techniques that each catch what the others miss:

1. **Static analysis** — `slither` (90+ detectors) and `aderyn` (Cyfrin, Rust) scan
   the AST/IR in seconds for known anti-patterns.
2. **Symbolic execution** — `mythril` (optional, slow) explores execution paths and
   SMT-solves for deep arithmetic/reentrancy bugs.
3. **Property-based testing** — `forge test` with **fuzzing** (`testFuzz_*`) and
   **invariant tests** (`invariant_*` + handler contracts with ghost variables)
   proves protocol-level properties hold across millions of random sequences.
4. **Manual review + key hygiene** — a structured checklist (see
   `references/vulnerability-checklist.md`) and a secrets/keystore audit so no
   private key ever lives in plaintext and deployment goes through an encrypted
   `cast` keystore (see `references/secure-deployment-and-keys.md`).

The skill is **dev-side and pre-deployment** — it is run by the engineer building
the contract, not by a SOC after an incident. Findings gate the deploy: any
high/critical static finding, failing test, leaked key, or low coverage = **FAIL**.

## When to Use

- Before deploying any Solidity contract to a testnet or mainnet EVM chain.
- When writing or reviewing a Foundry project (`foundry.toml`, `src/`, `test/`, `script/`).
- When a contract handles value: tokens (ERC-20/721/1155), vaults, staking, AMMs, bridges, governance.
- When adding fuzz or invariant tests, or when coverage of value-moving functions is unknown.
- When wiring deployment scripts — to verify keys are in an encrypted keystore, not `.env` plaintext.
- When integrating a price oracle, external call, `delegatecall`, or upgradeable proxy.
- When triaging a Slither/Aderyn report and needing to separate real bugs from false positives.

## Prerequisites

- **Foundry** installed (`forge`, `cast`, `anvil`): `curl -L https://foundry.paradigm.xyz | bash && foundryup`
- **Slither** + solc: `pip install slither-analyzer` and `solc-select install <ver> && solc-select use <ver>`
- **Aderyn** (recommended): `cargo install aderyn` (or `npm i -g @cyfrin/aderyn`)
- **Mythril** (optional, slow symbolic exec): `pip install mythril`
- **gitleaks** (key-leak scan): see the companion `implementing-secret-scanning-with-gitleaks` skill
- A Foundry project that **compiles** (`forge build` succeeds) — analyzers need build artifacts.
- Solidity ^0.8.x is assumed (built-in overflow checks); pre-0.8 contracts need extra SafeMath review.

> Install the Python tools in a virtualenv (recommended on externally-managed distros). Never run
> analysis against untrusted contract source on a machine with funded wallets unlocked.

## Steps

### Step 1: Build and sanity-check the project

```bash
forge build                    # analyzers require fresh artifacts
forge fmt --check              # style gate (optional)
cat foundry.toml               # note solc version, optimizer, remappings, evm_version
```

### Step 2: Static analysis (fast, run every time)

```bash
# Slither — full project (uses foundry.toml + remappings automatically)
slither . --json slither-report.json

# Aderyn — Cyfrin Rust analyzer, complementary detectors
aderyn . -o aderyn-report.json
```

Or run the bundled orchestrator that runs both, deduplicates, and gates the result:

```bash
python3 scripts/agent.py --project . --output audit-report.json
```

### Step 3: Symbolic execution on critical contracts (optional, slow)

```bash
# Only on the highest-value contract(s) — Mythril is path-explosive
myth analyze src/Vault.sol --solc-json mythril.config.json --execution-timeout 300 -o json
# or: python3 scripts/agent.py --project . --mythril src/Vault.sol
```

### Step 4: Property-based testing — fuzz + invariants

```bash
forge test -vvv                                  # unit + fuzz tests
forge coverage --report summary                  # coverage of value-moving code
forge test --match-test invariant_ -vvv          # invariant suite (handler-based)
```

Every value-moving contract should have **invariant tests with a handler** (bounded
inputs, ghost variables, `targetContract(handler)`) — not just unit tests. See
`references/api-reference.md` for the handler pattern, and write a
`test_RevertWhen_*` (with `vm.expectRevert`) for each access-control guard.

### Step 5: Manual review against the checklist

Walk `references/vulnerability-checklist.md` for every contract: reentrancy
(checks-effects-interactions / `nonReentrant`), access control, oracle manipulation,
`delegatecall`/proxy storage layout, unchecked return values, `tx.origin`, weak
randomness, DoS, front-running/MEV, and ERC-specific pitfalls (approve race,
fee-on-transfer, rebasing).

### Step 6: Key hygiene & secure deploy

```bash
gitleaks detect --no-banner            # no private keys / mnemonics / .env committed
git ls-files | grep -E '\.env$|keystore' && echo "WARN: secrets tracked by git"

# Import the deploy key ONCE into an encrypted keystore — never a plaintext PRIVATE_KEY env
cast wallet import deployer --interactive

# Deploy via the keystore account (testnet first), simulate before --broadcast
forge script script/Deploy.s.sol --account deployer --rpc-url <testnet> --broadcast --verify
```

See `references/secure-deployment-and-keys.md` for the full hardening rules
(MetaMask hygiene, hardware wallet for mainnet, RPC trust, post-deploy verification).

### Step 7: Triage and report

Combine Slither + Aderyn + Mythril + test results, deduplicate by (file, line),
drop confirmed false positives, rank by exploitability × financial impact, and map
each to its SWC id. The orchestrator emits `audit-report.json` with a PASS/FAIL gate.

## Expected Output

A JSON audit report listing findings with **SWC identifiers**, severity, tool source,
affected contract/function/line, and remediation; plus the test/coverage summary and a
single **PASS / FAIL** deploy gate. FAIL on any high/critical static finding, failing
test, leaked secret, or coverage below the configured threshold on value-moving code.
