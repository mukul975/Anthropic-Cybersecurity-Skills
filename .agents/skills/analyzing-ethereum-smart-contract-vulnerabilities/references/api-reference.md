# API Reference: Analyzing Ethereum Smart Contract Vulnerabilities

## Slither CLI

```bash
# Basic analysis
slither contracts/

# JSON output
slither contracts/ --json slither-report.json

# Run specific detector only
slither contracts/ --detect reentrancy-eth,unprotected-upgrade

# List all detectors
slither --list-detectors

# Print contract summary
slither contracts/ --print human-summary

# Generate inheritance graph
slither contracts/ --print inheritance-graph
```

## Mythril CLI

```bash
# Analyze single contract
myth analyze contracts/Token.sol

# JSON output
myth analyze contracts/Token.sol -o json

# Set execution timeout
myth analyze contracts/Token.sol --execution-timeout 300

# Analyze deployed bytecode
myth analyze --address 0x1234... --rpc infura

# Increase analysis depth
myth analyze contracts/Token.sol --max-depth 50 --transaction-count 3
```

## Slither Detector Severity Levels

| Impact | Confidence | Example Detectors |
|--------|------------|-------------------|
| High | High | reentrancy-eth, suicidal, arbitrary-send-eth |
| High | Medium | controlled-delegatecall, reentrancy-no-eth |
| Medium | High | locked-ether, incorrect-equality |
| Medium | Medium | uninitialized-state, shadowing-state |
| Low | High | naming-convention, solc-version |
| Informational | High | pragma, dead-code |

## SWC Registry (Key Entries)

| SWC ID | Title | Tool Coverage |
|--------|-------|---------------|
| SWC-101 | Integer Overflow/Underflow | Mythril |
| SWC-104 | Unchecked Call Return | Slither + Mythril |
| SWC-106 | Unprotected SELFDESTRUCT | Slither + Mythril |
| SWC-107 | Reentrancy | Slither + Mythril |
| SWC-110 | Assert Violation | Mythril |
| SWC-112 | Delegatecall to Untrusted Callee | Slither |
| SWC-115 | tx.origin Authentication | Slither |
| SWC-116 | Block Timestamp Dependence | Mythril |
| SWC-120 | Weak Randomness | Slither |

## Installation

```bash
# Slither (requires solc)
pip install slither-analyzer
solc-select install 0.8.20
solc-select use 0.8.20

# Mythril
pip install mythril
```

## Slither JSON Output Structure

```json
{
  "success": true,
  "results": {
    "detectors": [{
      "check": "reentrancy-eth",
      "impact": "High",
      "confidence": "Medium",
      "description": "Reentrancy in Contract.withdraw()",
      "elements": [{"source_mapping": {"filename_short": "Contract.sol", "lines": [42, 43]}}]
    }]
  }
}
```

### References

- Slither: https://github.com/crytic/slither
- Mythril: https://github.com/Consensys/mythril
- SWC Registry: https://swcregistry.io/
- Solidity Security: https://docs.soliditylang.org/en/latest/security-considerations.html
