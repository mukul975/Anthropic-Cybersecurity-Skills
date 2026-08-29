---
name: detecting-data-and-model-poisoning
description: Identify poisoned training data and backdoored ML models across the pipeline using IBM's Adversarial Robustness Toolbox (activation clustering, spectral signatures, trigger reconstruction), Cleanlab for label-quality issues, and supply-chain checks like weight-hash verification and safetensors enforcement. Use when training or deploying on third-party/user-contributed data or downloaded checkpoints, during ML supply-chain reviews, or when investigating model misbehavior tied to specific inputs (suspected backdoor trigger). Do not use for detecting inference-API model stealing, inversion, or membership-inference exfiltration - use detecting-model-extraction-attacks.
domain: cybersecurity
subdomain: ai-security
tags:
- ai-security
- data-poisoning
- model-backdoor
- ml-supply-chain
- adversarial-robustness-toolbox
- activation-clustering
- spectral-signatures
- model-integrity
version: '1.0'
author: mahipal
license: Apache-2.0
nist_ai_rmf:
- MEASURE-2.7
atlas_techniques:
- AML.T0020
- AML.T0018
---
# Detecting Data and Model Poisoning

> **Authorized-use-only notice:** This skill includes routines that craft poisoned samples and backdoor triggers for *defensive validation*. Generate and use poisoned data and backdoored models only in isolated test environments you control. Never deploy a backdoored model or distribute poisoned datasets.

## Overview

Data poisoning and model backdooring attack the *integrity* of an ML system at training time rather than at inference. In **data poisoning** (MITRE ATLAS **AML.T0020 Poison Training Data**), an adversary injects manipulated samples into the training, fine-tuning, or RAG corpus so the resulting model misbehaves — degraded accuracy, targeted misclassification, or an attacker-chosen bias. In **model backdooring** (MITRE ATLAS **AML.T0018 Backdoor ML Model**), the model behaves normally on clean inputs but produces an attacker-chosen output whenever a hidden *trigger* (a pixel patch, a rare token, a phrase) is present. Both are amplified by **ML supply-chain compromise (AML.T0010)**: poisoned public datasets, trojaned pre-trained weights downloaded from a hub, or a malicious model serialization. This is OWASP **LLM04:2025 Data and Model Poisoning**.

Detection spans the pipeline. On the *data* side: provenance and integrity checks, statistical outlier and label-flip detection, and de-duplication of suspiciously near-identical samples. On the *model* side: activation-clustering and spectral-signature analysis (which exploit the fact that poisoned samples activate the network differently than clean ones) and trigger reconstruction. On the *supply-chain* side: verifying weights hashes/signatures and refusing unsafe serialization formats (pickle-based `.bin`/`.pt`) in favor of safetensors. This skill implements all three using IBM's **Adversarial Robustness Toolbox (ART)**, **Cleanlab** for label-quality issues, and integrity tooling.

## When to Use

- Before training/fine-tuning on third-party or user-contributed data.
- Before deploying a model built on a downloaded pre-trained checkpoint.
- During an ML supply-chain security review.
- When investigating anomalous model behavior tied to specific inputs (possible backdoor trigger).
- As a CI/CD gate that scans datasets and model artifacts before they enter the pipeline.

## Prerequisites

- Python 3.10+ and a virtual environment.
- Install the tooling:

```bash
python -m venv .venv && source .venv/bin/activate

# IBM Adversarial Robustness Toolbox — poisoning detection defenses
pip install adversarial-robustness-toolbox

# Cleanlab — label/data quality issue detection
pip install cleanlab

# Modeling + safe serialization + hashing
pip install numpy scikit-learn safetensors

# (Choose one framework backend ART can wrap)
pip install tensorflow   # or: pip install torch
```

## Objectives

- Verify dataset and model-weight provenance and integrity (hashes/signatures, safe formats).
- Detect label-quality issues and outliers in training data with Cleanlab.
- Detect poisoned samples in a trained model using ART activation clustering.
- Confirm findings with ART spectral-signature analysis.
- Probe a suspect model for backdoor triggers and quantify trigger-induced misclassification.
- Produce a poisoning-assessment report mapped to ATLAS AML.T0020 / AML.T0018.

## MITRE ATT&CK Mapping

| ID | Official Name | Relevance |
|----|---------------|-----------|
| AML.T0020 | Poison Training Data | Injection of manipulated samples into the training corpus |
| AML.T0018 | Backdoor ML Model | Trigger-activated hidden behavior in the trained model |
| AML.T0010 | ML Supply Chain Compromise | Poisoned public datasets / trojaned downloaded weights |
| AML.T0024 | Exfiltration via ML Inference API | Some poisoning aims to leak data via the model's responses |

## Workflow

### 1. Verify data and model provenance/integrity
Refuse artifacts whose hash/signature you cannot verify, and prefer safetensors over pickle-based formats (pickle can execute code on load).

```bash
# Verify a downloaded checkpoint against a published SHA-256
sha256sum model.safetensors
# compare to the hub-published digest

# Flag unsafe pickle-based weights in a directory
find ./models -type f \( -name "*.bin" -o -name "*.pt" -o -name "*.pkl" -o -name "*.ckpt" \)
```

```python
# safe_load.py — load weights without executing pickle
from safetensors.numpy import load_file
weights = load_file("model.safetensors")   # no arbitrary code execution
```

### 2. Detect label/data-quality issues with Cleanlab
Cleanlab finds mislabeled, outlier, and near-duplicate samples — common signatures of label-flip poisoning.

```python
# cleanlab_scan.py
import numpy as np
from cleanlab.filter import find_label_issues

# pred_probs: out-of-sample predicted probabilities (n_samples x n_classes)
# labels: given integer labels (n_samples,)
def scan(labels: np.ndarray, pred_probs: np.ndarray):
    issues = find_label_issues(
        labels=labels, pred_probs=pred_probs,
        return_indices_ranked_by="self_confidence",
    )
    print(f"[*] {len(issues)} suspected label issues (potential poisoning)")
    return issues
```

### 3. Detect poisoned samples via ART activation clustering
ActivationDefence clusters per-class activations; a class whose activations split into two distinct clusters indicates injected (poisoned) samples.

```python
# activation_defence.py
import numpy as np
from art.estimators.classification import KerasClassifier
from art.defences.detector.poison import ActivationDefence

def detect(model, x_train, y_train):
    classifier = KerasClassifier(model=model)          # wrap your trained model
    defence = ActivationDefence(classifier, x_train, y_train)
    report, is_clean_lst = defence.detect_poison(
        nb_clusters=2, nb_dims=10, reduce="PCA"
    )
    # is_clean_lst[i] == 0 marks a suspected poisoned sample
    poisoned_idx = np.where(np.array(is_clean_lst) == 0)[0]
    print(f"[*] activation clustering flagged {len(poisoned_idx)} samples")
    return poisoned_idx, report
```

### 4. Confirm with ART spectral signatures
Spectral signatures use the covariance spectrum of feature representations to surface poisoned samples — a strong second signal.

```python
# spectral.py
import numpy as np
from art.estimators.classification import KerasClassifier
from art.defences.detector.poison import SpectralSignatureDefense

def detect(model, x_train, y_train, nb_classes):
    classifier = KerasClassifier(model=model)
    defence = SpectralSignatureDefense(
        classifier, x_train, y_train,
        expected_pp_poison=0.05, batch_size=128, eps_multiplier=1.5,
    )
    report, is_clean_lst = defence.detect_poison()
    poisoned_idx = np.where(np.array(is_clean_lst) == 0)[0]
    print(f"[*] spectral signatures flagged {len(poisoned_idx)} samples")
    return poisoned_idx, report
```

### 5. Probe the model for backdoor triggers
Test whether a candidate trigger flips predictions to an attacker target class far above the clean baseline.

```python
# trigger_probe.py
import numpy as np

def test_trigger(model, x_clean, target_class, apply_trigger):
    """apply_trigger(x) stamps a candidate trigger (e.g. a corner pixel patch)."""
    clean_preds = model.predict(x_clean).argmax(axis=1)
    x_trig = np.stack([apply_trigger(x.copy()) for x in x_clean])
    trig_preds = model.predict(x_trig).argmax(axis=1)
    asr = float(np.mean(trig_preds == target_class))   # attack success rate
    base = float(np.mean(clean_preds == target_class))
    print(f"[*] target-class rate clean={base:.3f} triggered={asr:.3f}")
    return {"baseline": base, "trigger_success_rate": asr,
            "backdoor_suspected": asr - base > 0.5}
```

### 6. Quarantine, retrain, and report
Remove flagged samples (intersection of Cleanlab + ART signals is highest-confidence), retrain on the cleaned set, and re-test for the trigger. Document: artifact provenance, samples flagged by each method, trigger ASR before/after, and ATLAS mapping. Recommend dataset provenance controls, signed weights (safetensors + sigstore/cosign), and ongoing pipeline scanning.

## Tools and Resources

| Tool | Purpose | Source |
|------|---------|--------|
| Adversarial Robustness Toolbox | Activation clustering & spectral-signature poisoning defenses | https://github.com/Trusted-AI/adversarial-robustness-toolbox |
| Cleanlab | Label/data-quality issue detection | https://github.com/cleanlab/cleanlab |
| safetensors | Safe (non-pickle) weight serialization | https://github.com/huggingface/safetensors |
| OWASP LLM04:2025 | Data and Model Poisoning reference | https://genai.owasp.org/llmrisk/llm042025-data-and-model-poisoning/ |
| MITRE ATLAS | AI threat technique taxonomy | https://atlas.mitre.org/ |

## Detection Method Reference

| Layer | Method | Tool | Signal |
|-------|--------|------|--------|
| Supply chain | Hash/signature + safe format | sha256/safetensors | Tampered or unsafe artifact |
| Data | Label issues / outliers | Cleanlab | Mislabeled / injected samples |
| Model | Activation clustering | ART ActivationDefence | Per-class activation split |
| Model | Spectral signatures | ART SpectralSignatureDefense | Outlier covariance spectrum |
| Model | Trigger probing | custom | High trigger attack-success-rate |

## Validation Criteria

- [ ] Dataset and weight provenance/integrity verified (hashes, safe format)
- [ ] Unsafe pickle-based artifacts identified and avoided
- [ ] Cleanlab label-issue scan run and suspicious samples listed
- [ ] ART activation clustering executed with flagged sample indices
- [ ] ART spectral-signature analysis run as confirmation
- [ ] Backdoor trigger probe quantifies attack-success-rate vs. baseline
- [ ] Highest-confidence poisoned samples quarantined (multi-method overlap)
- [ ] Model retrained on cleaned data and re-tested for the trigger
- [ ] Findings mapped to MITRE ATLAS AML.T0020 / AML.T0018 and OWASP LLM04:2025
- [ ] Report delivered with remediation (provenance, signed weights, pipeline scanning)
