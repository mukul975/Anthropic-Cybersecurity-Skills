---
name: detecting-deepfake-audio-in-vishing-attacks
description: 'Detects AI-generated deepfake audio used in voice phishing (vishing)
  attacks by extracting spectral features (MFCC, spectral centroid, spectral contrast,
  zero-crossing rate) and classifying samples with machine learning models. Supports
  batch analysis of audio files, generates confidence scores, and produces forensic
  reports. Activates for requests involving deepfake voice detection, vishing investigation,
  AI-generated speech analysis, voice cloning detection, or audio authenticity verification.

  '
domain: cybersecurity
subdomain: social-engineering-defense
tags:
- deepfake-detection
- vishing
- audio-forensics
- MFCC
- spectral-analysis
- voice-cloning
version: 1.0.0
author: mukul975
license: Apache-2.0
atlas_techniques:
- AML.T0088
- AML.T0043
- AML.T0018
- AML.T0052
nist_ai_rmf:
- MEASURE-2.7
- GOVERN-6.2
- MAP-5.2
- MEASURE-2.5
- MAP-5.1
d3fend_techniques:
- Sender Reputation Analysis
- Content Validation
- Message Analysis
- User Behavior Analysis
- Identifier Analysis
nist_csf:
- PR.AT-01
- DE.CM-09
- RS.CO-02
mitre_attack:
- T1078
- T1190
- T1059
- T1566
- T1598
---

# Detecting Deepfake Audio in Vishing Attacks

## When to Use

- A suspected vishing call used an AI-cloned executive voice to authorize a wire transfer
- Security operations received a voicemail that sounds like the CEO but the tone seems off
- Incident response needs to determine whether a recorded phone call contains synthetic speech
- Fraud investigation requires forensic proof that audio was AI-generated
- Red team exercises use voice cloning and blue team needs detection capability

**Do not use** for text-based phishing (email/SMS); use email header analysis or URL detonation tools instead.

## Prerequisites

- Python 3.9+ with librosa, numpy, scikit-learn, and scipy installed
- Audio samples in WAV, MP3, or FLAC format (mono or stereo, any sample rate)
- Reference corpus of known genuine voice samples for the targeted individual (optional but improves accuracy)
- FFmpeg installed for audio format conversion (librosa dependency)
- Minimum 3 seconds of audio for reliable feature extraction

## Workflow

### Step 1: Audio Preprocessing

Normalize and prepare audio samples for feature extraction:

```python
import librosa
import numpy as np

# Load audio, resample to 16kHz mono
y, sr = librosa.load("suspect_call.wav", sr=16000, mono=True)

# Trim silence from beginning and end
y_trimmed, _ = librosa.effects.trim(y, top_db=25)

# Normalize amplitude to [-1, 1]
y_norm = y_trimmed / np.max(np.abs(y_trimmed))
```

Audio preprocessing ensures consistent feature extraction across different recording conditions, microphones, and codec artifacts.

### Step 2: Extract Spectral Features

Extract the feature set that distinguishes real from synthetic speech:

**Mel-Frequency Cepstral Coefficients (MFCCs):**
```python
# Extract 20 MFCCs + delta and delta-delta
mfccs = librosa.feature.mfcc(y=y_norm, sr=sr, n_mfcc=20)
mfcc_delta = librosa.feature.delta(mfccs)
mfcc_delta2 = librosa.feature.delta(mfccs, order=2)
```

MFCCs capture the spectral envelope of speech, representing how the vocal tract shapes sound. Deepfake audio often shows unnatural smoothness in higher-order MFCCs because neural vocoders approximate but do not perfectly replicate the acoustic resonance of a physical vocal tract.

**Spectral Features:**
```python
spectral_centroid = librosa.feature.spectral_centroid(y=y_norm, sr=sr)
spectral_bandwidth = librosa.feature.spectral_bandwidth(y=y_norm, sr=sr)
spectral_contrast = librosa.feature.spectral_contrast(y=y_norm, sr=sr)
spectral_rolloff = librosa.feature.spectral_rolloff(y=y_norm, sr=sr)
zero_crossing_rate = librosa.feature.zero_crossing_rate(y_norm)
```

**Key indicators of deepfake audio:**
- Reduced spectral contrast in the 4-8 kHz range (vocoders compress high-frequency detail)
- Abnormally consistent spectral centroid over time (real speech has natural variation)
- Lower zero-crossing rate variance (synthetic speech lacks micro-perturbations)
- Missing or attenuated formant transitions during consonant-vowel boundaries

### Step 3: Build Feature Vector and Classify

Aggregate frame-level features into a fixed-length vector and classify:

```python
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import cross_val_score

def build_feature_vector(y, sr):
    features = []
    mfccs = librosa.feature.mfcc(y=y, sr=sr, n_mfcc=20)
    for coeff in mfccs:
        features.extend([np.mean(coeff), np.std(coeff), np.min(coeff), np.max(coeff)])
    for feat_fn in [librosa.feature.spectral_centroid,
                    librosa.feature.spectral_bandwidth,
                    librosa.feature.spectral_rolloff,
                    librosa.feature.zero_crossing_rate]:
        feat = feat_fn(y=y, sr=sr) if feat_fn != librosa.feature.zero_crossing_rate else feat_fn(y)
        features.extend([np.mean(feat), np.std(feat), np.min(feat), np.max(feat)])
    contrast = librosa.feature.spectral_contrast(y=y, sr=sr)
    for band in contrast:
        features.extend([np.mean(band), np.std(band)])
    return np.array(features)
```

Classification uses an ensemble approach: Random Forest for robustness and Gradient Boosting for accuracy, with a voting mechanism to reduce false positives.

### Step 4: Temporal Artifact Analysis

Examine time-domain artifacts that neural vocoders leave behind:

```python
# Pitch stability analysis - deepfakes often have unnaturally stable F0
f0, voiced_flag, voiced_probs = librosa.pyin(y_norm, fmin=50, fmax=500, sr=sr)
f0_clean = f0[~np.isnan(f0)]
pitch_std = np.std(f0_clean) if len(f0_clean) > 0 else 0
pitch_jitter = np.mean(np.abs(np.diff(f0_clean))) if len(f0_clean) > 1 else 0
```

Real human speech exhibits natural pitch jitter (micro-variations in fundamental frequency) and shimmer (amplitude perturbations). Deepfake audio generated by Tacotron 2, VALL-E, or ElevenLabs typically shows reduced jitter and shimmer compared to genuine speech.

### Step 5: Spectrogram Visual Inspection

Generate spectrograms for manual forensic review:

```python
import librosa.display
import matplotlib.pyplot as plt

fig, axes = plt.subplots(2, 2, figsize=(14, 10))
librosa.display.specshow(librosa.power_to_db(librosa.feature.melspectrogram(y=y_norm, sr=sr)),
                         sr=sr, ax=axes[0, 0], x_axis='time', y_axis='mel')
axes[0, 0].set_title('Mel Spectrogram')
librosa.display.specshow(mfccs, sr=sr, ax=axes[0, 1], x_axis='time')
axes[0, 1].set_title('MFCCs')
```

Visual inspection reveals banding artifacts in mel spectrograms, unnatural energy cutoffs above the vocoder's frequency ceiling, and periodic noise patterns in the high-frequency range that are characteristic of neural speech synthesis.

### Step 6: Generate Forensic Report

Compile findings into an actionable report:

```
DEEPFAKE AUDIO ANALYSIS REPORT
================================
File:              suspect_executive_call.wav
Duration:          47.3 seconds
Sample Rate:       16000 Hz
Analysis Date:     2026-03-19

CLASSIFICATION RESULT
Verdict:           LIKELY DEEPFAKE (confidence: 94.2%)
Ensemble Score:    RF=0.91, GBT=0.97, Avg=0.94

FEATURE ANOMALIES DETECTED
- MFCC variance in coefficients 13-20: 62% below genuine baseline
- Spectral contrast (4-8 kHz): 0.23 (genuine avg: 0.41)
- Pitch jitter: 0.8 Hz (genuine avg: 2.4 Hz)
- Zero-crossing rate std: 0.003 (genuine avg: 0.011)

SPECTROGRAM ARTIFACTS
- Energy cutoff above 7.8 kHz (consistent with neural vocoder ceiling)
- Banding pattern at 50ms intervals in mel spectrogram
- Missing formant transitions at 12.4s, 23.1s, 35.7s timestamps

RECOMMENDATION
High confidence of AI-generated audio. Recommend out-of-band
verification with the purported speaker. Preserve original audio
file with chain of custody documentation for potential legal action.
```

## Key Concepts

| Term | Definition |
|------|------------|
| **MFCC** | Mel-Frequency Cepstral Coefficients; representation of the short-term power spectrum on a mel (perceptual) frequency scale |
| **Spectral Centroid** | Weighted mean of frequencies present in the signal; indicates perceived brightness of a sound |
| **Spectral Contrast** | Difference in amplitude between peaks and valleys in the spectrum across frequency sub-bands |
| **Vocoder** | Signal processing component that synthesizes audio waveforms from acoustic features; used in TTS and voice cloning |
| **Pitch Jitter** | Cycle-to-cycle variation in fundamental frequency; natural in human speech, reduced in synthetic speech |
| **Vishing** | Voice phishing; social engineering attack conducted via phone calls, increasingly using AI-cloned voices |
| **Formant** | Resonant frequencies of the vocal tract that define vowel sounds; transitions between formants are difficult for AI to replicate perfectly |

## Tools & Systems

- **librosa**: Python library for audio analysis providing MFCC, spectral feature extraction, and spectrogram generation
- **scikit-learn**: Machine learning library used for Random Forest and Gradient Boosting classification
- **Resemblyzer**: Speaker embedding library for comparing voice identity between known genuine and suspect samples
- **Speechbrain**: Deep learning toolkit for speech processing with pretrained deepfake detection models
- **Praat**: Phonetics software for detailed pitch, jitter, and shimmer analysis of speech samples
- **FFmpeg**: Audio format conversion and preprocessing utility required by librosa

## Common Scenarios

### Scenario: Executive Impersonation Wire Transfer Fraud

**Context**: CFO receives a phone call appearing to be from the CEO requesting an urgent wire transfer of $2.3M. The call came from an unknown number but the voice sounded identical to the CEO. IT security was able to obtain a recording of the call from the phone system.

**Approach**:
1. Extract the audio from the phone system recording and convert to WAV at 16kHz
2. Run MFCC and spectral feature extraction on the suspect audio
3. Compare against known genuine CEO voice samples from recorded meetings
4. Analyze pitch jitter and shimmer against human speech baselines
5. Classify using the trained ensemble model and generate confidence score
6. Produce forensic report with spectrogram evidence for legal/compliance

**Pitfalls**:
- Phone codec compression (G.711, AMR) degrades audio quality and can mask deepfake artifacts
- Short audio clips (under 3 seconds) produce unreliable feature statistics
- Background noise from the call environment can reduce classification accuracy
- Highly sophisticated voice cloning (e.g., fine-tuned VALL-E with 30+ minutes of training data) may evade basic feature analysis
- Genuine speech transmitted through VoIP may exhibit spectral artifacts similar to deepfakes
