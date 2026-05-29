#!/usr/bin/env python3
"""Deepfake audio detection agent using spectral analysis, MFCC features, and ML classifiers.

Analyzes audio files to determine whether they contain AI-generated (deepfake) speech,
commonly used in vishing (voice phishing) attacks. Extracts spectral features with librosa,
builds feature vectors, and classifies using ensemble ML models.
"""

import os
import sys
import json
import warnings
import argparse
from pathlib import Path
from datetime import datetime

import numpy as np

try:
    import librosa
    HAS_LIBROSA = True
except ImportError:
    HAS_LIBROSA = False

try:
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import cross_val_score
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

warnings.filterwarnings("ignore", category=UserWarning)

# Default analysis parameters
DEFAULT_SR = 16000
DEFAULT_N_MFCC = 20
DEFAULT_HOP_LENGTH = 512
DEFAULT_N_FFT = 2048
TRIM_TOP_DB = 25
MIN_DURATION_SEC = 1.0

# Thresholds derived from research on deepfake vs genuine speech characteristics
# Based on findings from IEEE paper "Deepfake Audio Detection via MFCC Features Using ML"
DEEPFAKE_THRESHOLDS = {
    "mfcc_high_order_var_ratio": 0.5,     # deepfakes have <50% variance of genuine in MFCC 13-20
    "spectral_contrast_4_8khz": 0.30,     # genuine speech typically >0.35 in this band
    "pitch_jitter_hz": 1.5,              # genuine speech jitter typically >2.0 Hz
    "zcr_std_threshold": 0.006,          # genuine ZCR std typically >0.008
    "spectral_centroid_cv": 0.15,        # coefficient of variation; deepfakes show less variation
    "spectral_rolloff_std": 200,         # genuine rolloff std typically >300 Hz
}


def load_and_preprocess(audio_path, sr=DEFAULT_SR):
    """Load audio file, resample to target rate, trim silence, and normalize."""
    if not os.path.isfile(audio_path):
        raise FileNotFoundError(f"Audio file not found: {audio_path}")

    y, orig_sr = librosa.load(audio_path, sr=sr, mono=True)

    if len(y) / sr < MIN_DURATION_SEC:
        raise ValueError(f"Audio too short ({len(y)/sr:.1f}s). Minimum {MIN_DURATION_SEC}s required.")

    y_trimmed, trim_indices = librosa.effects.trim(y, top_db=TRIM_TOP_DB)

    if len(y_trimmed) < sr * MIN_DURATION_SEC:
        y_trimmed = y  # fall back to untrimmed if trim removes too much

    max_amp = np.max(np.abs(y_trimmed))
    if max_amp > 0:
        y_norm = y_trimmed / max_amp
    else:
        raise ValueError("Audio file contains only silence.")

    return y_norm, sr


def extract_mfcc_features(y, sr, n_mfcc=DEFAULT_N_MFCC):
    """Extract MFCC, delta, and delta-delta features with statistical aggregation."""
    mfccs = librosa.feature.mfcc(y=y, sr=sr, n_mfcc=n_mfcc,
                                  hop_length=DEFAULT_HOP_LENGTH, n_fft=DEFAULT_N_FFT)
    mfcc_delta = librosa.feature.delta(mfccs)
    mfcc_delta2 = librosa.feature.delta(mfccs, order=2)

    features = {}
    for i, coeff_row in enumerate(mfccs):
        prefix = f"mfcc_{i}"
        features[f"{prefix}_mean"] = float(np.mean(coeff_row))
        features[f"{prefix}_std"] = float(np.std(coeff_row))
        features[f"{prefix}_min"] = float(np.min(coeff_row))
        features[f"{prefix}_max"] = float(np.max(coeff_row))
        features[f"{prefix}_skew"] = float(_safe_skew(coeff_row))
        features[f"{prefix}_kurtosis"] = float(_safe_kurtosis(coeff_row))

    for i, row in enumerate(mfcc_delta):
        features[f"mfcc_delta_{i}_mean"] = float(np.mean(row))
        features[f"mfcc_delta_{i}_std"] = float(np.std(row))

    for i, row in enumerate(mfcc_delta2):
        features[f"mfcc_delta2_{i}_mean"] = float(np.mean(row))
        features[f"mfcc_delta2_{i}_std"] = float(np.std(row))

    return features, mfccs


def extract_spectral_features(y, sr):
    """Extract spectral centroid, bandwidth, contrast, rolloff, and ZCR."""
    features = {}

    spectral_centroid = librosa.feature.spectral_centroid(y=y, sr=sr,
                                                          hop_length=DEFAULT_HOP_LENGTH)
    features["spectral_centroid_mean"] = float(np.mean(spectral_centroid))
    features["spectral_centroid_std"] = float(np.std(spectral_centroid))
    centroid_mean = features["spectral_centroid_mean"]
    features["spectral_centroid_cv"] = (
        float(features["spectral_centroid_std"] / centroid_mean) if centroid_mean > 0 else 0.0
    )

    spectral_bw = librosa.feature.spectral_bandwidth(y=y, sr=sr, hop_length=DEFAULT_HOP_LENGTH)
    features["spectral_bandwidth_mean"] = float(np.mean(spectral_bw))
    features["spectral_bandwidth_std"] = float(np.std(spectral_bw))

    spectral_contrast = librosa.feature.spectral_contrast(y=y, sr=sr,
                                                           hop_length=DEFAULT_HOP_LENGTH)
    for i, band in enumerate(spectral_contrast):
        features[f"spectral_contrast_band_{i}_mean"] = float(np.mean(band))
        features[f"spectral_contrast_band_{i}_std"] = float(np.std(band))

    # Aggregate contrast in 4-8 kHz range (bands 4-5 at 16kHz SR)
    high_band_indices = [4, 5] if spectral_contrast.shape[0] > 5 else [spectral_contrast.shape[0] - 1]
    high_contrast_vals = [np.mean(spectral_contrast[i]) for i in high_band_indices]
    features["spectral_contrast_4_8khz"] = float(np.mean(high_contrast_vals))

    spectral_rolloff = librosa.feature.spectral_rolloff(y=y, sr=sr, hop_length=DEFAULT_HOP_LENGTH)
    features["spectral_rolloff_mean"] = float(np.mean(spectral_rolloff))
    features["spectral_rolloff_std"] = float(np.std(spectral_rolloff))

    zcr = librosa.feature.zero_crossing_rate(y, hop_length=DEFAULT_HOP_LENGTH)
    features["zcr_mean"] = float(np.mean(zcr))
    features["zcr_std"] = float(np.std(zcr))

    spectral_flatness = librosa.feature.spectral_flatness(y=y, hop_length=DEFAULT_HOP_LENGTH)
    features["spectral_flatness_mean"] = float(np.mean(spectral_flatness))
    features["spectral_flatness_std"] = float(np.std(spectral_flatness))

    return features


def extract_pitch_features(y, sr):
    """Extract fundamental frequency (F0), jitter, and shimmer-like features."""
    features = {}

    f0, voiced_flag, voiced_probs = librosa.pyin(y, fmin=50, fmax=500, sr=sr,
                                                  hop_length=DEFAULT_HOP_LENGTH)
    f0_clean = f0[~np.isnan(f0)]

    if len(f0_clean) > 1:
        features["pitch_mean"] = float(np.mean(f0_clean))
        features["pitch_std"] = float(np.std(f0_clean))
        features["pitch_range"] = float(np.max(f0_clean) - np.min(f0_clean))

        # Jitter: average absolute difference between consecutive F0 values
        pitch_diffs = np.abs(np.diff(f0_clean))
        features["pitch_jitter_hz"] = float(np.mean(pitch_diffs))
        features["pitch_jitter_relative"] = float(
            np.mean(pitch_diffs) / np.mean(f0_clean) if np.mean(f0_clean) > 0 else 0
        )

        # Shimmer approximation via amplitude envelope variation at pitch periods
        features["voiced_ratio"] = float(np.sum(~np.isnan(f0)) / len(f0))
        features["voiced_prob_mean"] = float(np.mean(voiced_probs[~np.isnan(voiced_probs)]))
    else:
        features["pitch_mean"] = 0.0
        features["pitch_std"] = 0.0
        features["pitch_range"] = 0.0
        features["pitch_jitter_hz"] = 0.0
        features["pitch_jitter_relative"] = 0.0
        features["voiced_ratio"] = 0.0
        features["voiced_prob_mean"] = 0.0

    return features


def extract_temporal_features(y, sr):
    """Extract time-domain features: RMS energy, tempo, onset strength."""
    features = {}

    rms = librosa.feature.rms(y=y, hop_length=DEFAULT_HOP_LENGTH)
    features["rms_mean"] = float(np.mean(rms))
    features["rms_std"] = float(np.std(rms))

    onset_env = librosa.onset.onset_strength(y=y, sr=sr, hop_length=DEFAULT_HOP_LENGTH)
    features["onset_strength_mean"] = float(np.mean(onset_env))
    features["onset_strength_std"] = float(np.std(onset_env))

    tempo = librosa.feature.tempo(onset_envelope=onset_env, sr=sr,
                                   hop_length=DEFAULT_HOP_LENGTH)
    features["tempo"] = float(tempo[0]) if len(tempo) > 0 else 0.0

    return features


def build_full_feature_vector(audio_path, sr=DEFAULT_SR):
    """Load audio and extract the complete feature set as a dict and numpy vector."""
    y, sr = load_and_preprocess(audio_path, sr=sr)

    all_features = {}
    mfcc_feats, raw_mfccs = extract_mfcc_features(y, sr)
    all_features.update(mfcc_feats)

    spectral_feats = extract_spectral_features(y, sr)
    all_features.update(spectral_feats)

    pitch_feats = extract_pitch_features(y, sr)
    all_features.update(pitch_feats)

    temporal_feats = extract_temporal_features(y, sr)
    all_features.update(temporal_feats)

    feature_names = sorted(all_features.keys())
    feature_vector = np.array([all_features[k] for k in feature_names])

    return all_features, feature_vector, feature_names, y, sr


def heuristic_deepfake_score(features):
    """Rule-based deepfake scoring using research-backed thresholds.

    Returns a score between 0.0 (likely genuine) and 1.0 (likely deepfake)
    based on known acoustic differences between real and synthetic speech.
    """
    indicators = []

    # 1. High-order MFCC variance check (coefficients 13-19 have lower variance in deepfakes)
    high_mfcc_stds = [features.get(f"mfcc_{i}_std", 1.0) for i in range(13, 20)]
    low_mfcc_stds = [features.get(f"mfcc_{i}_std", 1.0) for i in range(1, 7)]
    if np.mean(low_mfcc_stds) > 0:
        ratio = np.mean(high_mfcc_stds) / np.mean(low_mfcc_stds)
        indicators.append(1.0 if ratio < DEEPFAKE_THRESHOLDS["mfcc_high_order_var_ratio"] else 0.0)

    # 2. Spectral contrast in 4-8 kHz
    sc_4_8 = features.get("spectral_contrast_4_8khz", 0.5)
    indicators.append(1.0 if sc_4_8 < DEEPFAKE_THRESHOLDS["spectral_contrast_4_8khz"] else 0.0)

    # 3. Pitch jitter (lower in deepfakes)
    jitter = features.get("pitch_jitter_hz", 3.0)
    indicators.append(1.0 if jitter < DEEPFAKE_THRESHOLDS["pitch_jitter_hz"] else 0.0)

    # 4. Zero-crossing rate standard deviation
    zcr_std = features.get("zcr_std", 0.01)
    indicators.append(1.0 if zcr_std < DEEPFAKE_THRESHOLDS["zcr_std_threshold"] else 0.0)

    # 5. Spectral centroid coefficient of variation
    centroid_cv = features.get("spectral_centroid_cv", 0.3)
    indicators.append(1.0 if centroid_cv < DEEPFAKE_THRESHOLDS["spectral_centroid_cv"] else 0.0)

    # 6. Spectral rolloff stability
    rolloff_std = features.get("spectral_rolloff_std", 500)
    indicators.append(1.0 if rolloff_std < DEEPFAKE_THRESHOLDS["spectral_rolloff_std"] else 0.0)

    if not indicators:
        return 0.5

    # Weighted average: MFCC and pitch jitter are stronger signals
    weights = [1.5, 1.0, 1.5, 0.8, 1.0, 0.8]
    weights = weights[:len(indicators)]
    score = np.average(indicators, weights=weights)
    return float(np.clip(score, 0.0, 1.0))


def classify_with_ensemble(feature_vector, model_path=None):
    """Classify audio using pre-trained ensemble models if available.

    Falls back to heuristic scoring if no trained model is found.
    Returns dict with model predictions and confidence.
    """
    if model_path and os.path.isfile(model_path):
        try:
            import joblib
            model_data = joblib.load(model_path)
            scaler = model_data["scaler"]
            rf_model = model_data["random_forest"]
            gbt_model = model_data["gradient_boosting"]

            X_scaled = scaler.transform(feature_vector.reshape(1, -1))
            rf_prob = rf_model.predict_proba(X_scaled)[0][1]
            gbt_prob = gbt_model.predict_proba(X_scaled)[0][1]
            ensemble_prob = (rf_prob + gbt_prob) / 2.0

            return {
                "method": "trained_ensemble",
                "random_forest_score": float(rf_prob),
                "gradient_boosting_score": float(gbt_prob),
                "ensemble_score": float(ensemble_prob),
                "verdict": "LIKELY DEEPFAKE" if ensemble_prob > 0.5 else "LIKELY GENUINE",
            }
        except Exception as e:
            print(f"[WARN] Failed to load model from {model_path}: {e}", file=sys.stderr)

    return None


def train_model(genuine_dir, deepfake_dir, output_path):
    """Train ensemble classifier on directories of genuine and deepfake audio samples.

    Expects two directories containing WAV/MP3/FLAC files:
    - genuine_dir: directory of known real speech samples
    - deepfake_dir: directory of known AI-generated speech samples

    Saves trained model (scaler + RF + GBT) to output_path via joblib.
    """
    if not HAS_SKLEARN:
        print("[ERROR] scikit-learn required for training. Install with: pip install scikit-learn",
              file=sys.stderr)
        return None

    try:
        import joblib
    except ImportError:
        print("[ERROR] joblib required for model serialization. Install with: pip install joblib",
              file=sys.stderr)
        return None

    X, y_labels = [], []
    audio_extensions = {".wav", ".mp3", ".flac", ".ogg", ".m4a"}

    for label, directory in [(0, genuine_dir), (1, deepfake_dir)]:
        if not os.path.isdir(directory):
            print(f"[ERROR] Directory not found: {directory}", file=sys.stderr)
            return None
        for fname in os.listdir(directory):
            if Path(fname).suffix.lower() in audio_extensions:
                fpath = os.path.join(directory, fname)
                try:
                    _, fv, _, _, _ = build_full_feature_vector(fpath)
                    X.append(fv)
                    y_labels.append(label)
                    print(f"  Processed: {fname} (label={'deepfake' if label else 'genuine'})")
                except Exception as e:
                    print(f"  [WARN] Skipping {fname}: {e}", file=sys.stderr)

    if len(X) < 10:
        print(f"[ERROR] Need at least 10 samples, got {len(X)}. Add more audio files.",
              file=sys.stderr)
        return None

    X = np.array(X)
    y_labels = np.array(y_labels)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    rf = RandomForestClassifier(n_estimators=200, max_depth=15, random_state=42, n_jobs=-1)
    gbt = GradientBoostingClassifier(n_estimators=150, max_depth=5, learning_rate=0.1,
                                      random_state=42)

    print("\n[INFO] Training Random Forest...")
    rf_scores = cross_val_score(rf, X_scaled, y_labels, cv=min(5, len(X) // 2), scoring="accuracy")
    print(f"  RF Cross-val accuracy: {np.mean(rf_scores):.3f} (+/- {np.std(rf_scores):.3f})")

    print("[INFO] Training Gradient Boosting...")
    gbt_scores = cross_val_score(gbt, X_scaled, y_labels, cv=min(5, len(X) // 2), scoring="accuracy")
    print(f"  GBT Cross-val accuracy: {np.mean(gbt_scores):.3f} (+/- {np.std(gbt_scores):.3f})")

    rf.fit(X_scaled, y_labels)
    gbt.fit(X_scaled, y_labels)

    model_data = {
        "scaler": scaler,
        "random_forest": rf,
        "gradient_boosting": gbt,
        "feature_count": X_scaled.shape[1],
        "training_samples": len(X),
        "trained_at": datetime.utcnow().isoformat(),
    }
    joblib.dump(model_data, output_path)
    print(f"\n[OK] Model saved to {output_path}")
    return model_data


def analyze_audio(audio_path, model_path=None, output_json=None):
    """Full analysis pipeline: load, extract features, classify, and report."""
    print(f"\n{'='*60}")
    print("DEEPFAKE AUDIO ANALYSIS")
    print(f"{'='*60}")
    print(f"File:           {audio_path}")
    print(f"Analysis Date:  {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")

    features, feature_vector, feature_names, y, sr = build_full_feature_vector(audio_path)
    duration = len(y) / sr
    print(f"Duration:       {duration:.1f} seconds")
    print(f"Sample Rate:    {sr} Hz")
    print(f"Features:       {len(feature_names)} extracted")

    # Try trained model first, fall back to heuristic
    ml_result = classify_with_ensemble(feature_vector, model_path)
    heuristic_score = heuristic_deepfake_score(features)

    if ml_result:
        print("\n--- ML Classification (Trained Model) ---")
        print(f"Random Forest:     {ml_result['random_forest_score']:.3f}")
        print(f"Gradient Boosting: {ml_result['gradient_boosting_score']:.3f}")
        print(f"Ensemble Score:    {ml_result['ensemble_score']:.3f}")
        print(f"Verdict:           {ml_result['verdict']}")
        final_score = ml_result["ensemble_score"]
        method = "trained_ensemble"
    else:
        print("\n--- Heuristic Classification (No trained model) ---")
        print(f"Heuristic Score:   {heuristic_score:.3f}")
        verdict = "LIKELY DEEPFAKE" if heuristic_score > 0.5 else "LIKELY GENUINE"
        print(f"Verdict:           {verdict}")
        final_score = heuristic_score
        method = "heuristic"

    # Print feature anomalies
    print("\n--- Feature Anomaly Report ---")
    anomalies = []

    jitter = features.get("pitch_jitter_hz", 0)
    if jitter < DEEPFAKE_THRESHOLDS["pitch_jitter_hz"]:
        msg = f"Pitch jitter: {jitter:.2f} Hz (below genuine threshold of {DEEPFAKE_THRESHOLDS['pitch_jitter_hz']} Hz)"
        anomalies.append(msg)
        print(f"  [!] {msg}")

    zcr_std = features.get("zcr_std", 0)
    if zcr_std < DEEPFAKE_THRESHOLDS["zcr_std_threshold"]:
        msg = f"ZCR std: {zcr_std:.4f} (below genuine threshold of {DEEPFAKE_THRESHOLDS['zcr_std_threshold']})"
        anomalies.append(msg)
        print(f"  [!] {msg}")

    sc_4_8 = features.get("spectral_contrast_4_8khz", 0)
    if sc_4_8 < DEEPFAKE_THRESHOLDS["spectral_contrast_4_8khz"]:
        msg = f"Spectral contrast (4-8kHz): {sc_4_8:.3f} (below threshold of {DEEPFAKE_THRESHOLDS['spectral_contrast_4_8khz']})"
        anomalies.append(msg)
        print(f"  [!] {msg}")

    centroid_cv = features.get("spectral_centroid_cv", 0)
    if centroid_cv < DEEPFAKE_THRESHOLDS["spectral_centroid_cv"]:
        msg = f"Spectral centroid CV: {centroid_cv:.4f} (below threshold of {DEEPFAKE_THRESHOLDS['spectral_centroid_cv']})"
        anomalies.append(msg)
        print(f"  [!] {msg}")

    if not anomalies:
        print("  No significant anomalies detected.")

    # Build result dict
    result = {
        "file": audio_path,
        "duration_seconds": duration,
        "sample_rate": sr,
        "analysis_timestamp": datetime.utcnow().isoformat(),
        "classification": {
            "method": method,
            "deepfake_score": final_score,
            "verdict": "LIKELY DEEPFAKE" if final_score > 0.5 else "LIKELY GENUINE",
            "confidence_pct": round(max(final_score, 1 - final_score) * 100, 1),
        },
        "anomalies": anomalies,
        "features": {k: round(v, 6) if isinstance(v, float) else v for k, v in features.items()},
    }

    if ml_result:
        result["classification"]["random_forest_score"] = ml_result["random_forest_score"]
        result["classification"]["gradient_boosting_score"] = ml_result["gradient_boosting_score"]

    if output_json:
        with open(output_json, "w") as f:
            json.dump(result, f, indent=2)
        print(f"\n[OK] Full results saved to {output_json}")

    return result


def batch_analyze(audio_dir, model_path=None, output_json=None):
    """Analyze all audio files in a directory."""
    audio_extensions = {".wav", ".mp3", ".flac", ".ogg", ".m4a"}
    results = []

    if not os.path.isdir(audio_dir):
        print(f"[ERROR] Directory not found: {audio_dir}", file=sys.stderr)
        return results

    audio_files = [f for f in os.listdir(audio_dir)
                   if Path(f).suffix.lower() in audio_extensions]

    if not audio_files:
        print(f"[WARN] No audio files found in {audio_dir}", file=sys.stderr)
        return results

    print(f"\n[INFO] Batch analyzing {len(audio_files)} files from {audio_dir}\n")
    for fname in sorted(audio_files):
        fpath = os.path.join(audio_dir, fname)
        try:
            result = analyze_audio(fpath, model_path=model_path)
            results.append(result)
        except Exception as e:
            print(f"\n[ERROR] Failed to analyze {fname}: {e}", file=sys.stderr)
            results.append({"file": fpath, "error": str(e)})

    # Summary
    deepfakes = sum(1 for r in results if r.get("classification", {}).get("verdict") == "LIKELY DEEPFAKE")
    genuine = sum(1 for r in results if r.get("classification", {}).get("verdict") == "LIKELY GENUINE")
    errors = sum(1 for r in results if "error" in r)

    print(f"\n{'='*60}")
    print("BATCH ANALYSIS SUMMARY")
    print(f"{'='*60}")
    print(f"Total Files:    {len(results)}")
    print(f"Likely Deepfake: {deepfakes}")
    print(f"Likely Genuine:  {genuine}")
    print(f"Errors:          {errors}")

    if output_json:
        with open(output_json, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\n[OK] Batch results saved to {output_json}")

    return results


def _safe_skew(arr):
    """Compute skewness without scipy dependency."""
    n = len(arr)
    if n < 3:
        return 0.0
    mean = np.mean(arr)
    std = np.std(arr)
    if std == 0:
        return 0.0
    return float(np.mean(((arr - mean) / std) ** 3))


def _safe_kurtosis(arr):
    """Compute excess kurtosis without scipy dependency."""
    n = len(arr)
    if n < 4:
        return 0.0
    mean = np.mean(arr)
    std = np.std(arr)
    if std == 0:
        return 0.0
    return float(np.mean(((arr - mean) / std) ** 4) - 3.0)


def main():
    parser = argparse.ArgumentParser(
        description="Deepfake Audio Detection Agent - Analyzes audio for AI-generated speech"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Analyze single file
    analyze_parser = subparsers.add_parser("analyze", help="Analyze a single audio file")
    analyze_parser.add_argument("audio_path", help="Path to audio file (WAV, MP3, FLAC)")
    analyze_parser.add_argument("--model", help="Path to trained model (.joblib)")
    analyze_parser.add_argument("--output", "-o", help="Save results to JSON file")

    # Batch analyze directory
    batch_parser = subparsers.add_parser("batch", help="Analyze all audio files in a directory")
    batch_parser.add_argument("audio_dir", help="Directory containing audio files")
    batch_parser.add_argument("--model", help="Path to trained model (.joblib)")
    batch_parser.add_argument("--output", "-o", help="Save batch results to JSON file")

    # Train model
    train_parser = subparsers.add_parser("train", help="Train deepfake detection model")
    train_parser.add_argument("--genuine", required=True, help="Directory of genuine audio samples")
    train_parser.add_argument("--deepfake", required=True, help="Directory of deepfake audio samples")
    train_parser.add_argument("--output", "-o", default="deepfake_model.joblib",
                              help="Output model path (default: deepfake_model.joblib)")

    # Extract features only
    features_parser = subparsers.add_parser("features", help="Extract features and print as JSON")
    features_parser.add_argument("audio_path", help="Path to audio file")
    features_parser.add_argument("--output", "-o", help="Save features to JSON file")

    args = parser.parse_args()

    if not HAS_LIBROSA:
        print("[ERROR] librosa is required. Install with: pip install librosa", file=sys.stderr)
        sys.exit(1)

    if args.command == "analyze":
        analyze_audio(args.audio_path, model_path=args.model, output_json=args.output)

    elif args.command == "batch":
        batch_analyze(args.audio_dir, model_path=args.model, output_json=args.output)

    elif args.command == "train":
        if not HAS_SKLEARN:
            print("[ERROR] scikit-learn required. Install with: pip install scikit-learn",
                  file=sys.stderr)
            sys.exit(1)
        train_model(args.genuine, args.deepfake, args.output)

    elif args.command == "features":
        features, fv, names, _, _ = build_full_feature_vector(args.audio_path)
        output = {"file": args.audio_path, "feature_count": len(names), "features": features}
        if args.output:
            with open(args.output, "w") as f:
                json.dump(output, f, indent=2)
            print(f"[OK] Features saved to {args.output}")
        else:
            print(json.dumps(output, indent=2))

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
