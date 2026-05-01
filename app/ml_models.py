"""
ML Models – Phish X

Trains, saves, and loads the machine-learning classifiers used for
phishing email detection and audio deepfake detection.

Email detection pipeline:
  TF-IDF vectoriser → Naïve Bayes classifier (primary)
                    → Random Forest classifier (secondary / ensemble)

Audio deepfake detection pipeline:
  Librosa MFCC extraction → Random Forest classifier

Models are trained once on first startup and cached to disk via Joblib.
Subsequent startups load from disk (fast).  Delete the models/ directory
to force retraining.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import warnings
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import MinMaxScaler

warnings.filterwarnings("ignore", category=UserWarning)
logger = logging.getLogger(__name__)

if getattr(sys, "frozen", False):
    _PKG_DIR     = Path(sys._MEIPASS) / "app"
    _DATASET_DIR = _PKG_DIR / "_datasets"
    _MODEL_DIR   = Path(sys._MEIPASS) / "models"
else:
    _PKG_DIR     = Path(__file__).resolve().parent
    _DATASET_DIR = _PKG_DIR / "_datasets"
    _MODEL_DIR   = _PKG_DIR.parent / "models"

_MODEL_DIR.mkdir(parents=True, exist_ok=True)

_EMAIL_NB_PATH  = _MODEL_DIR / "email_nb_pipeline.joblib"
_EMAIL_RF_PATH  = _MODEL_DIR / "email_rf_pipeline.joblib"
_AUDIO_RF_PATH  = _MODEL_DIR / "audio_rf_classifier.joblib"
_AUDIO_SC_PATH  = _MODEL_DIR / "audio_scaler.joblib"

_email_nb:  Pipeline | None = None
_email_rf:  Pipeline | None = None
_audio_rf:  RandomForestClassifier | None = None
_audio_scaler: MinMaxScaler | None = None


def _load_json(path: Path) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _collect_email_training_data() -> tuple[list[str], list[int]]:
    """
    Build training corpus from bundled datasets + built-in simulation templates.
    Returns (texts, labels) where label 1 = phishing, 0 = legitimate.
    """
    texts:  list[str] = []
    labels: list[int] = []

    phish_data = _load_json(_DATASET_DIR / "phishing_email_dataset.json")
    for s in phish_data.get("samples", []):
        text = (s.get("subject", "") + " " + s.get("body", "")).strip()
        if text:
            texts.append(text)
            labels.append(1)

    legit_data = _load_json(_DATASET_DIR / "legitimate_email_dataset.json")
    for s in legit_data.get("samples", []):
        text = (s.get("subject", "") + " " + s.get("body", "")).strip()
        if text:
            texts.append(text)
            labels.append(0)

    sms_data = _load_json(_DATASET_DIR / "sms_phishing_dataset.json")
    for s in sms_data.get("samples", []):
        text = s.get("text", "").strip()
        if not text:
            continue
        label = 1 if s.get("label") == "smishing" else 0
        texts.append(text)
        labels.append(label)

    # imported lazily to avoid circular deps
    try:
        from app.simulation import PHISHING_EMAIL_TEMPLATES, LEGITIMATE_EMAIL_TEMPLATES
        for t in PHISHING_EMAIL_TEMPLATES:
            text = (t.get("subject", "") + " " + t.get("body", "")).strip()
            if text:
                texts.append(text)
                labels.append(1)
        for t in LEGITIMATE_EMAIL_TEMPLATES:
            text = (t.get("subject", "") + " " + t.get("body", "")).strip()
            if text:
                texts.append(text)
                labels.append(0)
    except ImportError:
        pass

    return texts, labels


def _train_email_models() -> tuple[Pipeline, Pipeline]:
    """Train and save TF-IDF + Naïve Bayes and TF-IDF + Random Forest pipelines."""
    texts, labels = _collect_email_training_data()

    if len(texts) < 10:
        raise RuntimeError("Insufficient training data for email models.")

    logger.info("Training email ML models on %d samples…", len(texts))

    tfidf_nb = TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=8000,
        sublinear_tf=True,
        min_df=1,
    )
    tfidf_rf = TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=8000,
        sublinear_tf=True,
        min_df=1,
    )

    nb_pipeline = Pipeline([
        ("tfidf", tfidf_nb),
        ("clf",   MultinomialNB(alpha=0.5)),
    ])
    rf_pipeline = Pipeline([
        ("tfidf", tfidf_rf),
        ("clf",   RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            min_samples_leaf=1,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        )),
    ])

    nb_pipeline.fit(texts, labels)
    rf_pipeline.fit(texts, labels)

    joblib.dump(nb_pipeline, _EMAIL_NB_PATH)
    joblib.dump(rf_pipeline, _EMAIL_RF_PATH)
    logger.info("Email models saved to %s", _MODEL_DIR)
    return nb_pipeline, rf_pipeline


_N_MFCC = 13
# 13 means + 13 stds + 13 delta means + 13 delta stds + ZCR mean/std + spectral centroid + rolloff = 56
_AUDIO_FEATURE_DIM = _N_MFCC * 4 + 4


def _synth_real_speech_features(n: int, rng: np.random.Generator) -> np.ndarray:
    """
    Synthetic MFCC feature vectors approximating genuine human speech.

    Characteristics (from ASVspoof/WaveFake literature):
    - High intra-utterance variance across MFCC coefficients
    - Natural pitch variation → wider spread in lower MFCCs
    - Non-zero ZCR variance (breath sounds, coarticulation)
    - Higher spectral centroid variance
    """
    rows = []
    for _ in range(n):
        # MFCC means: wide dynamic range, lower coefficients dominate
        mfcc_means = rng.normal(loc=0, scale=np.linspace(20, 3, _N_MFCC))
        # MFCC stds: real speech has high per-frame variance
        mfcc_stds  = np.abs(rng.normal(loc=8, scale=3, size=_N_MFCC)) + 2
        # Delta MFCC: captures temporal dynamics (real speech is non-monotonic)
        delta_means = rng.normal(loc=0, scale=np.linspace(4, 0.8, _N_MFCC))
        delta_stds  = np.abs(rng.normal(loc=2.5, scale=1.0, size=_N_MFCC)) + 0.5
        # Zero-crossing rate: real speech has breathing gaps → higher variance
        zcr_mean = rng.uniform(0.05, 0.15)
        zcr_std  = rng.uniform(0.03, 0.08)
        # Spectral centroid and rolloff
        sc_mean = rng.uniform(1800, 3500)
        sr_mean = rng.uniform(3000, 6000)

        row = np.concatenate([
            mfcc_means, mfcc_stds, delta_means, delta_stds,
            [zcr_mean, zcr_std, sc_mean, sr_mean],
        ])
        rows.append(row)
    return np.array(rows)


def _synth_ai_speech_features(n: int, rng: np.random.Generator) -> np.ndarray:
    """
    Synthetic MFCC feature vectors approximating AI-generated / TTS / VC speech.

    Characteristics (ASVspoof 2019/2021, WaveFake literature):
    - Lower MFCC variance → monotone pitch (low F0 variation)
    - Reduced delta MFCC variance → overly smooth temporal transitions
    - Low ZCR variance → absence of breath sounds and natural pauses
    - Periodic artefacts in high-frequency bands (WaveNet, MelGAN vocoders)
    - Compressed dynamic range
    """
    rows = []
    for _ in range(n):
        # MFCC means: narrower range, less natural variation
        mfcc_means = rng.normal(loc=0, scale=np.linspace(12, 2, _N_MFCC))
        # MFCC stds: AI speech is unusually smooth → lower variance
        mfcc_stds  = np.abs(rng.normal(loc=3, scale=1.0, size=_N_MFCC)) + 0.5
        # Delta MFCC: smooth transitions, low temporal dynamics
        delta_means = rng.normal(loc=0, scale=np.linspace(1.5, 0.3, _N_MFCC))
        delta_stds  = np.abs(rng.normal(loc=0.8, scale=0.4, size=_N_MFCC)) + 0.1
        # ZCR: AI speech lacks breath sounds → low variance, steady rate
        zcr_mean = rng.uniform(0.07, 0.12)
        zcr_std  = rng.uniform(0.005, 0.02)
        # Spectral: often narrower band and higher rolloff for vocoders
        sc_mean = rng.uniform(2200, 4000)
        sr_mean = rng.uniform(5000, 7500)

        row = np.concatenate([
            mfcc_means, mfcc_stds, delta_means, delta_stds,
            [zcr_mean, zcr_std, sc_mean, sr_mean],
        ])
        rows.append(row)
    return np.array(rows)


def _train_audio_model() -> tuple[RandomForestClassifier, MinMaxScaler]:
    """
    Train and save an audio deepfake classifier using synthetic MFCC feature vectors.

    Training data is generated from distributions parameterised by acoustic
    characteristics documented in ASVspoof 2019/2021, WaveFake, and FakeAVCeleb
    research (see app/_datasets/audio_deepfake_dataset.json for citations).

    Label: 0 = genuine speech, 1 = AI-generated / deepfake speech.
    """
    logger.info("Training audio deepfake classifier on synthetic MFCC features…")
    rng = np.random.default_rng(seed=42)

    n_real = 1500
    n_fake = 1500

    X_real = _synth_real_speech_features(n_real, rng)
    X_fake = _synth_ai_speech_features(n_fake, rng)

    X = np.vstack([X_real, X_fake])
    y = np.array([0] * n_real + [1] * n_fake)

    scaler = MinMaxScaler()
    X_scaled = scaler.fit_transform(X)

    clf = RandomForestClassifier(
        n_estimators=300,
        max_depth=15,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_scaled, y)

    joblib.dump(clf, _AUDIO_RF_PATH)
    joblib.dump(scaler, _AUDIO_SC_PATH)
    logger.info("Audio model saved to %s", _MODEL_DIR)
    return clf, scaler


def get_email_models() -> tuple[Pipeline, Pipeline]:
    """
    Return (nb_pipeline, rf_pipeline) for email phishing classification.
    Trains and caches on first call.
    """
    global _email_nb, _email_rf
    if _email_nb is not None and _email_rf is not None:
        return _email_nb, _email_rf

    if _EMAIL_NB_PATH.exists() and _EMAIL_RF_PATH.exists():
        try:
            _email_nb = joblib.load(_EMAIL_NB_PATH)
            _email_rf = joblib.load(_EMAIL_RF_PATH)
            logger.info("Email ML models loaded from disk.")
            return _email_nb, _email_rf
        except Exception as e:
            logger.warning("Could not load email models from disk (%s). Retraining…", e)

    _email_nb, _email_rf = _train_email_models()
    return _email_nb, _email_rf


def get_audio_model() -> tuple[RandomForestClassifier, MinMaxScaler]:
    """
    Return (classifier, scaler) for audio deepfake detection.
    Trains and caches on first call.
    """
    global _audio_rf, _audio_scaler
    if _audio_rf is not None and _audio_scaler is not None:
        return _audio_rf, _audio_scaler

    if _AUDIO_RF_PATH.exists() and _AUDIO_SC_PATH.exists():
        try:
            _audio_rf     = joblib.load(_AUDIO_RF_PATH)
            _audio_scaler = joblib.load(_AUDIO_SC_PATH)
            logger.info("Audio ML model loaded from disk.")
            return _audio_rf, _audio_scaler
        except Exception as e:
            logger.warning("Could not load audio model from disk (%s). Retraining…", e)

    _audio_rf, _audio_scaler = _train_audio_model()
    return _audio_rf, _audio_scaler


def classify_email_text(text: str) -> dict:
    """
    Classify email/SMS text as phishing or legitimate using the ML ensemble.

    Returns:
        {
            nb_label:       "phishing" | "legitimate",
            nb_confidence:  float,       # probability of phishing class
            rf_label:       "phishing" | "legitimate",
            rf_confidence:  float,
            ensemble_score: float,       # weighted average (60% NB, 40% RF)
        }
    """
    try:
        nb, rf = get_email_models()
    except Exception as e:
        logger.error("Email model unavailable: %s", e)
        return {
            "nb_label": "unknown", "nb_confidence": 0.5,
            "rf_label": "unknown", "rf_confidence": 0.5,
            "ensemble_score": 0.5,
        }

    nb_proba = nb.predict_proba([text])[0]
    rf_proba = rf.predict_proba([text])[0]

    # Class order: [0=legitimate, 1=phishing]
    nb_phish = float(nb_proba[1]) if len(nb_proba) > 1 else 0.5
    rf_phish = float(rf_proba[1]) if len(rf_proba) > 1 else 0.5

    ensemble = round(nb_phish * 0.60 + rf_phish * 0.40, 3)

    return {
        "nb_label":       "phishing" if nb_phish >= 0.5 else "legitimate",
        "nb_confidence":  round(nb_phish, 3),
        "rf_label":       "phishing" if rf_phish >= 0.5 else "legitimate",
        "rf_confidence":  round(rf_phish, 3),
        "ensemble_score": ensemble,
    }


def extract_audio_features(y: "np.ndarray", sr: int) -> np.ndarray:
    """
    Extract a fixed-length MFCC feature vector from a raw audio waveform.

    Features (56-dim):
      13 MFCC means, 13 MFCC stds,
      13 delta-MFCC means, 13 delta-MFCC stds,
      ZCR mean, ZCR std, spectral centroid mean, spectral rolloff mean.

    Args:
        y:  1-D numpy array of audio samples (float32).
        sr: Sample rate in Hz.

    Returns:
        56-dimensional float64 feature vector.
    """
    import librosa  

    mfcc        = librosa.feature.mfcc(y=y, sr=sr, n_mfcc=_N_MFCC)
    delta_mfcc  = librosa.feature.delta(mfcc)
    zcr         = librosa.feature.zero_crossing_rate(y)
    sc          = librosa.feature.spectral_centroid(y=y, sr=sr)
    sr_feat     = librosa.feature.spectral_rolloff(y=y, sr=sr)

    features = np.concatenate([
        np.mean(mfcc, axis=1),        
        np.std(mfcc, axis=1),         
        np.mean(delta_mfcc, axis=1),  
        np.std(delta_mfcc, axis=1),   
        [np.mean(zcr), np.std(zcr)],  
        [np.mean(sc)],                
        [np.mean(sr_feat)],           
    ])
    return features.astype(np.float64)


def classify_audio(y: "np.ndarray", sr: int) -> dict:
    """
    Classify a raw audio waveform as genuine or AI-generated speech.

    Returns:
        {
            label:       "genuine" | "ai_generated",
            confidence:  float,     # probability of AI-generated class
            risk_level:  "low" | "medium" | "high" | "critical",
            features_used: list[str],
        }
    """
    try:
        features = extract_audio_features(y, sr)
    except Exception as e:
        logger.warning("Audio feature extraction failed: %s", e)
        return {
            "label": "unknown", "confidence": 0.5,
            "risk_level": "medium", "features_used": [],
        }

    try:
        clf, scaler = get_audio_model()
        X = scaler.transform(features.reshape(1, -1))
        proba = clf.predict_proba(X)[0]
        ai_prob = float(proba[1]) if len(proba) > 1 else 0.5
    except Exception as e:
        logger.error("Audio model inference failed: %s", e)
        return {
            "label": "unknown", "confidence": 0.5,
            "risk_level": "medium", "features_used": [],
        }

    if ai_prob >= 0.75:
        risk_level = "critical"
    elif ai_prob >= 0.55:
        risk_level = "high"
    elif ai_prob >= 0.35:
        risk_level = "medium"
    else:
        risk_level = "low"

    return {
        "label":         "ai_generated" if ai_prob >= 0.5 else "genuine",
        "confidence":    round(ai_prob, 3),
        "risk_level":    risk_level,
        "features_used": [
            "MFCC (13 coefficients, mean + std)",
            "Delta-MFCC (temporal dynamics)",
            "Zero Crossing Rate",
            "Spectral Centroid",
            "Spectral Rolloff",
        ],
    }


def _prewarm() -> None:
    """Train / load models at import time so first requests are fast."""
    try:
        get_email_models()
    except Exception as e:
        logger.warning("Email model pre-warm failed: %s", e)
    try:
        get_audio_model()
    except Exception as e:
        logger.warning("Audio model pre-warm failed: %s", e)


_prewarm()
