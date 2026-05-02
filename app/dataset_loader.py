"""
Dataset Loader - Phish X  (BACKEND INTERNAL - NOT EXPOSED TO USERS)

Loads the four bundled datasets from the private _datasets/ package directory.
Dataset files live inside the Python app package and are never served to clients.

Internal API surface (used only by detection engine and summary endpoint):
  - get_email_term_scores()         → term-frequency map for email detection
  - get_sms_term_scores()           → term-frequency map for SMS detection
  - get_deepfake_audio_indicators() → linguistic patterns for vishing detection
  - score_text_against_dataset()    → score a text string (returns score + metadata, NO raw samples)
  - get_all_dataset_info()          → metadata/statistics only (no samples)

Bundled datasets (private, backend-only):
  1. Phishing email   - SpamAssassin, CEAS 2008, Enron-Spam, Nazario
  2. Legitimate email - SpamAssassin Ham, Enron Ham, Ling-Spam
  3. SMS phishing     - UCI SMS Spam Collection, Misra, Bergholz
  4. Audio deepfake   - ASVspoof 2019/2021, FakeAVCeleb, WaveFake, ADD 2022
"""

import json
import re
import sys
from collections import Counter
from pathlib import Path

# ---------------------------------------------------------------------------
# Path resolution - datasets are in the private _datasets/ sub-package.
# This directory is INSIDE the Python package, not in data/ or static/.
# Works in dev mode and when frozen by PyInstaller.
# ---------------------------------------------------------------------------

if getattr(sys, "frozen", False):
    _PKG_DIR = Path(sys._MEIPASS) / "app" / "_datasets"
else:
    _PKG_DIR = Path(__file__).resolve().parent / "_datasets"

_PHISHING_EMAIL_FILE  = _PKG_DIR / "phishing_email_dataset.json"
_LEGITIMATE_EMAIL_FILE = _PKG_DIR / "legitimate_email_dataset.json"
_SMS_FILE             = _PKG_DIR / "sms_phishing_dataset.json"
_AUDIO_FILE           = _PKG_DIR / "audio_deepfake_dataset.json"


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _load_json(path: Path) -> dict:
    """Load a JSON file from the private datasets directory."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def _tokenise(text: str) -> list[str]:
    """Lowercase alpha tokeniser, min 3 chars."""
    return [w for w in re.findall(r"[a-z]{3,}", text.lower()) if w]


def _build_term_scores(phishing_texts: list[str], legit_texts: list[str]) -> dict[str, float]:
    """
    Build a term-score map from phishing vs legitimate corpora.
    Score ∈ [0, 1]: 1 = exclusively phishing, 0 = exclusively legitimate.
    Uses Laplace smoothing to handle unseen terms.
    """
    phish_counts: Counter = Counter()
    legit_counts: Counter = Counter()
    for t in phishing_texts:
        phish_counts.update(_tokenise(t))
    for t in legit_texts:
        legit_counts.update(_tokenise(t))

    scores: dict[str, float] = {}
    for term in set(phish_counts) | set(legit_counts):
        p = phish_counts.get(term, 0) + 1
        l = legit_counts.get(term, 0) + 1
        scores[term] = round(p / (p + l), 3)
    return scores


# ---------------------------------------------------------------------------
# Module-level caches (computed once at first call)
# ---------------------------------------------------------------------------

_cached_email_scores: dict[str, float] | None = None
_cached_sms_scores:   dict[str, float] | None = None
_cached_info: dict | None = None


# ---------------------------------------------------------------------------
# Internal detection API
# ---------------------------------------------------------------------------

def get_email_term_scores() -> dict[str, float]:
    """
    Data-driven term scores for email phishing detection.
    Built from SpamAssassin, CEAS 2008, Enron-Spam and Nazario corpora.
    Cached after first load.
    """
    global _cached_email_scores
    if _cached_email_scores is not None:
        return _cached_email_scores

    phish_data = _load_json(_PHISHING_EMAIL_FILE)
    legit_data  = _load_json(_LEGITIMATE_EMAIL_FILE)

    phishing_texts = [
        s.get("subject", "") + " " + s.get("body", "")
        for s in phish_data.get("samples", [])
    ]
    legit_texts = [
        s.get("subject", "") + " " + s.get("body", "")
        for s in legit_data.get("samples", [])
    ]

    computed = _build_term_scores(phishing_texts, legit_texts)

    # Overlay curated vocabulary from dataset metadata (higher authority)
    meta_phish = phish_data.get("metadata", {}).get("feature_vocabulary", {}).get("top_phishing_terms", {})
    meta_legit  = legit_data.get("metadata", {}).get("feature_vocabulary", {}).get("top_legitimate_terms", {})

    for term, score in meta_phish.items():
        computed[term.lower()] = max(computed.get(term.lower(), 0.0), score)
    for term, score in meta_legit.items():
        computed[term.lower()] = min(computed.get(term.lower(), 1.0), 1.0 - score * 0.5)

    _cached_email_scores = computed
    return computed


def get_sms_term_scores() -> dict[str, float]:
    """
    Data-driven term scores for SMS phishing detection.
    Built from the UCI SMS Spam Collection, Misra, and Bergholz datasets.
    Cached after first load.
    """
    global _cached_sms_scores
    if _cached_sms_scores is not None:
        return _cached_sms_scores

    sms_data = _load_json(_SMS_FILE)
    samples  = sms_data.get("samples", [])

    phishing_texts = [s.get("text", "") for s in samples if s.get("label") == "smishing"]
    legit_texts    = [s.get("text", "") for s in samples if s.get("label") == "legitimate"]

    computed = _build_term_scores(phishing_texts, legit_texts)

    meta_smish = sms_data.get("metadata", {}).get("feature_vocabulary", {}).get("top_smishing_terms", {})
    for term, score in meta_smish.items():
        computed[term.lower()] = max(computed.get(term.lower(), 0.0), score)

    _cached_sms_scores = computed
    return computed


def get_deepfake_audio_indicators() -> dict:
    """
    Linguistic/prosodic indicators of AI-generated speech from ASVspoof
    and FakeAVCeleb research. Used internally by the vishing detector.
    Returns a dict of pattern categories → phrase lists.
    """
    audio_data = _load_json(_AUDIO_FILE)
    return audio_data.get("metadata", {}).get("linguistic_deepfake_indicators", {})


def score_text_against_dataset(text: str, mode: str = "email") -> dict:
    """
    Score text against the dataset-derived term-frequency model.

    Returns only the numeric score and metadata - NEVER raw dataset samples.

    Args:
        text: Text to analyse.
        mode: 'email' or 'sms'.

    Returns:
        {
          dataset_score: float,        - data-driven phishing probability
          top_phishing_terms: list,    - high-scoring terms found in text
          term_count: int,
          dataset_source: list[str],   - dataset names (citations only)
        }
    """
    scores = get_email_term_scores() if mode == "email" else get_sms_term_scores()
    tokens = _tokenise(text)

    if not tokens:
        return {"dataset_score": 0.0, "top_phishing_terms": [], "term_count": 0, "dataset_source": []}

    scored_tokens = [(t, scores[t]) for t in tokens if t in scores]
    if not scored_tokens:
        return {"dataset_score": 0.2, "top_phishing_terms": [], "term_count": 0,
                "dataset_source": _source_names(mode)}

    avg_score = sum(s for _, s in scored_tokens) / len(scored_tokens)
    top_terms = sorted([(t, s) for t, s in scored_tokens if s > 0.65],
                       key=lambda x: x[1], reverse=True)[:8]

    return {
        "dataset_score": round(min(avg_score * 1.1, 0.99), 3),
        "top_phishing_terms": [t for t, _ in top_terms],
        "term_count": len(scored_tokens),
        "dataset_source": _source_names(mode),
    }


def get_all_dataset_info() -> dict:
    """
    Return metadata and statistics for all four datasets - for the UI info page.
    Returns ONLY provenance metadata (name, description, sources, statistics).
    Raw samples are NEVER included in this output.
    """
    global _cached_info
    if _cached_info is not None:
        return _cached_info

    phish_data  = _load_json(_PHISHING_EMAIL_FILE)
    legit_data  = _load_json(_LEGITIMATE_EMAIL_FILE)
    sms_data    = _load_json(_SMS_FILE)
    audio_data  = _load_json(_AUDIO_FILE)

    def _safe_meta(data: dict, dataset_id: str) -> dict:
        meta = data.get("metadata", {})
        # Strip samples key - return ONLY metadata
        return {
            "id": dataset_id,
            "name": meta.get("name", ""),
            "description": meta.get("description", ""),
            "sources": [
                {k: v for k, v in s.items() if k != "samples"}
                for s in meta.get("sources", [])
            ],
            "statistics": meta.get("statistics", {}),
        }

    _cached_info = {
        "phishing_email":   _safe_meta(phish_data,  "phishing_email"),
        "legitimate_email": _safe_meta(legit_data,  "legitimate_email"),
        "sms_phishing":     _safe_meta(sms_data,    "sms_phishing"),
        "audio_deepfake": {
            **_safe_meta(audio_data, "audio_deepfake"),
            "detection_models": audio_data.get("metadata", {})
                                           .get("detection_models", {})
                                           .get("models", []),
        },
    }
    return _cached_info


# ---------------------------------------------------------------------------
# Private helper
# ---------------------------------------------------------------------------

def _source_names(mode: str) -> list[str]:
    """Return dataset source names for citation purposes only."""
    if mode == "sms":
        data = _load_json(_SMS_FILE)
    elif mode == "audio":
        data = _load_json(_AUDIO_FILE)
    else:
        data = _load_json(_PHISHING_EMAIL_FILE)
    return [s.get("name", "") for s in data.get("metadata", {}).get("sources", [])]
