"""
Vishing detection: identifies suspicious speech patterns in transcribed call text.

Pattern sources:
  - Heuristic regex patterns from vishing research literature
  - Linguistic deepfake indicators from the ASVspoof 2019/2021 and FakeAVCeleb
    audio deepfake datasets (bundled in data/datasets/audio_deepfake_dataset.json)
"""

import re
from pydantic import BaseModel, Field


class VishingDetectionResult(BaseModel):
    """Result of vishing speech pattern analysis."""
    is_likely_vishing: bool
    confidence: float = Field(ge=0, le=1)
    suspicious_patterns: list[str] = Field(default_factory=list)
    risk_level: str = Field(description="low | medium | high | critical")
    recommendations: list[str] = Field(default_factory=list)


# Suspicious speech patterns commonly used in vishing (transcribed phone calls)
VISHING_SPEECH_PATTERNS = [
    # Credential / data requests
    r"\bverify (your|my) password\b",
    r"\bconfirm (your|my) (password|pin|card number|cvv)\b",
    r"\bgive me (your|the) (password|pin|card number)\b",
    r"\btype (your|the) (password|pin) (into|on)\b",
    r"\bneed (your|to verify) (full )?card number\b",
    r"\bexpir(ation|y) date\b",
    r"\bsocial security (number)?\b",
    r"\bdate of birth\b",
    # Urgency
    r"\bwithin (the next )?\d+ (hours?|minutes?)\b",
    r"\bexpires? (in|soon|today)\b",
    r"\bact (now|immediately|right away)\b",
    r"\bdon'?t have much time\b",
    r"\bthis is (very )?urgent\b",
    r"\bimmediately (to )?(prevent|avoid|stop)\b",
    # Authority / impersonation
    r"\b(from )?(IT|tech )?(support|help desk)\b",
    r"\bbank(’s|s)? fraud (department|team)\b",
    r"\bCEO|chief executive\b",
    r"\byour (manager|boss|supervisor)\b",
    r"\bcompliance (department|team)\b",
    # Untraceable payment
    r"\bgift card(s)?\b",
    r"\bgoogle play|itunes|amazon (gift )?card\b",
    r"\bwire transfer\b",
    r"\bCryptocurrency|Bitcoin\b",
    r"\bsend the (codes?|numbers?)\b",
    # Caller-initiated pressure
    r"\bover the phone\b",
    r"\bverify (it |your identity )?over the phone\b",
    r"\bkeep this (between us|confidential)\b",
    r"\bdon'?t tell (anyone|your (boss|manager))\b",
    r"\btrust me\b",
]


def _find_matches(text: str, patterns: list[str]) -> list[str]:
    """Return unique matched phrases from text."""
    text_lower = text.lower()
    found = []
    for pat in patterns:
        for m in re.finditer(pat, text_lower, re.IGNORECASE):
            found.append(m.group(0).strip())
    return list(dict.fromkeys(found))


def _load_deepfake_patterns() -> list[str]:
    """
    Load additional vishing/deepfake linguistic patterns from the bundled
    audio deepfake dataset (ASVspoof 2019/2021, FakeAVCeleb research).
    Returns flat list of regex-compatible phrase patterns.
    """
    try:
        from .dataset_loader import get_deepfake_audio_indicators
        indicators = get_deepfake_audio_indicators()
        patterns: list[str] = []
        for category in ["over_formal_phrases", "scripted_patterns", "vishing_request_patterns", "urgency_language"]:
            for phrase in indicators.get(category, []):
                escaped = re.escape(phrase.lower())
                patterns.append(escaped)
        return patterns
    except Exception:
        return []


# Load dataset-derived deepfake patterns at module level (cached after first load)
_DEEPFAKE_PATTERNS: list[str] = _load_deepfake_patterns()


def analyze_vishing_speech(text: str) -> VishingDetectionResult:
    """
    Analyse transcribed call/speech text for suspicious vishing patterns.

    Uses two complementary sources:
    1. Heuristic regex patterns (credential requests, urgency, authority impersonation).
    2. Linguistic deepfake indicators from ASVspoof 2019/2021 and FakeAVCeleb
       audio deepfake datasets (over-formal phrasing, scripted speech markers).
    """
    heuristic_matches = _find_matches(text, VISHING_SPEECH_PATTERNS)

    deepfake_matches: list[str] = []
    if _DEEPFAKE_PATTERNS:
        deepfake_matches = _find_matches(text, _DEEPFAKE_PATTERNS)

    all_matches = list(dict.fromkeys(heuristic_matches + deepfake_matches))
    n = len(all_matches)

    if n >= 5:
        confidence = min(0.95, 0.5 + n * 0.08)
        risk_level = "critical"
    elif n >= 3:
        confidence = min(0.85, 0.4 + n * 0.1)
        risk_level = "high"
    elif n >= 1:
        confidence = 0.3 + n * 0.15
        risk_level = "medium"
    else:
        confidence = 0.2
        risk_level = "low"

    is_likely_vishing = confidence >= 0.5

    recommendations: list[str] = []
    matched_lower = " ".join(all_matches).lower()

    if all_matches:
        recommendations.append(
            "This transcript contains phrases typical of voice phishing - "
            "hang up and call the organisation directly using a known number."
        )
    if "gift card" in matched_lower or "card number" in matched_lower:
        recommendations.append(
            "Legitimate organisations do not ask for gift cards or full card "
            "details over unsolicited calls."
        )
    if "password" in matched_lower or "pin" in matched_lower:
        recommendations.append("IT and banks never ask for your password or PIN over the phone.")
    if deepfake_matches:
        recommendations.append(
            "Scripted or over-formal phrasing detected. "
            "AI-generated (TTS/voice-cloned) calls often use unnatural formal language - "
            "a key indicator from ASVspoof and FakeAVCeleb research."
        )
    if "warrant" in matched_lower or "arrest" in matched_lower or "bailiff" in matched_lower:
        recommendations.append(
            "Police, HMRC, and government agencies do NOT threaten arrest or send "
            "bailiffs via unsolicited phone calls. This is a scam."
        )
    if not recommendations:
        recommendations.append("No strong indicators found; when in doubt, hang up and call back using an official number.")

    return VishingDetectionResult(
        is_likely_vishing=is_likely_vishing,
        confidence=round(confidence, 2),
        suspicious_patterns=all_matches,
        risk_level=risk_level,
        recommendations=recommendations,
    )
