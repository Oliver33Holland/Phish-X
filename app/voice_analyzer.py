"""
Voice Analyzer - Upload audio or video files to detect vishing attacks.

Processing pipeline:
  1. Convert to WAV (pydub / ffmpeg) if needed.
  2. Transcribe speech using Google Speech Recognition (free, no API key).
  3. Run vishing speech-pattern analysis on the transcript (heuristic regex).
  4. Extract MFCC / spectral features with Librosa and classify the audio
     waveform as genuine or AI-generated using the Random Forest deepfake
     classifier (see app/ml_models.py).

Falls back gracefully if optional dependencies (pydub, librosa, ffmpeg) are
missing - each stage degrades independently.
"""

import logging
import os
import shutil
import tempfile
from pathlib import Path

# Ensure pydub can find ffmpeg even if PATH hasn't been refreshed yet
def _find_ffmpeg() -> str | None:
    if path := shutil.which("ffmpeg"):
        return path
    candidates = [
        Path.home() / "AppData/Local/Microsoft/WinGet/Links/ffmpeg.exe",
        Path("C:/ProgramData/chocolatey/bin/ffmpeg.exe"),
        Path("C:/ffmpeg/bin/ffmpeg.exe"),
    ]
    for c in candidates:
        if c.exists():
            return str(c)
    return None

_ffmpeg_path = _find_ffmpeg()
if _ffmpeg_path:
    os.environ.setdefault("PATH", "")
    _ffmpeg_dir = str(Path(_ffmpeg_path).parent)
    if _ffmpeg_dir not in os.environ["PATH"]:
        os.environ["PATH"] = _ffmpeg_dir + os.pathsep + os.environ["PATH"]

import numpy as np
from pydantic import BaseModel, Field

from .detection import analyze_vishing_speech

logger = logging.getLogger(__name__)

AUDIO_EXTENSIONS = {".wav", ".flac", ".aiff", ".aif"}
CONVERTIBLE_EXTENSIONS = {".mp3", ".ogg", ".m4a", ".mp4", ".mov", ".avi", ".mkv",
                           ".webm", ".wma", ".aac", ".3gp"}
ALL_SUPPORTED = AUDIO_EXTENSIONS | CONVERTIBLE_EXTENSIONS


class TranscriptResult(BaseModel):
    """Result of audio transcription + vishing analysis + deepfake classification."""
    filename: str
    transcript: str
    transcript_confidence: str = Field(description="high | medium | low | manual")
    engine_used: str
    analysis: dict
    deepfake_analysis: dict = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
    supported_formats: list[str] = Field(default_factory=list)


def _transcribe_wav(wav_path: str) -> tuple[str, str]:
    """
    Transcribe a WAV file using SpeechRecognition (Google free API).
    Returns (transcript, confidence_label).
    """
    try:
        import speech_recognition as sr
    except ImportError:
        raise RuntimeError("Speech recognition engine unavailable. Please paste the transcript manually.")

    recognizer = sr.Recognizer()
    recognizer.energy_threshold = 300
    recognizer.dynamic_energy_threshold = True

    with sr.AudioFile(wav_path) as source:
        recognizer.adjust_for_ambient_noise(source, duration=0.5)
        audio = recognizer.record(source)

    try:
        transcript = recognizer.recognize_google(audio, language="en-GB")
        return transcript, "high"
    except sr.UnknownValueError:
        return "", "low"
    except sr.RequestError as e:
        raise RuntimeError(f"Google Speech API unavailable: {e}. Check your internet connection.")


def _convert_to_wav(input_path: str, output_wav: str) -> None:
    """Convert audio/video to WAV using pydub (requires ffmpeg on PATH)."""
    try:
        from pydub import AudioSegment
    except ImportError:
        raise RuntimeError(
            "MP4/MP3 conversion requires ffmpeg. "
            "Download from https://ffmpeg.org/download.html and add to PATH, "
            "then restart Phish X."
        )

    ext = Path(input_path).suffix.lower().lstrip(".")
    is_video = ext in {"mp4", "mov", "avi", "mkv", "webm", "3gp"}

    try:
        if is_video:
            audio = AudioSegment.from_file(input_path, format=ext)
        else:
            audio = AudioSegment.from_file(input_path)

        # Mono 16kHz WAV - best for speech recognition
        audio = audio.set_channels(1).set_frame_rate(16000)
        audio.export(output_wav, format="wav")
    except Exception as e:
        err = str(e)
        needs_ffmpeg = (
            "ffmpeg" in err.lower()
            or "ffprobe" in err.lower()
            or "winerror 2" in err.lower()
            or getattr(e, "errno", None) == 2
            or isinstance(e, FileNotFoundError)
        )
        if needs_ffmpeg:
            raise RuntimeError(
                "MP4/MP3 conversion requires ffmpeg. "
                "Download from https://ffmpeg.org/download.html, "
                "install it, then restart Phish X. "
                "Alternatively, paste the transcript manually in the box below."
            )
        raise RuntimeError(f"Audio conversion failed: {err}")


def _classify_audio_deepfake(wav_path: str) -> dict:
    """
    Load a WAV file with Librosa, extract MFCC / spectral features, and
    classify it as genuine or AI-generated speech using the ML model.

    Returns a result dict (see ml_models.classify_audio) or an empty dict
    if Librosa / the model is unavailable.
    """
    try:
        import librosa
    except ImportError:
        logger.debug("Librosa not installed - skipping acoustic deepfake analysis.")
        return {}

    try:
        y, sr = librosa.load(wav_path, sr=None, mono=True)
        if len(y) < sr * 0.5:
            return {"label": "unknown", "confidence": 0.5,
                    "risk_level": "low", "note": "Audio too short for reliable classification."}

        from .ml_models import classify_audio
        return classify_audio(y, sr)
    except Exception as e:
        logger.warning("Audio deepfake classification error: %s", e)
        return {}


def _split_long_audio(wav_path: str, chunk_ms: int = 55000) -> list[str]:
    """Split long WAV into chunks to stay within API limits. Returns list of temp WAV paths."""
    try:
        from pydub import AudioSegment
        audio = AudioSegment.from_wav(wav_path)
    except Exception:
        return [wav_path]

    if len(audio) <= chunk_ms:
        return [wav_path]

    chunks = []
    for i, start in enumerate(range(0, len(audio), chunk_ms)):
        chunk = audio[start:start + chunk_ms]
        fd, path = tempfile.mkstemp(suffix=f"_chunk{i}.wav")
        os.close(fd)
        chunk.export(path, format="wav")
        chunks.append(path)
    return chunks


def analyze_audio_file(
    file_bytes: bytes,
    filename: str,
    manual_transcript: str | None = None,
) -> TranscriptResult:
    """
    Transcribe an audio/video file and run vishing detection on the transcript.
    Accepts WAV, MP3, MP4, MOV, AVI, MKV, FLAC, M4A, OGG, AAC, WMA, WEBM.
    If manual_transcript is provided, skips transcription and uses that text.
    """
    ext = Path(filename).suffix.lower()
    warnings: list[str] = []
    tmp_files: list[str] = []

    supported = sorted(ALL_SUPPORTED)

    if manual_transcript and manual_transcript.strip():
        analysis = analyze_vishing_speech(manual_transcript.strip())
        return TranscriptResult(
            filename=filename,
            transcript=manual_transcript.strip(),
            transcript_confidence="manual",
            engine_used="manual input",
            analysis=analysis.model_dump(),
            supported_formats=supported,
        )

    if ext not in ALL_SUPPORTED:
        return TranscriptResult(
            filename=filename,
            transcript="",
            transcript_confidence="low",
            engine_used="none",
            analysis=analyze_vishing_speech("").model_dump(),
            warnings=[
                f"Unsupported file type: {ext}. "
                f"Supported: {', '.join(sorted(ALL_SUPPORTED))}"
            ],
            supported_formats=supported,
        )

    try:
        fd, input_path = tempfile.mkstemp(suffix=ext)
        tmp_files.append(input_path)
        with os.fdopen(fd, "wb") as f:
            f.write(file_bytes)

        if ext in CONVERTIBLE_EXTENSIONS:
            fd2, wav_path = tempfile.mkstemp(suffix=".wav")
            os.close(fd2)
            tmp_files.append(wav_path)
            try:
                _convert_to_wav(input_path, wav_path)
            except RuntimeError as e:
                return TranscriptResult(
                    filename=filename,
                    transcript="",
                    transcript_confidence="low",
                    engine_used="none",
                    analysis=analyze_vishing_speech("").model_dump(),
                    warnings=[str(e)],
                    supported_formats=supported,
                )
        else:
            wav_path = input_path

        chunks = _split_long_audio(wav_path)
        tmp_files.extend([c for c in chunks if c != wav_path and c != input_path])

        transcript_parts = []
        engine = "Google Speech Recognition (free)"
        low_confidence = False

        for chunk_path in chunks:
            try:
                part, conf = _transcribe_wav(chunk_path)
                transcript_parts.append(part)
                if conf == "low":
                    low_confidence = True
            except RuntimeError as e:
                return TranscriptResult(
                    filename=filename,
                    transcript="",
                    transcript_confidence="low",
                    engine_used=engine,
                    analysis=analyze_vishing_speech("").model_dump(),
                    warnings=[str(e)],
                    supported_formats=supported,
                )

        full_transcript = " ".join(t for t in transcript_parts if t).strip()

        if not full_transcript:
            warnings.append("No speech detected in the audio. The audio may be too quiet, noisy, or non-English.")
            warnings.append("Tip: Paste the transcript manually in the text box below.")
            confidence = "low"
        else:
            confidence = "low" if low_confidence else "high"

        analysis = analyze_vishing_speech(full_transcript) if full_transcript else analyze_vishing_speech("")

        deepfake_result = _classify_audio_deepfake(wav_path)

        return TranscriptResult(
            filename=filename,
            transcript=full_transcript,
            transcript_confidence=confidence,
            engine_used=engine,
            analysis=analysis.model_dump(),
            deepfake_analysis=deepfake_result,
            warnings=warnings,
            supported_formats=supported,
        )

    finally:
        for p in tmp_files:
            try:
                os.unlink(p)
            except OSError:
                pass
