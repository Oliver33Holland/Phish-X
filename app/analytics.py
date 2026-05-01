"""Analytics store: click rates, user performance, risk levels, feedback, game scores."""

import json
import sys
from pathlib import Path
from datetime import datetime, timezone

# In-memory store (with optional JSON persistence)
_storage: dict = {
    "feedback": [],
    "clicks": [],
    "game_scores": [],
    "simulation_views": [],
}

# When frozen (PyInstaller exe), store data next to the exe so it's writable
if getattr(sys, "frozen", False):
    _DATA_FILE = Path(sys.executable).resolve().parent / "data" / "analytics.json"
else:
    _DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "analytics.json"


def _load() -> None:
    """Load persisted data if file exists."""
    if _DATA_FILE.exists():
        try:
            with open(_DATA_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                _storage["feedback"] = data.get("feedback", [])
                _storage["clicks"] = data.get("clicks", [])
                _storage["game_scores"] = data.get("game_scores", [])
                _storage["simulation_views"] = data.get("simulation_views", [])
        except (json.JSONDecodeError, OSError):
            pass


def _save() -> None:
    """Persist data to JSON file."""
    _DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(_DATA_FILE, "w", encoding="utf-8") as f:
            json.dump(_storage, f, indent=2)
    except OSError:
        pass


def record_feedback(simulation_id: str, simulation_type: str, user_acted_safely: bool, reported: bool | None, feedback_notes: str | None) -> None:
    """Record a feedback submission."""
    _load()
    _storage["feedback"].append({
        "simulation_id": simulation_id,
        "simulation_type": simulation_type,
        "user_acted_safely": user_acted_safely,
        "reported": reported,
        "feedback_notes": feedback_notes,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    _save()


def record_click(simulation_id: str, simulation_type: str, clicked_phishing: bool, user_acted_safely: bool) -> None:
    """Record a user click/action (e.g. clicked link = bad, reported = good)."""
    _load()
    _storage["clicks"].append({
        "simulation_id": simulation_id,
        "simulation_type": simulation_type,
        "clicked_phishing": clicked_phishing,
        "user_acted_safely": user_acted_safely,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    _save()


def record_game_score(correct: bool, simulation_id: str, difficulty: str, points: int) -> None:
    """Record a game round result."""
    _load()
    _storage["game_scores"].append({
        "correct": correct,
        "simulation_id": simulation_id,
        "difficulty": difficulty,
        "points": points,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    _save()


def record_simulation_view(simulation_id: str, simulation_type: str) -> None:
    """Record that a user viewed a simulation."""
    _load()
    _storage["simulation_views"].append({
        "simulation_id": simulation_id,
        "simulation_type": simulation_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    _save()


def get_dashboard_analytics() -> dict:
    """Return aggregated dashboard metrics."""
    _load()
    feedback = _storage["feedback"]
    clicks = _storage["clicks"]
    game = _storage["game_scores"]
    views = _storage["simulation_views"]

    total_feedback = len(feedback)
    safe_count = sum(1 for f in feedback if f.get("user_acted_safely"))
    reported_count = sum(1 for f in feedback if f.get("reported"))

    total_clicks = len(clicks)
    clicked_phishing = sum(1 for c in clicks if c.get("clicked_phishing"))

    total_rounds = len(game)
    correct_rounds = sum(1 for g in game if g.get("correct"))
    total_points = sum(g.get("points", 0) for g in game)

    ctr_phishing = (clicked_phishing / total_clicks * 100) if total_clicks else 0
    safe_rate = (safe_count / total_feedback * 100) if total_feedback else 0
    report_rate = (reported_count / total_feedback * 100) if total_feedback else 0
    game_accuracy = (correct_rounds / total_rounds * 100) if total_rounds else 0

    # high click rate = high risk
    if ctr_phishing >= 50 or safe_rate < 50:
        risk_level = "high"
    elif ctr_phishing >= 25 or safe_rate < 75:
        risk_level = "medium"
    else:
        risk_level = "low"

    return {
        "total_simulations_viewed": len(views),
        "total_feedback": total_feedback,
        "total_clicks": total_clicks,
        "total_game_rounds": total_rounds,
        "click_through_rate_phishing_pct": round(ctr_phishing, 1),
        "safe_behavior_rate_pct": round(safe_rate, 1),
        "report_rate_pct": round(report_rate, 1),
        "game_accuracy_pct": round(game_accuracy, 1),
        "game_total_points": total_points,
        "overall_risk_level": risk_level,
    }


def get_feedback_reports() -> list[dict]:
    """Return list of feedback entries for reporting."""
    _load()
    return list(reversed(_storage["feedback"]))
