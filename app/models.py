"""Pydantic models for phishing simulation and AI detection."""

from enum import Enum
from pydantic import BaseModel, Field


class PhishingCategory(str, Enum):
    """Type of phishing attempt."""
    EMAIL = "email"
    VISHING = "vishing"


class SimulatedEmail(BaseModel):
    """A simulated phishing email for training."""
    id: str
    subject: str
    sender: str
    body: str
    brand: str = Field(default="Generic", description="Brand being spoofed (e.g. Microsoft Teams, Zoom)")
    category: PhishingCategory = PhishingCategory.EMAIL
    difficulty: str = Field(description="easy | medium | hard")
    red_flags: list[str] = Field(default_factory=list, description="Indicators this is phishing")
    is_phishing: bool = True


class DetectionRequest(BaseModel):
    """Request to analyze text or raw email source for phishing indicators."""
    text: str = Field(default="", description="Plain message text (used when raw_email is not provided)")
    context: str | None = Field(None, description="Optional: subject line or sender context")
    raw_email: str | None = Field(None, description="Full raw email source (headers + body) for deep analysis")


class DetectionResult(BaseModel):
    """Result of AI-phishing detection analysis."""
    is_likely_phishing: bool
    confidence: float = Field(ge=0, le=1)
    ai_generated_indicators: list[str] = Field(default_factory=list)
    red_flags: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    risk_level: str = Field(description="low | medium | high | critical")
    header_findings: list[str] = Field(default_factory=list, description="Issues found in email headers")
    extracted_headers: dict = Field(default_factory=dict, description="Key header values shown to the user")
    ml_scores: dict = Field(default_factory=dict, description="ML model scores: nb_confidence, rf_confidence, ensemble_score")


class VishingScenario(BaseModel):
    """A simulated vishing (voice phishing) scenario for training."""
    id: str
    title: str
    scenario: str = Field(description="Script/situation description")
    caller_pretext: str = Field(description="Who the caller claims to be")
    objective: str = Field(description="What the attacker is trying to get")
    red_flags: list[str] = Field(default_factory=list)
    correct_response: str = Field(description="Recommended response/behavior")
    difficulty: str = "medium"


class UserResponse(BaseModel):
    """User's response to a simulation (for training feedback)."""
    simulation_id: str
    simulation_type: PhishingCategory
    user_acted_safely: bool = Field(description="Did the user avoid the trap?")
    reported: bool | None = Field(None, description="Did they report it?")
    feedback_notes: str | None = None


class SimulationSummary(BaseModel):
    """Summary of available simulations for dashboard."""
    total_emails: int
    total_vishing: int
    categories: list[str]
