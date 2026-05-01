"""API routes for phishing simulation and AI detection."""

from fastapi import APIRouter, HTTPException, UploadFile, File, Form
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from .analytics import (
    get_dashboard_analytics,
    get_feedback_reports,
    record_click,
    record_feedback,
    record_game_score,
    record_simulation_view,
)
from .detection import analyze_vishing_speech
from .models import (
    DetectionRequest,
    SimulationSummary,
    UserResponse,
)
from .campaign_manager import (
    complete_campaign, create_campaign, create_template, delete_campaign,
    delete_template, get_campaign, get_campaign_stats, get_template,
    import_targets_csv, launch_campaign, list_campaigns, list_templates,
    pause_campaign, record_event, schedule_campaign,
)
from .campaign_models import CampaignCreate
from .fakepage import build_fake_page, list_page_templates
from .generator import GenerateRequest, generate_phishing_email, list_malware_types
from .voice_analyzer import analyze_audio_file
from .simulation import (
    analyze_text_for_ai_phishing,
    get_random_game_email,
    get_simulated_email_by_id,
    get_simulated_emails,
    get_random_simulated_email,
    get_vishing_scenarios,
)

router = APIRouter(prefix="/api", tags=["phishing"])


class VishingDetectRequest(BaseModel):
    """Request to analyze speech/transcript for vishing patterns."""
    text: str = Field(..., min_length=5)


class ClickRecordRequest(BaseModel):
    """Record a user click/action (e.g. clicked link = bad)."""
    simulation_id: str
    simulation_type: str
    clicked_phishing: bool
    user_acted_safely: bool


class GameScoreRequest(BaseModel):
    """Record a game round result."""
    correct: bool
    simulation_id: str
    difficulty: str
    points: int


@router.get("/")
def api_root():
    """API info."""
    return {
        "name": "Phish X API",
        "version": "1.0",
        "endpoints": {
            "simulations": "/api/simulations",
            "emails": "/api/simulations/emails",
            "emails_random": "/api/simulations/emails/random",
            "email_by_id": "/api/simulations/emails/{email_id}",
            "vishing": "/api/simulations/vishing",
            "game_random": "/api/game/random",
            "detect": "POST /api/detect",
            "detect_vishing": "POST /api/detect/vishing",
            "feedback": "POST /api/feedback",
            "analytics_dashboard": "/api/analytics/dashboard",
            "reports_feedback": "/api/reports/feedback",
        },
    }


@router.get("/simulations", response_model=SimulationSummary)
def list_simulations():
    """List available simulation categories and counts."""
    emails = get_simulated_emails()
    vishing = get_vishing_scenarios()
    return SimulationSummary(
        total_emails=len(emails),
        total_vishing=len(vishing),
        categories=["email", "vishing"],
    )


@router.get("/simulations/emails")
def list_simulated_emails():
    """List all simulated phishing emails (ids and metadata only)."""
    emails = get_simulated_emails()
    return [
        {
            "id": e.id,
            "subject": e.subject,
            "sender": e.sender,
            "difficulty": e.difficulty,
        }
        for e in emails
    ]


@router.get("/simulations/emails/random")
def get_random_email():
    """Get one random simulated phishing email for quick training."""
    return get_random_simulated_email()


@router.get("/simulations/emails/{email_id}")
def get_email(email_id: str):
    """Get a specific simulated phishing email by id."""
    email = get_simulated_email_by_id(email_id)
    if not email:
        raise HTTPException(status_code=404, detail="Simulated email not found")
    return email


@router.get("/simulations/vishing")
def list_vishing_scenarios():
    """List all vishing (voice phishing) training scenarios."""
    return get_vishing_scenarios()


@router.post("/detect")
def detect_ai_phishing(request: DetectionRequest):
    """
    Analyze an email for phishing indicators.

    Pass raw_email (full source headers + body) for deep header analysis including
    SPF/DKIM/DMARC checks, domain spoofing, and Reply-To mismatches.
    Alternatively pass plain text in the text field for basic content analysis.
    """
    return analyze_text_for_ai_phishing(
        text=request.text or "",
        context=request.context,
        raw_email=request.raw_email,
    )


@router.post("/detect/vishing")
def detect_vishing(request: VishingDetectRequest):
    """
    Analyze transcribed speech/call text for suspicious vishing patterns.
    Use on text that represents what a caller said (e.g. from speech-to-text).
    """
    return analyze_vishing_speech(text=request.text)


@router.post("/feedback")
def submit_feedback(response: UserResponse):
    """
    Submit user response to a simulation (for training metrics).
    Persisted for reporting and analytics.
    """
    record_feedback(
        simulation_id=response.simulation_id,
        simulation_type=response.simulation_type.value,
        user_acted_safely=response.user_acted_safely,
        reported=response.reported,
        feedback_notes=response.feedback_notes,
    )
    return {
        "received": True,
        "simulation_id": response.simulation_id,
        "simulation_type": response.simulation_type.value,
        "user_acted_safely": response.user_acted_safely,
        "reported": response.reported,
        "message": "Thank you for helping improve security awareness.",
    }


@router.post("/analytics/click")
def record_user_click(req: ClickRecordRequest):
    """Record a user click/action (for click-through and performance analytics)."""
    record_click(
        simulation_id=req.simulation_id,
        simulation_type=req.simulation_type,
        clicked_phishing=req.clicked_phishing,
        user_acted_safely=req.user_acted_safely,
    )
    return {"recorded": True}


@router.post("/analytics/view")
def record_view(simulation_id: str = "", simulation_type: str = "email"):
    """Record that a user viewed a simulation (query params: simulation_id, simulation_type)."""
    record_simulation_view(simulation_id=simulation_id, simulation_type=simulation_type)
    return {"recorded": True}


@router.get("/analytics/dashboard")
def analytics_dashboard():
    """Dashboard metrics: click rates, user performance, risk levels."""
    return get_dashboard_analytics()


@router.get("/reports/feedback")
def reports_feedback():
    """List feedback submissions for reporting."""
    return {"entries": get_feedback_reports()}


@router.get("/game/random")
def game_random_email():
    """Get one random email for the mini game (phishing or legitimate)."""
    return get_random_game_email()


@router.post("/game/score")
def game_record_score(req: GameScoreRequest):
    """Record a game round result (correct/incorrect, points)."""
    record_game_score(
        correct=req.correct,
        simulation_id=req.simulation_id,
        difficulty=req.difficulty,
        points=req.points,
    )
    return {"recorded": True, "points": req.points}



@router.get("/generator/malware-types")
def get_malware_types():
    """List all available simulated malware payload types."""
    return list_malware_types()


@router.post("/generator/generate")
def generate_email(request: GenerateRequest):
    """
    Generate a simulated phishing email with a malware payload breakdown.
    FOR SECURITY AWARENESS TRAINING ONLY. No real malware is created.
    """
    return generate_phishing_email(request)



@router.get("/fakepage/templates")
def get_fakepage_templates():
    """List all available fake login page templates."""
    return list_page_templates()


@router.get("/fakepage/view/{page_id}", response_class=HTMLResponse)
def view_fake_page(page_id: str, spoofed_url: str | None = None):
    """
    Render a simulated fake login page for training.
    FOR SECURITY AWARENESS TRAINING ONLY.
    The page displays a visible training banner and captures no credentials.
    """
    html = build_fake_page(page_id, spoofed_url)
    if not html:
        raise HTTPException(status_code=404, detail=f"No template for page_id '{page_id}'")
    return HTMLResponse(content=html)



@router.post("/voice-analyze")
async def voice_analyze(
    file: UploadFile = File(None),
    manual_transcript: str = Form(default=""),
):
    """
    Upload an audio or video file to transcribe and analyse for vishing patterns.
    Supported: WAV, MP3, MP4, MOV, AVI, MKV, FLAC, M4A, OGG, AAC, WMA, WEBM, 3GP.
    Alternatively, provide a manual_transcript to skip transcription.
    """
    filename = ""
    file_bytes = b""

    if file and file.filename:
        filename = file.filename
        file_bytes = await file.read()

    return analyze_audio_file(
        file_bytes=file_bytes,
        filename=filename or "unknown",
        manual_transcript=manual_transcript or None,
    )



class EventRequest(BaseModel):
    target_id: str
    event_type: str
    data: dict | None = None


class ScheduleRequest(BaseModel):
    scheduled_at: str


@router.get("/campaigns")
def api_list_campaigns():
    return list_campaigns()


@router.post("/campaigns")
def api_create_campaign(data: CampaignCreate):
    return create_campaign(data)


@router.get("/campaigns/{campaign_id}")
def api_get_campaign(campaign_id: str):
    c = get_campaign(campaign_id)
    if not c:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return c


@router.delete("/campaigns/{campaign_id}")
def api_delete_campaign(campaign_id: str):
    if not delete_campaign(campaign_id):
        raise HTTPException(status_code=404, detail="Campaign not found")
    return {"deleted": True}


@router.post("/campaigns/{campaign_id}/launch")
def api_launch_campaign(campaign_id: str):
    c = launch_campaign(campaign_id)
    if not c:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return c


@router.post("/campaigns/{campaign_id}/pause")
def api_pause_campaign(campaign_id: str):
    c = pause_campaign(campaign_id)
    if not c:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return c


@router.post("/campaigns/{campaign_id}/complete")
def api_complete_campaign(campaign_id: str):
    c = complete_campaign(campaign_id)
    if not c:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return c


@router.post("/campaigns/{campaign_id}/schedule")
def api_schedule_campaign(campaign_id: str, req: ScheduleRequest):
    c = schedule_campaign(campaign_id, req.scheduled_at)
    if not c:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return c


@router.get("/campaigns/{campaign_id}/stats")
def api_campaign_stats(campaign_id: str):
    s = get_campaign_stats(campaign_id)
    if not s:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return s


@router.post("/campaigns/{campaign_id}/event")
def api_record_event(campaign_id: str, req: EventRequest):
    ok = record_event(campaign_id, req.target_id, req.event_type, req.data)
    if not ok:
        raise HTTPException(status_code=404, detail="Campaign or target not found")
    return {"recorded": True}


@router.post("/campaigns/{campaign_id}/import-csv")
async def api_import_csv(campaign_id: str, file: UploadFile = File(...)):
    c = get_campaign(campaign_id)
    if not c:
        raise HTTPException(status_code=404, detail="Campaign not found")
    csv_bytes = await file.read()
    targets = import_targets_csv(csv_bytes)
    if not targets:
        raise HTTPException(status_code=400, detail="No valid targets found in CSV. Expected columns: first_name, last_name, email")
    from .campaign_manager import _store, _save, _lock, _load
    added: list[dict] = []
    with _lock:
        _load()
        cc = _store["campaigns"].get(campaign_id)
        if not cc:
            raise HTTPException(status_code=404, detail="Campaign not found")
        existing_emails = {t["email"] for t in cc["targets"]}
        for t in targets:
            if t["email"] not in existing_emails:
                cc["targets"].append(t)
                cc["results"].append({
                    "target_id": t["id"],
                    "target_email": t["email"],
                    "target_name": f"{t['first_name']} {t['last_name']}",
                    "email_sent": False, "email_opened": False,
                    "link_clicked": False, "data_submitted": False,
                    "reported": False, "captured_data": None, "events": [],
                })
                added.append(t)
        _save()
    return {"added": len(added), "targets": added}


# Email templates
@router.get("/campaign-templates")
def api_list_templates():
    return list_templates()


@router.post("/campaign-templates")
def api_create_template(data: dict):
    return create_template(data)


@router.get("/campaign-templates/{template_id}")
def api_get_template(template_id: str):
    t = get_template(template_id)
    if not t:
        raise HTTPException(status_code=404, detail="Template not found")
    return t


@router.delete("/campaign-templates/{template_id}")
def api_delete_template(template_id: str):
    if not delete_template(template_id):
        raise HTTPException(status_code=404, detail="Template not found")
    return {"deleted": True}


