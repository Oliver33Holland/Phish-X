"""Campaign management models for Phish X."""

from datetime import datetime, timezone
from enum import Enum
from pydantic import BaseModel, Field


class CampaignStatus(str, Enum):
    DRAFT = "draft"
    SCHEDULED = "scheduled"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"


class TargetEventType(str, Enum):
    EMAIL_SENT = "email_sent"
    EMAIL_OPENED = "email_opened"
    LINK_CLICKED = "link_clicked"
    DATA_SUBMITTED = "data_submitted"
    REPORTED = "reported"


class EmailTemplate(BaseModel):
    id: str
    name: str
    subject: str
    sender_name: str
    sender_email: str
    body_html: str
    landing_page_id: str | None = None
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class LandingPage(BaseModel):
    id: str
    name: str
    page_type: str = Field(description="google | microsoft | office365 | barclays | hsbc | custom")
    redirect_url: str = Field(default="https://www.google.com", description="Where to redirect after submission")
    capture_credentials: bool = True
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class Target(BaseModel):
    id: str
    first_name: str
    last_name: str
    email: str
    department: str | None = None
    position: str | None = None


class CampaignCreate(BaseModel):
    name: str = Field(..., min_length=1)
    description: str | None = None
    template_id: str
    landing_page_id: str | None = None
    targets: list[Target] = Field(default_factory=list)
    send_from_name: str | None = None
    send_from_email: str | None = None
    scheduled_at: str | None = Field(None, description="ISO datetime to auto-launch")


class TargetResult(BaseModel):
    target_id: str
    target_email: str
    target_name: str
    email_sent: bool = False
    email_opened: bool = False
    link_clicked: bool = False
    data_submitted: bool = False
    reported: bool = False
    captured_data: dict | None = None
    events: list[dict] = Field(default_factory=list)


class Campaign(BaseModel):
    id: str
    name: str
    description: str | None = None
    status: CampaignStatus = CampaignStatus.DRAFT
    template_id: str
    landing_page_id: str | None = None
    send_from_name: str = "IT Security Team"
    send_from_email: str = "security@company.com"
    targets: list[Target] = Field(default_factory=list)
    results: list[TargetResult] = Field(default_factory=list)
    scheduled_at: str | None = None
    launched_at: str | None = None
    completed_at: str | None = None
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class CampaignStats(BaseModel):
    campaign_id: str
    campaign_name: str
    status: str
    total_targets: int
    emails_sent: int
    emails_opened: int
    links_clicked: int
    data_submitted: int
    reported: int
    open_rate_pct: float
    click_rate_pct: float
    submit_rate_pct: float
    report_rate_pct: float
