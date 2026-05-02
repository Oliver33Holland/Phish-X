"""
Campaign Manager - Phish X
Handles campaign CRUD, target management, scheduling, event tracking,
credential capture simulation, and real-time stats.
All emails are SIMULATED (not actually sent). For security training only.
"""

import csv
import io
import json
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .campaign_models import (
    Campaign,
    CampaignCreate,
    CampaignStats,
    CampaignStatus,
    EmailTemplate,
    LandingPage,
    Target,
    TargetEventType,
    TargetResult,
)

# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

if getattr(sys, "frozen", False):
    _DATA_DIR = Path(sys.executable).resolve().parent / "data"
else:
    _DATA_DIR = Path(__file__).resolve().parent.parent / "data"

_CAMPAIGNS_FILE = _DATA_DIR / "campaigns.json"
_TEMPLATES_FILE = _DATA_DIR / "email_templates.json"

_store: dict = {"campaigns": {}, "templates": {}, "landing_pages": {}}
_lock = threading.Lock()


def _load():
    for filepath, key in [(_CAMPAIGNS_FILE, "campaigns"), (_TEMPLATES_FILE, "templates")]:
        if filepath.exists():
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    _store[key] = json.load(f)
            except (json.JSONDecodeError, OSError):
                pass


def _save():
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    for filepath, key in [(_CAMPAIGNS_FILE, "campaigns"), (_TEMPLATES_FILE, "templates")]:
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(_store[key], f, indent=2)
        except OSError:
            pass


_load()

# ---------------------------------------------------------------------------
# Seed default email templates
# ---------------------------------------------------------------------------

_DEFAULT_TEMPLATES = [
    {
        "id": "tpl_account_verify",
        "name": "Account Verification",
        "subject": "Urgent: Verify your account within 24 hours",
        "sender_name": "IT Security",
        "sender_email": "security@it-helpdesk-portal.com",
        "body_html": """<p>Dear {first_name},</p>
<p>We have detected unusual activity on your account. Please verify your identity within 24 hours to prevent suspension.</p>
<p><a href="{phish_link}" style="background:#1a73e8;color:white;padding:10px 20px;text-decoration:none;border-radius:4px;">Verify My Account</a></p>
<p>If you did not initiate this, contact IT support immediately.</p>
<p>Regards,<br/>IT Security Team</p>""",
    },
    {
        "id": "tpl_invoice",
        "name": "Invoice / Finance Lure",
        "subject": "Invoice #{invoice_num} requires your approval",
        "sender_name": "Accounts Payable",
        "sender_email": "billing@finance-invoices-portal.com",
        "body_html": """<p>Hello {first_name},</p>
<p>An invoice requires your immediate approval. Please review and approve by end of business today.</p>
<p><a href="{phish_link}" style="background:#0078d4;color:white;padding:10px 20px;text-decoration:none;border-radius:4px;">View Invoice</a></p>
<p>Regards,<br/>Finance Team</p>""",
    },
    {
        "id": "tpl_password_reset",
        "name": "Password Expiry",
        "subject": "Your password expires in 24 hours - action required",
        "sender_name": "IT Helpdesk",
        "sender_email": "helpdesk@company-it-portal.net",
        "body_html": """<p>Hi {first_name},</p>
<p>Your corporate password will expire in 24 hours. Please reset it now to avoid being locked out.</p>
<p><a href="{phish_link}" style="background:#d32f2f;color:white;padding:10px 20px;text-decoration:none;border-radius:4px;">Reset Password Now</a></p>
<p>IT Helpdesk</p>""",
    },
    {
        "id": "tpl_shared_doc",
        "name": "Shared Document",
        "subject": "{sender_name} shared a document with you",
        "sender_name": "OneDrive Notifications",
        "sender_email": "no-reply@sharepoint-notifications.com",
        "body_html": """<p>Hi {first_name},</p>
<p>A document has been shared with you. Click below to view it.</p>
<p><a href="{phish_link}" style="background:#217346;color:white;padding:10px 20px;text-decoration:none;border-radius:4px;">Open Document</a></p>
<p>Microsoft OneDrive</p>""",
    },
    {
        "id": "tpl_ceo_fraud",
        "name": "CEO / Executive Fraud",
        "subject": "Confidential - urgent request from {ceo_name}",
        "sender_name": "Executive Office",
        "sender_email": "ceo@company-executive-office.com",
        "body_html": """<p>Hi {first_name},</p>
<p>I need you to action this urgently and confidentially. Please review the attached brief and confirm via the secure portal below.</p>
<p><a href="{phish_link}" style="background:#333;color:white;padding:10px 20px;text-decoration:none;border-radius:4px;">Access Secure Portal</a></p>
<p>Please do not discuss this with colleagues. Thank you.</p>""",
    },
]

# LinkSec brand templates seeded as campaign email templates
# Source: https://github.com/LinkSec/phishing-templates
_LINKSEC_CAMPAIGN_TEMPLATES = [
    {
        "id": "tpl_ls_aws_verify",
        "name": "[AWS] Account Verification",
        "brand": "Amazon Web Services",
        "subject": "AWS Account Verification Request",
        "sender_name": "Amazon Web Services Security",
        "sender_email": "no-reply@account-verify-aws.com",
        "body_html": """<p>Dear {first_name} {last_name},</p>
<p>We have detected unusual login activity on your AWS account. To ensure the security of your account and avoid service disruption, we require you to verify your identity immediately.</p>
<p><a href="{phish_link}" style="background:#ff9900;color:white;padding:10px 20px;text-decoration:none;border-radius:4px;">Verify AWS Account</a></p>
<p>If you do not verify within 24 hours, your AWS account may be temporarily suspended.</p>
<p>Best regards,<br/>Amazon Web Services Security Team</p>""",
    },
    {
        "id": "tpl_ls_aws_giftcard",
        "name": "[AWS] Gift Card Reward Lure",
        "brand": "Amazon Web Services",
        "subject": "Exclusive: $100 Amazon Gift Card - Claim Now",
        "sender_name": "AWS Rewards Team",
        "sender_email": "rewards@aws-exclusive-offers.com",
        "body_html": """<p>Dear {first_name},</p>
<p>Congratulations! As a valued AWS customer, you have been selected to receive an exclusive $100 Amazon Gift Card.</p>
<p><a href="{phish_link}" style="background:#ff9900;color:white;padding:10px 20px;text-decoration:none;border-radius:4px;">Claim Your Reward</a></p>
<p>This offer expires in 48 hours. Act now to secure your reward.</p>
<p>Best regards,<br/>AWS Rewards Team</p>""",
    },
    {
        "id": "tpl_ls_zoom_verify",
        "name": "[Zoom] Account Security Alert",
        "brand": "Zoom",
        "subject": "Urgent Zoom Account Security Alert",
        "sender_name": "Zoom Security Team",
        "sender_email": "security@zoom-security-alert.net",
        "body_html": """<p>Dear {first_name},</p>
<p>We have detected unusual activity on your Zoom account. To protect your account and prevent unauthorised access to your meetings, please verify your identity immediately.</p>
<p><a href="{phish_link}" style="background:#2d8cff;color:white;padding:10px 20px;text-decoration:none;border-radius:4px;">Verify Zoom Account</a></p>
<p>If you do not verify within 24 hours, your Zoom account will be temporarily suspended.</p>
<p>Best regards,<br/>Zoom Security Team</p>""",
    },
    {
        "id": "tpl_ls_zoom_update",
        "name": "[Zoom] Terms of Service Update",
        "brand": "Zoom",
        "subject": "Urgent: Your Zoom Account Update Required",
        "sender_name": "Zoom Account Team",
        "sender_email": "no-reply@zoom-account-update.com",
        "body_html": """<p>Dear {first_name} {last_name},</p>
<p>Your Zoom account requires an important update to comply with our latest terms of service. Failure to update may result in loss of access to your Zoom meetings.</p>
<p><a href="{phish_link}" style="background:#2d8cff;color:white;padding:10px 20px;text-decoration:none;border-radius:4px;">Update Zoom Account</a></p>
<p>This update must be completed within 24 hours.</p>
<p>Best regards,<br/>Zoom Account Team</p>""",
    },
    {
        "id": "tpl_ls_teams_verify",
        "name": "[Microsoft Teams] Account Verification",
        "brand": "Microsoft Teams",
        "subject": "Urgent: Verify Your Microsoft Teams Account",
        "sender_name": "Microsoft Teams Security Team",
        "sender_email": "security@teams-account-verify.com",
        "body_html": """<p>Dear {first_name},</p>
<p>This is an important notification concerning your Microsoft Teams account. Due to recent updates in our system, we require you to verify your account within the next 24 hours to prevent suspension.</p>
<ul>
<li>Ensures continuous access to all Microsoft Teams features</li>
<li>Protects your account from potential security threats</li>
<li>Keeps your data secure</li>
</ul>
<p><a href="{phish_link}" style="background:#6264a7;color:white;padding:10px 20px;text-decoration:none;border-radius:4px;">Verify Teams Account</a></p>
<p>Best regards,<br/>Microsoft Teams Security Team</p>""",
    },
    {
        "id": "tpl_ls_teams_upgrade",
        "name": "[Microsoft Teams] Free Upgrade Offer",
        "brand": "Microsoft Teams",
        "subject": "Microsoft Teams Free Upgrade Offer",
        "sender_name": "Microsoft Teams Promotions",
        "sender_email": "promotions@teams-free-upgrade.net",
        "body_html": """<p>Dear {first_name} {last_name},</p>
<p>Congratulations! You have been selected to receive a free Microsoft Teams Essentials upgrade for 90 days.</p>
<p><a href="{phish_link}" style="background:#6264a7;color:white;padding:10px 20px;text-decoration:none;border-radius:4px;">Activate Free Upgrade</a></p>
<p>Do not miss this limited time offer - it expires in 72 hours.</p>
<p>Best regards,<br/>Microsoft Teams Promotions</p>""",
    },
    {
        "id": "tpl_ls_o365_verify",
        "name": "[Microsoft 365] Account Verification Notice",
        "brand": "Microsoft Office 365",
        "subject": "Urgent: Microsoft 365 Account Verification Notice",
        "sender_name": "Microsoft 365 Security Team",
        "sender_email": "security@office365-account-verify.net",
        "body_html": """<p>Dear {first_name} {last_name},</p>
<p>We have detected unusual activity on your Microsoft 365 account. To ensure the security of your emails, documents, and data, we require you to verify your account immediately.</p>
<p><a href="{phish_link}" style="background:#0078d4;color:white;padding:10px 20px;text-decoration:none;border-radius:4px;">Verify Microsoft 365 Account</a></p>
<p>Failure to verify within 24 hours will result in suspension of your Microsoft 365 services including Outlook, Teams, and SharePoint.</p>
<p>Best regards,<br/>Microsoft 365 Security Team</p>""",
    },
    {
        "id": "tpl_ls_o365_reward",
        "name": "[Microsoft 365] Exclusive Reward Offer",
        "brand": "Microsoft Office 365",
        "subject": "Exclusive Reward - Microsoft Office 365",
        "sender_name": "Microsoft 365 Rewards Team",
        "sender_email": "rewards@office365-exclusive-rewards.com",
        "body_html": """<p>Dear {first_name},</p>
<p>You have been selected to receive an exclusive Microsoft 365 reward. As one of our valued customers, you are eligible for a free 3-month Microsoft 365 Business Premium subscription.</p>
<p><a href="{phish_link}" style="background:#0078d4;color:white;padding:10px 20px;text-decoration:none;border-radius:4px;">Claim Your Reward</a></p>
<p>This offer expires in 48 hours.</p>
<p>Best regards,<br/>Microsoft 365 Rewards Team</p>""",
    },
    {
        "id": "tpl_ls_azure_verify",
        "name": "[Microsoft Azure] Account Verification",
        "brand": "Microsoft Azure",
        "subject": "Urgent Azure Account Verification Request",
        "sender_name": "Microsoft Azure Security Team",
        "sender_email": "no-reply@azure-account-verify.com",
        "body_html": """<p>Dear {first_name},</p>
<p>We have detected suspicious sign-in attempts on your Microsoft Azure account. To protect your Azure resources and subscriptions, please verify your identity immediately.</p>
<p><a href="{phish_link}" style="background:#0089d6;color:white;padding:10px 20px;text-decoration:none;border-radius:4px;">Verify Azure Account</a></p>
<p>If you do not verify within 12 hours, access to your Azure portal will be restricted.</p>
<p>Best regards,<br/>Microsoft Azure Security Team</p>""",
    },
    {
        "id": "tpl_ls_gworkspace_verify",
        "name": "[Google Workspace] Account Verification",
        "brand": "Google Workspace",
        "subject": "Urgent: Verify Your Google Workspace Account",
        "sender_name": "Google Workspace Security Team",
        "sender_email": "security@google-workspace-verify.net",
        "body_html": """<p>Dear {first_name} {last_name},</p>
<p>We have detected unusual activity on your Google Workspace account. To protect your organisation's data, you must verify your account immediately.</p>
<p><a href="{phish_link}" style="background:#1a73e8;color:white;padding:10px 20px;text-decoration:none;border-radius:4px;">Verify Google Workspace Account</a></p>
<p>You must complete this verification within 24 hours to avoid account suspension.</p>
<p>Best regards,<br/>Google Workspace Security Team</p>""",
    },
    {
        "id": "tpl_ls_gworkspace_storage",
        "name": "[Google Workspace] Storage Alert",
        "brand": "Google Workspace",
        "subject": "Urgent: Google Workspace Storage Alert",
        "sender_name": "Google Workspace Team",
        "sender_email": "alerts@google-workspace-storage-alert.com",
        "body_html": """<p>Dear {first_name},</p>
<p>Your Google Workspace storage is almost full. If you do not take action immediately, you will lose access to Gmail, Drive, and other Google services.</p>
<p><a href="{phish_link}" style="background:#1a73e8;color:white;padding:10px 20px;text-decoration:none;border-radius:4px;">Upgrade Storage Now</a></p>
<p>Act now to prevent data loss.</p>
<p>Best regards,<br/>Google Workspace Team</p>""",
    },
    {
        "id": "tpl_ls_gcp_alert",
        "name": "[Google Cloud] GCP Service Alert",
        "brand": "Google Cloud Platform",
        "subject": "Urgent: Verify Your GCP Subscription Now",
        "sender_name": "Google Cloud Platform Support Team",
        "sender_email": "subscriptions@gcp-verify-now.com",
        "body_html": """<p>Dear {first_name} {last_name},</p>
<p>We are writing to inform you of an urgent matter regarding your Google Cloud Platform (GCP) subscription. Our records indicate that there is an issue that requires your immediate attention to ensure continuous service.</p>
<p><a href="{phish_link}" style="background:#4285f4;color:white;padding:10px 20px;text-decoration:none;border-radius:4px;">Verify Your Subscription</a></p>
<p style="color:#ff0000;">Failure to address this issue within the next 24 hours will result in a temporary suspension of your GCP services.</p>
<p>Best regards,<br/>Google Cloud Platform Support Team</p>""",
    },
    {
        "id": "tpl_ls_slack_verify",
        "name": "[Slack] Account Verification",
        "brand": "Slack",
        "subject": "Urgent: Verify Your Slack Account",
        "sender_name": "Slack Security Team",
        "sender_email": "no-reply@slack-account-verify.com",
        "body_html": """<p>Dear {first_name},</p>
<p>Due to recent updates to our security infrastructure, all Slack users are required to re-verify their accounts. This is mandatory to maintain uninterrupted access to your Slack workspaces.</p>
<p><a href="{phish_link}" style="background:#4a154b;color:white;padding:10px 20px;text-decoration:none;border-radius:4px;">Verify Slack Account</a></p>
<p>You must complete this verification within 24 hours. Failure to do so will result in loss of access to your Slack workspaces.</p>
<p>Best regards,<br/>Slack Security Team</p>""",
    },
    {
        "id": "tpl_ls_slack_giftcard",
        "name": "[Slack] Gift Card Reward Lure",
        "brand": "Slack",
        "subject": "You've Received a Gift Card - Slack",
        "sender_name": "Slack Team",
        "sender_email": "gifts@slack-gift-card-offer.com",
        "body_html": """<p>Dear {first_name},</p>
<p>Great news! You have been selected to receive a $50 gift card as part of our appreciation programme for valued Slack customers.</p>
<p><a href="{phish_link}" style="background:#4a154b;color:white;padding:10px 20px;text-decoration:none;border-radius:4px;">Claim Gift Card</a></p>
<p>This offer is only valid for 48 hours.</p>
<p>Best regards,<br/>Slack Team</p>""",
    },
    {
        "id": "tpl_ls_cisco_webex_verify",
        "name": "[Cisco Webex] Account Verification",
        "brand": "Cisco Webex",
        "subject": "Urgent Webex Account Verification Request",
        "sender_name": "Cisco Webex Security Team",
        "sender_email": "no-reply@webex-account-verify.net",
        "body_html": """<p>Dear {first_name},</p>
<p>Due to recent changes in our security policies, all Webex users are required to re-verify their accounts. This is a mandatory step to maintain access to your Webex services.</p>
<p><a href="{phish_link}" style="background:#00bceb;color:white;padding:10px 20px;text-decoration:none;border-radius:4px;">Verify Webex Account</a></p>
<p>Failure to complete this verification will result in restricted access to your Webex account.</p>
<p>Best regards,<br/>Cisco Webex Security Team</p>""",
    },
    {
        "id": "tpl_ls_ringcentral_alert",
        "name": "[RingCentral] Account Security Alert",
        "brand": "RingCentral",
        "subject": "Urgent RingCentral Account Security Alert",
        "sender_name": "RingCentral Security Team",
        "sender_email": "security@ringcentral-security-alerts.com",
        "body_html": """<p>Dear {first_name} {last_name},</p>
<p>We have detected suspicious activity on your RingCentral account. Your account may be at risk of unauthorised access. Please verify your identity immediately to secure your account.</p>
<p><a href="{phish_link}" style="background:#f60;color:white;padding:10px 20px;text-decoration:none;border-radius:4px;">Verify RingCentral Account</a></p>
<p>Failure to verify within 24 hours will result in your account being locked.</p>
<p>Best regards,<br/>RingCentral Security Team</p>""",
    },
    {
        "id": "tpl_ls_ibmcloud_verify",
        "name": "[IBM Cloud] Account Verification",
        "brand": "IBM Cloud",
        "subject": "Urgent IBM Cloud Account Verification Request",
        "sender_name": "IBM Cloud Security Team",
        "sender_email": "security@ibmcloud-account-verify.com",
        "body_html": """<p>Dear {first_name} {last_name},</p>
<p>We have detected unusual access patterns on your IBM Cloud account. To prevent unauthorised access to your cloud resources, please verify your identity immediately.</p>
<p><a href="{phish_link}" style="background:#054ada;color:white;padding:10px 20px;text-decoration:none;border-radius:4px;">Verify IBM Cloud Account</a></p>
<p>Failure to verify within 24 hours will result in temporary suspension of your IBM Cloud services.</p>
<p>Best regards,<br/>IBM Cloud Security Team</p>""",
    },
    {
        "id": "tpl_ls_oracle_cloud_update",
        "name": "[Oracle Cloud] Account Update Request",
        "brand": "Oracle Cloud",
        "subject": "Urgent Oracle Cloud Account Update Request",
        "sender_name": "Oracle Cloud Security Team",
        "sender_email": "no-reply@oracle-cloud-update.net",
        "body_html": """<p>Dear {first_name} {last_name},</p>
<p>We have detected unusual activity on your Oracle Cloud account. To ensure the continued security of your data and cloud services, we require you to update your account information immediately.</p>
<p><a href="{phish_link}" style="background:#f80000;color:white;padding:10px 20px;text-decoration:none;border-radius:4px;">Update Oracle Cloud Account</a></p>
<p>You must complete this update within 24 hours to avoid service interruption.</p>
<p>Best regards,<br/>Oracle Cloud Security Team</p>""",
    },
    {
        "id": "tpl_ls_skype_password",
        "name": "[Skype] Password Reset Reminder",
        "brand": "Skype for Business",
        "subject": "Urgent: Skype Password Reset Reminder",
        "sender_name": "Skype for Business Security Team",
        "sender_email": "security@skype-password-reset-notice.com",
        "body_html": """<p>Dear {first_name},</p>
<p>Our security systems have flagged your Skype for Business account for a mandatory password reset. This is required to comply with your organisation's new security policy.</p>
<p><a href="{phish_link}" style="background:#00aff0;color:white;padding:10px 20px;text-decoration:none;border-radius:4px;">Reset Skype Password</a></p>
<p>Your account will be locked if the password reset is not completed within 12 hours.</p>
<p>Best regards,<br/>Skype for Business Security Team</p>""",
    },
    {
        "id": "tpl_ls_gotomeeting_alert",
        "name": "[GoToMeeting] Urgent Security Update",
        "brand": "GoToMeeting",
        "subject": "Urgent Security Update for GoToMeeting",
        "sender_name": "GoToMeeting Security Team",
        "sender_email": "security@gotomeeting-security-update.com",
        "body_html": """<p>Dear {first_name},</p>
<p>A critical security update is required for your GoToMeeting account. Our systems have identified a vulnerability that could expose your meeting data to unauthorised parties.</p>
<p><a href="{phish_link}" style="background:#f68d2e;color:white;padding:10px 20px;text-decoration:none;border-radius:4px;">Apply Security Update</a></p>
<p>You must apply this update within 12 hours to protect your account.</p>
<p>Best regards,<br/>GoToMeeting Security Team</p>""",
    },
]

for _t in _DEFAULT_TEMPLATES + _LINKSEC_CAMPAIGN_TEMPLATES:
    if _t["id"] not in _store["templates"]:
        _store["templates"][_t["id"]] = _t
_save()


# ---------------------------------------------------------------------------
# Template CRUD
# ---------------------------------------------------------------------------

def list_templates() -> list[dict]:
    _load()
    return list(_store["templates"].values())


def get_template(template_id: str) -> dict | None:
    _load()
    return _store["templates"].get(template_id)


def create_template(data: dict) -> dict:
    with _lock:
        _load()
        tid = "tpl_" + uuid.uuid4().hex[:12]
        data["id"] = tid
        data.setdefault("created_at", datetime.now(timezone.utc).isoformat())
        _store["templates"][tid] = data
        _save()
    return data


def delete_template(template_id: str) -> bool:
    with _lock:
        _load()
        if template_id in _store["templates"]:
            del _store["templates"][template_id]
            _save()
            return True
    return False


# ---------------------------------------------------------------------------
# Campaign CRUD
# ---------------------------------------------------------------------------

def _make_id(prefix: str = "cmp") -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def _make_target_id() -> str:
    return "tgt_" + uuid.uuid4().hex[:10]


def list_campaigns() -> list[dict]:
    _load()
    return sorted(_store["campaigns"].values(), key=lambda c: c.get("created_at", ""), reverse=True)


def get_campaign(campaign_id: str) -> dict | None:
    _load()
    return _store["campaigns"].get(campaign_id)


def create_campaign(data: CampaignCreate) -> dict:
    with _lock:
        _load()
        cid = _make_id()
        targets = []
        for t in data.targets:
            td = t.model_dump()
            if not td.get("id"):
                td["id"] = _make_target_id()
            targets.append(td)

        results = [
            {
                "target_id": t["id"],
                "target_email": t["email"],
                "target_name": f"{t['first_name']} {t['last_name']}",
                "email_sent": False,
                "email_opened": False,
                "link_clicked": False,
                "data_submitted": False,
                "reported": False,
                "captured_data": None,
                "events": [],
            }
            for t in targets
        ]

        campaign = {
            "id": cid,
            "name": data.name,
            "description": data.description or "",
            "status": CampaignStatus.DRAFT.value,
            "template_id": data.template_id,
            "landing_page_id": data.landing_page_id or "google",
            "send_from_name": data.send_from_name or "IT Security Team",
            "send_from_email": data.send_from_email or "security@phishx-training.local",
            "targets": targets,
            "results": results,
            "scheduled_at": data.scheduled_at,
            "launched_at": None,
            "completed_at": None,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        _store["campaigns"][cid] = campaign
        _save()
    return campaign


def delete_campaign(campaign_id: str) -> bool:
    with _lock:
        _load()
        if campaign_id in _store["campaigns"]:
            del _store["campaigns"][campaign_id]
            _save()
            return True
    return False


# ---------------------------------------------------------------------------
# CSV import
# ---------------------------------------------------------------------------

def import_targets_csv(csv_bytes: bytes) -> list[dict]:
    """
    Parse CSV of targets. Expected columns: first_name, last_name, email
    Optional: department, position
    Returns list of target dicts.
    """
    text = csv_bytes.decode("utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    targets = []
    for row in reader:
        row = {k.strip().lower(): v.strip() for k, v in row.items()}
        email = row.get("email", "")
        if not email or "@" not in email:
            continue
        targets.append({
            "id": _make_target_id(),
            "first_name": row.get("first_name", row.get("firstname", "User")),
            "last_name": row.get("last_name", row.get("lastname", "")),
            "email": email,
            "department": row.get("department", row.get("dept", "")),
            "position": row.get("position", row.get("role", row.get("title", ""))),
        })
    return targets


# ---------------------------------------------------------------------------
# Campaign launch & scheduling
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def launch_campaign(campaign_id: str) -> dict | None:
    """Mark campaign as running and simulate email sends."""
    with _lock:
        _load()
        c = _store["campaigns"].get(campaign_id)
        if not c:
            return None
        now = _now_iso()
        c["status"] = CampaignStatus.RUNNING.value
        c["launched_at"] = now
        # Simulate emails being sent to all targets
        for r in c.get("results", []):
            if not r["email_sent"]:
                r["email_sent"] = True
                r["events"].append({"type": TargetEventType.EMAIL_SENT.value, "at": now})
        _save()
    return c


def pause_campaign(campaign_id: str) -> dict | None:
    with _lock:
        _load()
        c = _store["campaigns"].get(campaign_id)
        if c:
            c["status"] = CampaignStatus.PAUSED.value
            _save()
    return c


def complete_campaign(campaign_id: str) -> dict | None:
    with _lock:
        _load()
        c = _store["campaigns"].get(campaign_id)
        if c:
            c["status"] = CampaignStatus.COMPLETED.value
            c["completed_at"] = _now_iso()
            _save()
    return c


def _scheduler_loop():
    """Background thread: auto-launch scheduled campaigns when their time arrives."""
    while True:
        try:
            _load()
            now = datetime.now(timezone.utc)
            for cid, c in list(_store["campaigns"].items()):
                if c.get("status") == CampaignStatus.SCHEDULED.value and c.get("scheduled_at"):
                    try:
                        scheduled = datetime.fromisoformat(c["scheduled_at"].replace("Z", "+00:00"))
                        if now >= scheduled:
                            launch_campaign(cid)
                    except ValueError:
                        pass
        except Exception:
            pass
        time.sleep(30)


_scheduler_thread = threading.Thread(target=_scheduler_loop, daemon=True)
_scheduler_thread.start()


def schedule_campaign(campaign_id: str, scheduled_at: str) -> dict | None:
    with _lock:
        _load()
        c = _store["campaigns"].get(campaign_id)
        if c:
            c["status"] = CampaignStatus.SCHEDULED.value
            c["scheduled_at"] = scheduled_at
            _save()
    return c


# ---------------------------------------------------------------------------
# Event tracking (real-time results)
# ---------------------------------------------------------------------------

def record_event(campaign_id: str, target_id: str, event_type: str, data: dict | None = None) -> bool:
    """Record a user interaction event (email opened, link clicked, data submitted, reported)."""
    with _lock:
        _load()
        c = _store["campaigns"].get(campaign_id)
        if not c:
            return False
        for r in c.get("results", []):
            if r["target_id"] == target_id:
                now = _now_iso()
                event = {"type": event_type, "at": now}
                if data:
                    event["data"] = data
                r["events"].append(event)
                if event_type == TargetEventType.EMAIL_OPENED.value:
                    r["email_opened"] = True
                elif event_type == TargetEventType.LINK_CLICKED.value:
                    r["link_clicked"] = True
                elif event_type == TargetEventType.DATA_SUBMITTED.value:
                    r["data_submitted"] = True
                    if data:
                        r["captured_data"] = data
                elif event_type == TargetEventType.REPORTED.value:
                    r["reported"] = True
                _save()
                return True
    return False


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

def get_campaign_stats(campaign_id: str) -> dict | None:
    _load()
    c = _store["campaigns"].get(campaign_id)
    if not c:
        return None
    results = c.get("results", [])
    total = len(results)

    def pct(n):
        return round(n / total * 100, 1) if total else 0.0

    sent = sum(1 for r in results if r.get("email_sent"))
    opened = sum(1 for r in results if r.get("email_opened"))
    clicked = sum(1 for r in results if r.get("link_clicked"))
    submitted = sum(1 for r in results if r.get("data_submitted"))
    reported = sum(1 for r in results if r.get("reported"))

    return {
        "campaign_id": campaign_id,
        "campaign_name": c["name"],
        "status": c["status"],
        "total_targets": total,
        "emails_sent": sent,
        "emails_opened": opened,
        "links_clicked": clicked,
        "data_submitted": submitted,
        "reported": reported,
        "open_rate_pct": pct(opened),
        "click_rate_pct": pct(clicked),
        "submit_rate_pct": pct(submitted),
        "report_rate_pct": pct(reported),
    }
