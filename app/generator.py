"""
Phishing Email Generator - SECURITY TRAINING USE ONLY.

Generates realistic simulated phishing emails with simulated malware payload
descriptions for security awareness training. No real malware is created.
All output is for training, testing user awareness, and demonstrating attack
techniques in a safe, controlled environment.
"""

import random
import uuid
from pydantic import BaseModel, Field



MALWARE_TYPES = [
    {
        "name": "Ransomware",
        "type": "ransomware",
        "description": "Encrypts victim files and demands a ransom payment to restore access.",
        "delivery": "Malicious Word macro (.docx) or PDF attachment",
        "indicators": ["Suspicious .docx or .pdf attachment", "Macro execution prompts", "Unusual file extension in attachment"],
        "real_world_examples": ["WannaCry", "LockBit", "REvil"],
    },
    {
        "name": "Keylogger",
        "type": "keylogger",
        "description": "Records keystrokes silently to steal credentials and sensitive data.",
        "delivery": "Malicious executable (.exe) disguised as invoice or document",
        "indicators": ["Unexpected .exe or .zip attachment", "Link to 'download document'", "Request to disable antivirus"],
        "real_world_examples": ["Agent Tesla", "Hawkeye", "Remcos RAT"],
    },
    {
        "name": "Trojan / Remote Access Tool (RAT)",
        "type": "rat",
        "description": "Gives attacker full remote control of the victim's machine.",
        "delivery": "Malicious link to fake login portal or attachment with embedded script",
        "indicators": ["Spoofed sender domain", "Urgent call-to-action to click link", "Fake login page URL"],
        "real_world_examples": ["AsyncRAT", "njRAT", "DarkComet"],
    },
    {
        "name": "Credential Harvester",
        "type": "credential_harvester",
        "description": "Directs victim to a fake login page to steal username and password.",
        "delivery": "Phishing link to cloned website (e.g. Microsoft, Google, bank)",
        "indicators": ["Mismatched or spoofed URL", "Urgency to 'verify account'", "Fake login form"],
        "real_world_examples": ["EvilProxy", "Evilginx2", "Modlishka"],
    },
    {
        "name": "Information Stealer",
        "type": "infostealer",
        "description": "Exfiltrates saved passwords, cookies, crypto wallets, and system info.",
        "delivery": "Malicious link or .zip attachment",
        "indicators": ["Suspicious compressed attachment (.zip, .rar)", "Link to 'secure file share'", "Impersonating cloud storage"],
        "real_world_examples": ["RedLine Stealer", "Raccoon Stealer", "Vidar"],
    },
    {
        "name": "Macro Virus (Office document)",
        "type": "macro_virus",
        "description": "Embedded VBA macro executes when victim opens and enables editing in Office.",
        "delivery": "Word or Excel document (.docm, .xlsm) with 'Enable Content' prompt",
        "indicators": ["Office document attachment", "'Enable Content' or 'Enable Macros' prompt", "Blurred preview trick"],
        "real_world_examples": ["Emotet", "Dridex", "TrickBot loader"],
    },
]

def _generate_ransomware_email(target_org: str, sender_name: str) -> dict:
    return {
        "subject": f"Invoice #{random.randint(10000, 99999)} overdue - immediate action required",
        "sender_display": f"Accounts Payable <billing@{target_org.lower().replace(' ','-')}-invoices.com>",
        "body": f"""Dear {target_org} Team,

Please find attached the overdue invoice for services rendered last month. The total outstanding balance requires your urgent attention to avoid service interruption.

To view and process the invoice, please open the attached document and click "Enable Content" when prompted - this is required by our secure document system.

Attachment: Invoice_{random.randint(10000, 99999)}.docm

If you have any questions regarding this invoice, please do not hesitate to contact our billing department.

Kind regards,
{sender_name}
Accounts Payable Department""",
    }


def _generate_credential_email(target_org: str, sender_name: str) -> dict:
    fake_domain = f"{target_org.lower().replace(' ','-')}-portal-login.com"
    return {
        "subject": "Action required: Your account will be suspended in 24 hours",
        "sender_display": f"IT Security <no-reply@{fake_domain}>",
        "body": f"""Dear {target_org} User,

We have detected unusual sign-in activity on your account. To protect your account, access has been temporarily restricted.

To restore full access, please verify your identity using the link below within the next 24 hours:

[Verify My Account - Click Here]
https://{fake_domain}/verify?token={uuid.uuid4().hex[:16]}

Failure to verify will result in permanent account suspension. We apologise for any inconvenience.

Regards,
{sender_name}
IT Security Team""",
    }


def _generate_rat_email(target_org: str, sender_name: str) -> dict:
    return {
        "subject": f"Urgent: Updated remote access policy - action required by Friday",
        "sender_display": f"IT Helpdesk <helpdesk@{target_org.lower().replace(' ','-')}-it-support.com>",
        "body": f"""Hi,

As part of our ongoing security improvements, all staff are required to install the updated remote access client before Friday.

Please download and run the setup tool from the link below. The installation takes less than 2 minutes and requires no IT involvement:

[Download Remote Access Tool]

If you experience any issues, please reply to this email or call our helpdesk on the number in your welcome pack.

Thank you for your cooperation.

Best regards,
{sender_name}
IT Helpdesk""",
    }


def _generate_infostealer_email(target_org: str, sender_name: str) -> dict:
    return {
        "subject": f"Shared with you: {target_org} Q4 report - confidential",
        "sender_display": f"{sender_name} <{sender_name.lower().replace(' ','.')}@sharepoint-files-secure.com>",
        "body": f"""Hi,

I've shared a confidential document with you via our secure file portal. Please review before our meeting on Thursday.

Document: {target_org}_Q4_Financial_Report_CONFIDENTIAL.zip

Click below to access:
[Access Secure Document]

The link expires in 48 hours. You may need to sign in with your corporate credentials.

Thanks,
{sender_name}""",
    }


def _generate_macro_email(target_org: str, sender_name: str) -> dict:
    return {
        "subject": "Your contract renewal - please review and sign",
        "sender_display": f"Legal & Compliance <legal@{target_org.lower().replace(' ','-')}-contracts.net>",
        "body": f"""Dear Team,

Please find enclosed your updated contract renewal document for the upcoming period. Kindly review the terms and return the signed copy at your earliest convenience.

To view the full document:
1. Open the attached file: Contract_Renewal_{random.randint(1000, 9999)}.docm
2. Click "Enable Content" when prompted (required to load the signature fields)
3. Complete the highlighted fields and save

If you have any concerns regarding the updated terms, please reach out to your account manager.

Warm regards,
{sender_name}
Legal & Compliance""",
    }


_TEMPLATE_MAP = {
    "ransomware": _generate_ransomware_email,
    "credential_harvester": _generate_credential_email,
    "rat": _generate_rat_email,
    "infostealer": _generate_infostealer_email,
    "macro_virus": _generate_macro_email,
    "keylogger": _generate_credential_email,
}


class GeneratedPhishingEmail(BaseModel):
    id: str
    subject: str
    sender_display: str
    body: str
    malware_type: str
    malware_name: str
    malware_description: str
    delivery_method: str
    payload_indicators: list[str]
    real_world_examples: list[str]
    training_notes: list[str]
    disclaimer: str = "SIMULATED - FOR SECURITY TRAINING ONLY. No real malware. Do not send to real users."


class GenerateRequest(BaseModel):
    target_org: str = Field(default="Acme Corp", description="Organisation name to personalise the email")
    sender_name: str = Field(default="John Smith", description="Name of the fake sender")
    malware_type: str | None = Field(None, description="ransomware | keylogger | rat | credential_harvester | infostealer | macro_virus | random")
    difficulty: str = Field(default="medium", description="easy | medium | hard")


def generate_phishing_email(request: GenerateRequest) -> GeneratedPhishingEmail:
    """
    Generate a realistic simulated phishing email for training purposes.
    Returns email content + full educational breakdown of malware payload.
    FOR SECURITY AWARENESS TRAINING ONLY.
    """
    malware_key = request.malware_type
    if not malware_key or malware_key == "random":
        malware_key = random.choice([m["type"] for m in MALWARE_TYPES])

    malware_info = next((m for m in MALWARE_TYPES if m["type"] == malware_key), MALWARE_TYPES[0])
    template_fn = _TEMPLATE_MAP.get(malware_key, _generate_credential_email)
    email_content = template_fn(request.target_org, request.sender_name)

    # Add difficulty-based red flags visibility hint
    difficulty_notes = {
        "easy": [
            "The sender domain is clearly fake and unrelated to the real organisation.",
            "The email uses generic greetings and vague language.",
            "Urgency tactics are obvious and over the top.",
        ],
        "medium": [
            "The sender domain looks plausible but is slightly misspelled.",
            "The email mimics a real business process (invoice, contract).",
            "The call-to-action is unusual but not immediately suspicious.",
        ],
        "hard": [
            "The domain closely resembles a legitimate one (typosquatting).",
            "The email references real-seeming invoice numbers and names.",
            "Tone and formatting are professional; red flags are subtle.",
        ],
    }

    return GeneratedPhishingEmail(
        id=f"gen_{uuid.uuid4().hex[:12]}",
        subject=email_content["subject"],
        sender_display=email_content["sender_display"],
        body=email_content["body"],
        malware_type=malware_info["type"],
        malware_name=malware_info["name"],
        malware_description=malware_info["description"],
        delivery_method=malware_info["delivery"],
        payload_indicators=malware_info["indicators"],
        real_world_examples=malware_info["real_world_examples"],
        training_notes=difficulty_notes.get(request.difficulty, difficulty_notes["medium"]),
    )


def list_malware_types() -> list[dict]:
    """Return all available simulated malware types with descriptions."""
    return [{"type": m["type"], "name": m["name"], "description": m["description"]} for m in MALWARE_TYPES]
