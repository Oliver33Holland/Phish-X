"""Phishing and vishing simulation logic and AI-phishing detection heuristics."""

import email
import email.policy
import ipaddress
import random
import re
from .detection import _find_matches as _score_indicators
from .models import (
    DetectionResult,
    PhishingCategory,
    SimulatedEmail,
    VishingScenario,
)

# LinkSec phishing email templates (16 brands, 45 templates)
# Source: https://github.com/LinkSec/phishing-templates
# GoPhish-style placeholders: {{.FirstName}}, {{.LastName}}, {{.URL}} â€” training use only.
LINKSEC_EMAIL_TEMPLATES: list[dict] = [
    # â”€â”€ Amazon Web Services â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    {
        "subject": "AWS Account Verification Request",
        "sender": "no-reply@account-verify-aws.com",
        "brand": "Amazon Web Services",
        "body": """Dear {{.FirstName}} {{.LastName}},

We have detected unusual login activity on your AWS account. To ensure the security of your account and avoid service disruption, we require you to verify your identity immediately.

Please click the link below to verify your AWS account:

{{.URL}}

If you do not verify within 24 hours, your AWS account may be temporarily suspended.

Thank you for your prompt attention.

Best regards,
Amazon Web Services Security Team
Â© 2024 Amazon Web Services. All rights reserved.""",
        "difficulty": "medium",
        "red_flags": ["Urgency (24 hours)", "Unusual login activity claim", "Suspicious sender domain", "Threat of account suspension"],
    },
    {
        "subject": "Exclusive: $100 Amazon Gift Card â€“ Claim Now",
        "sender": "rewards@aws-exclusive-offers.com",
        "brand": "Amazon Web Services",
        "body": """Dear {{.FirstName}},

Congratulations! As a valued AWS customer, you have been selected to receive an exclusive $100 Amazon Gift Card.

To claim your reward, please verify your account details by clicking the link below:

{{.URL}}

This offer expires in 48 hours. Act now to secure your reward.

Best regards,
AWS Rewards Team
Â© 2024 Amazon Web Services. All rights reserved.""",
        "difficulty": "easy",
        "red_flags": ["Unsolicited reward offer", "Urgency (48 hours)", "Suspicious sender domain", "Request to verify account details"],
    },
    {
        "subject": "Urgent AWS Security Update Alert",
        "sender": "security-alert@aws-update-notices.com",
        "brand": "Amazon Web Services",
        "body": """Dear {{.FirstName}} {{.LastName}},

We are writing to inform you of a critical security update that requires your immediate attention. Our systems have identified a potential vulnerability affecting your AWS account.

To apply the security update and protect your account, please click the link below:

{{.URL}}

Failure to apply this update within 24 hours may result in your account being compromised.

Best regards,
Amazon Web Services Security Team
Â© 2024 Amazon Web Services. All rights reserved.""",
        "difficulty": "hard",
        "red_flags": ["Fake security update", "Urgency (24 hours)", "Vague 'vulnerability' claim", "Suspicious sender domain", "Threat of account compromise"],
    },
    # â”€â”€ BlueJeans â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    {
        "subject": "BlueJeans Account Verification Request",
        "sender": "no-reply@bluejeans-account-verify.com",
        "brand": "BlueJeans",
        "body": """Dear {{.FirstName}},

We have noticed some unusual activity on your BlueJeans account. To ensure the security of your account, we require you to verify your identity.

Please click the link below to verify your BlueJeans account:

{{.URL}}

If you do not verify within 24 hours, your account may be suspended.

Best regards,
BlueJeans Support Team
Â© 2024 BlueJeans. All rights reserved.""",
        "difficulty": "easy",
        "red_flags": ["Urgency (24 hours)", "Unusual activity claim", "Suspicious sender domain", "Threat of account suspension"],
    },
    {
        "subject": "Exclusive Upgrade Offer â€“ BlueJeans Premium",
        "sender": "offers@bluejeans-upgrade-offer.com",
        "brand": "BlueJeans",
        "body": """Dear {{.FirstName}},

We are pleased to offer you an exclusive upgrade to BlueJeans Premium at no extra cost for 3 months.

To claim your free upgrade, please verify your account by clicking the link below:

{{.URL}}

This exclusive offer is only available for a limited time.

Best regards,
BlueJeans Team
Â© 2024 BlueJeans. All rights reserved.""",
        "difficulty": "medium",
        "red_flags": ["Unsolicited upgrade offer", "Limited time pressure", "Suspicious sender domain", "Request to verify account"],
    },
    {
        "subject": "Free BlueJeans Premium Subscription â€“ Limited Offer",
        "sender": "promotions@bluejeans-free-premium.com",
        "brand": "BlueJeans",
        "body": """Dear {{.FirstName}},

Congratulations! You have been selected to receive a free 6-month BlueJeans Premium subscription.

To activate your free subscription, please click the link below:

{{.URL}}

Offer expires in 72 hours. Do not miss out!

Best regards,
BlueJeans Promotions Team
Â© 2024 BlueJeans. All rights reserved.""",
        "difficulty": "easy",
        "red_flags": ["Unsolicited reward offer", "Urgency (72 hours)", "Suspicious sender domain", "Caller-initiated contact"],
    },
    {
        "subject": "Someone Viewed Your BlueJeans Profile",
        "sender": "notifications@bluejeans-profile-alerts.com",
        "brand": "BlueJeans",
        "body": """Dear {{.FirstName}},

Someone has recently viewed your BlueJeans profile. To see who viewed your profile and manage your privacy settings, click the link below:

{{.URL}}

Keep your BlueJeans account secure.

Best regards,
BlueJeans Notifications
Â© 2024 BlueJeans. All rights reserved.""",
        "difficulty": "medium",
        "red_flags": ["Fake social notification", "Suspicious sender domain", "Bait to click link"],
    },
    {
        "subject": "Urgent: Verify Your BlueJeans Account Immediately",
        "sender": "urgent@bluejeans-account-verify.net",
        "brand": "BlueJeans",
        "body": """Dear {{.FirstName}} {{.LastName}},

We have detected suspicious activity on your BlueJeans account. Immediate action is required to prevent your account from being locked.

Please verify your account by clicking the link below:

{{.URL}}

You must complete this verification within the next 12 hours.

Best regards,
BlueJeans Security Team
Â© 2024 BlueJeans. All rights reserved.""",
        "difficulty": "hard",
        "red_flags": ["Extreme urgency (12 hours)", "Suspicious activity claim", "Threat of account lock", "Suspicious sender domain"],
    },
    # â”€â”€ Cisco Webex â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    {
        "subject": "Claim Your Free Webex Pro Offer",
        "sender": "promo@webex-free-pro-offer.com",
        "brand": "Cisco Webex",
        "body": """Dear {{.FirstName}},

As a valued Webex user, you are eligible to claim a free Webex Pro upgrade for 90 days.

To claim your free upgrade, please click the link below and verify your Webex account:

{{.URL}}

This offer is only valid for 48 hours.

Best regards,
Cisco Webex Team
Â© 2024 Cisco. All rights reserved.""",
        "difficulty": "easy",
        "red_flags": ["Unsolicited offer", "Urgency (48 hours)", "Suspicious sender domain", "Request to verify account"],
    },
    {
        "subject": "Urgent: Password Reset Required â€“ Webex",
        "sender": "security@webex-password-reset.com",
        "brand": "Cisco Webex",
        "body": """Dear {{.FirstName}} {{.LastName}},

Our security systems have detected that your Webex account password may have been compromised. For your protection, an immediate password reset is required.

Please reset your password by clicking the link below:

{{.URL}}

If you do not reset your password within 24 hours, your account access will be restricted.

Best regards,
Cisco Webex Security Team
Â© 2024 Cisco. All rights reserved.""",
        "difficulty": "medium",
        "red_flags": ["Fake password compromise alert", "Urgency (24 hours)", "Suspicious sender domain", "Threat of access restriction"],
    },
    {
        "subject": "Urgent Webex Account Verification Request",
        "sender": "no-reply@webex-account-verify.net",
        "brand": "Cisco Webex",
        "body": """Dear {{.FirstName}},

Due to recent changes in our security policies, all Webex users are required to re-verify their accounts. This is a mandatory step to maintain access to your Webex services.

Please verify your account by clicking the link below:

{{.URL}}

Failure to complete this verification will result in restricted access to your Webex account.

Best regards,
Cisco Webex Security Team
Â© 2024 Cisco. All rights reserved.""",
        "difficulty": "hard",
        "red_flags": ["Fake mandatory policy change", "Suspicious sender domain", "Vague 'security policy' claim", "Threat of restricted access"],
    },
    # â”€â”€ Google Cloud Platform â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    {
        "subject": "Exclusive Rewards Verification â€“ Google Cloud",
        "sender": "rewards@gcp-exclusive-rewards.com",
        "brand": "Google Cloud Platform",
        "body": """Dear {{.FirstName}} {{.LastName}},

You have been selected to receive exclusive Google Cloud Platform rewards as part of our loyalty programme.

To verify your eligibility and claim your rewards, please click the link below:

{{.URL}}

This offer expires in 48 hours.

Best regards,
Google Cloud Platform Rewards Team
Â© 2024 Google Cloud Platform. All rights reserved.""",
        "difficulty": "medium",
        "red_flags": ["Unsolicited rewards offer", "Urgency (48 hours)", "Suspicious sender domain", "Request to verify eligibility"],
    },
    {
        "subject": "Urgent GCP Account Security Notification",
        "sender": "security@gcp-security-notifications.com",
        "brand": "Google Cloud Platform",
        "body": """Dear {{.FirstName}} {{.LastName}},

We have detected suspicious sign-in activity on your Google Cloud Platform account. To protect your account and cloud resources, please verify your identity immediately.

{{.URL}}

Failure to verify within 24 hours may result in suspension of your GCP services.

Best regards,
Google Cloud Platform Security Team
Â© 2024 Google Cloud Platform. All rights reserved.""",
        "difficulty": "medium",
        "red_flags": ["Suspicious sign-in claim", "Urgency (24 hours)", "Suspicious sender domain", "Threat of service suspension"],
    },
    {
        "subject": "Urgent: Verify Your GCP Subscription Now",
        "sender": "subscriptions@gcp-verify-now.com",
        "brand": "Google Cloud Platform",
        "body": """Dear {{.FirstName}} {{.LastName}},

We hope this message finds you well. We are writing to inform you of an urgent matter regarding your Google Cloud Platform (GCP) subscription. Our records indicate that there is an issue that requires your immediate attention to ensure continuous service.

Please verify your subscription details by clicking the link below to avoid any interruption to your services:

{{.URL}}

Failure to address this issue within the next 24 hours will result in a temporary suspension of your GCP services.

Thank you for your immediate attention to this urgent matter.

Best regards,
Google Cloud Platform Support Team
Â© 2024 Google Cloud Platform. All rights reserved.""",
        "difficulty": "hard",
        "red_flags": ["Vague 'issue' with subscription", "Urgency (24 hours)", "Suspicious sender domain", "Threat of service suspension", "AI phrase: 'we hope this message finds you well'"],
    },
    # â”€â”€ Google Workspace â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    {
        "subject": "Exciting Google Workspace Free Upgrade",
        "sender": "offers@google-workspace-upgrade.com",
        "brand": "Google Workspace",
        "body": """Dear {{.FirstName}},

We are delighted to offer you a free upgrade to Google Workspace Business Plus for 3 months.

To activate your free upgrade, please verify your account by clicking the link below:

{{.URL}}

This offer is only available for the next 72 hours.

Best regards,
Google Workspace Team
Â© 2024 Google LLC. All rights reserved.""",
        "difficulty": "easy",
        "red_flags": ["Unsolicited upgrade offer", "Urgency (72 hours)", "Suspicious sender domain", "Request to verify account"],
    },
    {
        "subject": "Urgent: Verify Your Google Workspace Account",
        "sender": "security@google-workspace-verify.net",
        "brand": "Google Workspace",
        "body": """Dear {{.FirstName}} {{.LastName}},

We have detected unusual activity on your Google Workspace account. To protect your organisation's data, you must verify your account immediately.

Please click the link below to verify your Google Workspace account:

{{.URL}}

You must complete this verification within 24 hours to avoid account suspension.

Best regards,
Google Workspace Security Team
Â© 2024 Google LLC. All rights reserved.""",
        "difficulty": "medium",
        "red_flags": ["Unusual activity claim", "Urgency (24 hours)", "Suspicious sender domain", "Threat of account suspension"],
    },
    {
        "subject": "Urgent: Google Workspace Storage Alert",
        "sender": "alerts@google-workspace-storage-alert.com",
        "brand": "Google Workspace",
        "body": """Dear {{.FirstName}},

Your Google Workspace storage is almost full. If you do not take action immediately, you will lose access to Gmail, Drive, and other Google services.

To upgrade your storage and avoid service disruption, please click the link below:

{{.URL}}

Act now to prevent data loss.

Best regards,
Google Workspace Team
Â© 2024 Google LLC. All rights reserved.""",
        "difficulty": "hard",
        "red_flags": ["Fake storage alert", "Threat of data loss", "Suspicious sender domain", "Multiple service disruption threats"],
    },
    # â”€â”€ GoToMeeting â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    {
        "subject": "Exclusive GoToMeeting Subscription Upgrade",
        "sender": "offers@gotomeeting-upgrade-offer.com",
        "brand": "GoToMeeting",
        "body": """Dear {{.FirstName}},

As a valued GoToMeeting customer, we are offering you an exclusive upgrade to our premium plan at no additional cost for 6 months.

To claim your free upgrade, please click the link below:

{{.URL}}

This offer expires in 48 hours.

Best regards,
GoToMeeting Team
Â© 2024 GoTo Group. All rights reserved.""",
        "difficulty": "easy",
        "red_flags": ["Unsolicited upgrade offer", "Urgency (48 hours)", "Suspicious sender domain"],
    },
    {
        "subject": "Urgent GoToMeeting Account Verification Request",
        "sender": "no-reply@gotomeeting-verify.net",
        "brand": "GoToMeeting",
        "body": """Dear {{.FirstName}} {{.LastName}},

We have detected suspicious activity on your GoToMeeting account. To protect your account and prevent unauthorised access, please verify your identity immediately.

{{.URL}}

If you do not verify within 24 hours, your account will be locked.

Best regards,
GoToMeeting Security Team
Â© 2024 GoTo Group. All rights reserved.""",
        "difficulty": "medium",
        "red_flags": ["Suspicious activity claim", "Urgency (24 hours)", "Threat of account lock", "Suspicious sender domain"],
    },
    {
        "subject": "Urgent Security Update for GoToMeeting",
        "sender": "security@gotomeeting-security-update.com",
        "brand": "GoToMeeting",
        "body": """Dear {{.FirstName}},

A critical security update is required for your GoToMeeting account. Our systems have identified a vulnerability that could expose your meeting data to unauthorised parties.

Please apply the security update by clicking the link below:

{{.URL}}

You must apply this update within 12 hours to protect your account.

Best regards,
GoToMeeting Security Team
Â© 2024 GoTo Group. All rights reserved.""",
        "difficulty": "hard",
        "red_flags": ["Fake security update", "Extreme urgency (12 hours)", "Vague 'vulnerability' claim", "Suspicious sender domain"],
    },
    # â”€â”€ IBM Cloud â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    {
        "subject": "Exclusive IBM Cloud Services Trial",
        "sender": "offers@ibmcloud-trial-offer.com",
        "brand": "IBM Cloud",
        "body": """Dear {{.FirstName}},

We are pleased to invite you to an exclusive IBM Cloud free trial offering full access to our enterprise cloud services for 90 days.

To activate your free trial, please verify your account by clicking the link below:

{{.URL}}

This limited offer expires in 72 hours.

Best regards,
IBM Cloud Team
Â© 2024 IBM Corporation. All rights reserved.""",
        "difficulty": "easy",
        "red_flags": ["Unsolicited trial offer", "Urgency (72 hours)", "Suspicious sender domain", "Request to verify account"],
    },
    {
        "subject": "Urgent IBM Cloud Account Verification Request",
        "sender": "security@ibmcloud-account-verify.com",
        "brand": "IBM Cloud",
        "body": """Dear {{.FirstName}} {{.LastName}},

We have detected unusual access patterns on your IBM Cloud account. To prevent unauthorised access to your cloud resources, please verify your identity immediately.

{{.URL}}

Failure to verify within 24 hours will result in temporary suspension of your IBM Cloud services.

Best regards,
IBM Cloud Security Team
Â© 2024 IBM Corporation. All rights reserved.""",
        "difficulty": "medium",
        "red_flags": ["Unusual access claim", "Urgency (24 hours)", "Suspicious sender domain", "Threat of service suspension"],
    },
    {
        "subject": "Urgent IBM Cloud Security Update Notification",
        "sender": "alerts@ibmcloud-security-alerts.net",
        "brand": "IBM Cloud",
        "body": """Dear {{.FirstName}},

A critical security vulnerability has been identified affecting IBM Cloud accounts. Immediate action is required to protect your data and cloud infrastructure.

Please click the link below to apply the security patch to your account:

{{.URL}}

You must apply this patch within 24 hours to avoid service interruption.

Best regards,
IBM Cloud Security Team
Â© 2024 IBM Corporation. All rights reserved.""",
        "difficulty": "hard",
        "red_flags": ["Fake security vulnerability", "Urgency (24 hours)", "Suspicious sender domain", "Threat of service interruption"],
    },
    # â”€â”€ Microsoft Azure â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    {
        "subject": "Exclusive Discount Offer from Microsoft Azure",
        "sender": "offers@azure-discount-offers.com",
        "brand": "Microsoft Azure",
        "body": """Dear {{.FirstName}},

As a valued Microsoft Azure customer, we are offering you an exclusive 40% discount on your next Azure invoice.

To claim your discount, please verify your Azure account by clicking the link below:

{{.URL}}

This offer is valid for 48 hours only.

Best regards,
Microsoft Azure Team
Â© 2024 Microsoft Corporation. All rights reserved.""",
        "difficulty": "easy",
        "red_flags": ["Unsolicited discount offer", "Urgency (48 hours)", "Suspicious sender domain", "Request to verify account"],
    },
    {
        "subject": "New Azure Security Features Alert",
        "sender": "updates@azure-security-updates.net",
        "brand": "Microsoft Azure",
        "body": """Dear {{.FirstName}} {{.LastName}},

Microsoft Azure has introduced new security features to better protect your cloud resources. You are required to update your account settings to take advantage of these new protections.

Please click the link below to update your Azure account security settings:

{{.URL}}

This update is mandatory and must be completed within 48 hours.

Best regards,
Microsoft Azure Security Team
Â© 2024 Microsoft Corporation. All rights reserved.""",
        "difficulty": "medium",
        "red_flags": ["Fake mandatory update", "Urgency (48 hours)", "Suspicious sender domain", "False sense of authority"],
    },
    {
        "subject": "Urgent Azure Account Verification Request",
        "sender": "no-reply@azure-account-verify.com",
        "brand": "Microsoft Azure",
        "body": """Dear {{.FirstName}},

We have detected suspicious sign-in attempts on your Microsoft Azure account. To protect your Azure resources and subscriptions, please verify your identity immediately.

{{.URL}}

If you do not verify within 12 hours, access to your Azure portal will be restricted.

Best regards,
Microsoft Azure Security Team
Â© 2024 Microsoft Corporation. All rights reserved.""",
        "difficulty": "hard",
        "red_flags": ["Suspicious sign-in claim", "Extreme urgency (12 hours)", "Suspicious sender domain", "Threat of portal access restriction"],
    },
    # â”€â”€ Microsoft Office 365 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    {
        "subject": "Exclusive Reward â€“ Microsoft Office 365",
        "sender": "rewards@office365-exclusive-rewards.com",
        "brand": "Microsoft Office 365",
        "body": """Dear {{.FirstName}},

You have been selected to receive an exclusive Microsoft 365 reward. As one of our valued customers, you are eligible for a free 3-month Microsoft 365 Business Premium subscription.

To claim your reward, please verify your account:

{{.URL}}

This offer expires in 48 hours.

Best regards,
Microsoft 365 Rewards Team
Â© 2024 Microsoft Corporation. All rights reserved.""",
        "difficulty": "easy",
        "red_flags": ["Unsolicited reward offer", "Urgency (48 hours)", "Suspicious sender domain", "Request to verify account"],
    },
    {
        "subject": "Urgent: Microsoft 365 Account Verification Notice",
        "sender": "security@office365-account-verify.net",
        "brand": "Microsoft Office 365",
        "body": """Dear {{.FirstName}} {{.LastName}},

We have detected unusual activity on your Microsoft 365 account. To ensure the security of your emails, documents, and data, we require you to verify your account immediately.

Please click the link below to verify your Microsoft 365 account:

{{.URL}}

Failure to verify within 24 hours will result in suspension of your Microsoft 365 services including Outlook, Teams, and SharePoint.

Best regards,
Microsoft 365 Security Team
Â© 2024 Microsoft Corporation. All rights reserved.""",
        "difficulty": "hard",
        "red_flags": ["Unusual activity claim", "Urgency (24 hours)", "Suspicious sender domain", "Threat to multiple services (Outlook, Teams, SharePoint)"],
    },
    # â”€â”€ Microsoft Teams â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    {
        "subject": "Exclusive Microsoft 365 Upgrade Offer â€“ Teams",
        "sender": "offers@teams-365-upgrade.com",
        "brand": "Microsoft Teams",
        "body": """Dear {{.FirstName}},

We are pleased to offer you an exclusive Microsoft Teams Premium upgrade at no additional cost for 6 months.

To claim your free upgrade, please click the link below:

{{.URL}}

This offer is available for 48 hours only.

Best regards,
Microsoft Teams Team
Â© 2024 Microsoft Corporation. All rights reserved.""",
        "difficulty": "easy",
        "red_flags": ["Unsolicited upgrade offer", "Urgency (48 hours)", "Suspicious sender domain"],
    },
    {
        "subject": "Microsoft Teams Free Upgrade Offer",
        "sender": "promotions@teams-free-upgrade.net",
        "brand": "Microsoft Teams",
        "body": """Dear {{.FirstName}} {{.LastName}},

Congratulations! You have been selected to receive a free Microsoft Teams Essentials upgrade for 90 days.

To activate your free upgrade, please verify your account by clicking the link below:

{{.URL}}

Do not miss this limited time offer â€“ it expires in 72 hours.

Best regards,
Microsoft Teams Promotions
Â© 2024 Microsoft Corporation. All rights reserved.""",
        "difficulty": "medium",
        "red_flags": ["Unsolicited upgrade offer", "Urgency (72 hours)", "Suspicious sender domain", "Request to verify account"],
    },
    {
        "subject": "Urgent: Verify Your Microsoft Teams Account",
        "sender": "security@teams-account-verify.com",
        "brand": "Microsoft Teams",
        "body": """Dear {{.FirstName}},

We hope this message finds you well. This is an important notification concerning your Microsoft Teams account. Due to recent updates in our system, we require you to verify your account within the next 24 hours to prevent suspension.

Why is this necessary?
- Ensures continuous access to all Microsoft Teams features
- Protects your account from potential security threats
- Keeps your data secure

Please click the link below to verify your account:

{{.URL}}

Failure to complete this verification will result in temporary suspension of your Microsoft Teams account.

Best regards,
Microsoft Teams Security Team
Â© 2024 Microsoft Teams. All rights reserved.""",
        "difficulty": "hard",
        "red_flags": ["AI phrase: 'we hope this message finds you well'", "Urgency (24 hours)", "Suspicious sender domain", "Fake bullet list of benefits", "Threat of account suspension"],
    },
    # â”€â”€ Oracle Cloud â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    {
        "subject": "Free Oracle Cloud Subscription Offer",
        "sender": "offers@oracle-cloud-free-offer.com",
        "brand": "Oracle Cloud",
        "body": """Dear {{.FirstName}},

As a valued Oracle customer, you have been selected to receive a free Oracle Cloud subscription upgrade for 6 months.

To activate your free upgrade, please verify your account by clicking the link below:

{{.URL}}

This exclusive offer expires in 48 hours.

Best regards,
Oracle Cloud Team
Â© 2024 Oracle Corporation. All rights reserved.""",
        "difficulty": "easy",
        "red_flags": ["Unsolicited offer", "Urgency (48 hours)", "Suspicious sender domain", "Request to verify account"],
    },
    {
        "subject": "Urgent Oracle Cloud Account Update Request",
        "sender": "no-reply@oracle-cloud-update.net",
        "brand": "Oracle Cloud",
        "body": """Dear {{.FirstName}} {{.LastName}},

We have detected unusual activity on your Oracle Cloud account. To ensure the continued security of your data and cloud services, we require you to update your account information immediately.

Please click the link below to update your Oracle Cloud account:

{{.URL}}

You must complete this update within 24 hours to avoid service interruption.

Best regards,
Oracle Cloud Security Team
Â© 2024 Oracle Corporation. All rights reserved.""",
        "difficulty": "medium",
        "red_flags": ["Unusual activity claim", "Urgency (24 hours)", "Suspicious sender domain", "Threat of service interruption"],
    },
    # â”€â”€ RingCentral â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    {
        "subject": "Exclusive 50% Discount â€“ RingCentral",
        "sender": "offers@ringcentral-discount-offer.com",
        "brand": "RingCentral",
        "body": """Dear {{.FirstName}},

We are pleased to offer you an exclusive 50% discount on your RingCentral subscription for the next 6 months.

To claim your discount, please verify your RingCentral account by clicking the link below:

{{.URL}}

This offer is only valid for 48 hours.

Best regards,
RingCentral Team
Â© 2024 RingCentral Inc. All rights reserved.""",
        "difficulty": "easy",
        "red_flags": ["Unsolicited discount offer", "Urgency (48 hours)", "Suspicious sender domain", "Request to verify account"],
    },
    {
        "subject": "Urgent RingCentral Account Security Alert",
        "sender": "security@ringcentral-security-alerts.com",
        "brand": "RingCentral",
        "body": """Dear {{.FirstName}} {{.LastName}},

We have detected suspicious activity on your RingCentral account. Your account may be at risk of unauthorised access. Please verify your identity immediately to secure your account.

{{.URL}}

Failure to verify within 24 hours will result in your account being locked.

Best regards,
RingCentral Security Team
Â© 2024 RingCentral Inc. All rights reserved.""",
        "difficulty": "medium",
        "red_flags": ["Suspicious activity claim", "Urgency (24 hours)", "Suspicious sender domain", "Threat of account lock"],
    },
    {
        "subject": "Urgent: RingCentral Subscription Renewal Notice",
        "sender": "billing@ringcentral-renewal-notice.net",
        "brand": "RingCentral",
        "body": """Dear {{.FirstName}},

Your RingCentral subscription is due for renewal. To avoid service interruption and maintain access to your RingCentral phone system, you must renew your subscription immediately.

Please click the link below to renew your subscription:

{{.URL}}

Your service will be suspended within 24 hours if renewal is not completed.

Best regards,
RingCentral Billing Team
Â© 2024 RingCentral Inc. All rights reserved.""",
        "difficulty": "hard",
        "red_flags": ["Fake renewal urgency", "Urgency (24 hours)", "Suspicious sender domain", "Threat of service suspension"],
    },
    # â”€â”€ Skype for Business â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    {
        "subject": "Free Year of Skype Premium",
        "sender": "offers@skype-premium-free.com",
        "brand": "Skype for Business",
        "body": """Dear {{.FirstName}},

Congratulations! You have been selected to receive a free 12-month Skype Premium subscription.

To activate your free subscription, please verify your Microsoft account by clicking the link below:

{{.URL}}

This offer expires in 72 hours â€“ act now.

Best regards,
Skype Team
Â© 2024 Microsoft Corporation. All rights reserved.""",
        "difficulty": "easy",
        "red_flags": ["Unsolicited reward offer", "Urgency (72 hours)", "Suspicious sender domain", "Request to verify Microsoft account"],
    },
    {
        "subject": "Urgent Skype for Business Account Verification",
        "sender": "no-reply@skype-business-verify.net",
        "brand": "Skype for Business",
        "body": """Dear {{.FirstName}} {{.LastName}},

We have detected unusual sign-in activity on your Skype for Business account. To protect your communications and prevent unauthorised access, please verify your account immediately.

{{.URL}}

You must complete this verification within 24 hours.

Best regards,
Skype for Business Security Team
Â© 2024 Microsoft Corporation. All rights reserved.""",
        "difficulty": "medium",
        "red_flags": ["Unusual sign-in claim", "Urgency (24 hours)", "Suspicious sender domain"],
    },
    {
        "subject": "Urgent: Skype Password Reset Reminder",
        "sender": "security@skype-password-reset-notice.com",
        "brand": "Skype for Business",
        "body": """Dear {{.FirstName}},

Our security systems have flagged your Skype for Business account for a mandatory password reset. This is required to comply with your organisation's new security policy.

Please reset your password immediately by clicking the link below:

{{.URL}}

Your account will be locked if the password reset is not completed within 12 hours.

Best regards,
Skype for Business Security Team
Â© 2024 Microsoft Corporation. All rights reserved.""",
        "difficulty": "hard",
        "red_flags": ["Fake mandatory password reset", "Extreme urgency (12 hours)", "Suspicious sender domain", "False 'security policy' claim"],
    },
    # â”€â”€ Slack â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    {
        "subject": "You've Received a Gift Card â€“ Slack",
        "sender": "gifts@slack-gift-card-offer.com",
        "brand": "Slack",
        "body": """Dear {{.FirstName}},

Great news! You have been selected to receive a $50 gift card as part of our appreciation programme for valued Slack customers.

To claim your gift card, please click the link below and verify your Slack account:

{{.URL}}

This offer is only valid for 48 hours.

Best regards,
Slack Team
Â© 2024 Salesforce. All rights reserved.""",
        "difficulty": "easy",
        "red_flags": ["Gift card offer (untraceable reward lure)", "Urgency (48 hours)", "Suspicious sender domain", "Request to verify account"],
    },
    {
        "subject": "Urgent Slack Account Security Alert",
        "sender": "security@slack-account-security.net",
        "brand": "Slack",
        "body": """Dear {{.FirstName}} {{.LastName}},

We have detected suspicious sign-in activity on your Slack account from an unrecognised device. To protect your workspace and prevent data exposure, please verify your identity immediately.

{{.URL}}

Failure to verify within 24 hours will result in your Slack account being suspended.

Best regards,
Slack Security Team
Â© 2024 Salesforce. All rights reserved.""",
        "difficulty": "medium",
        "red_flags": ["Suspicious sign-in from unknown device", "Urgency (24 hours)", "Suspicious sender domain", "Threat of account suspension"],
    },
    {
        "subject": "Urgent: Verify Your Slack Account",
        "sender": "no-reply@slack-account-verify.com",
        "brand": "Slack",
        "body": """Dear {{.FirstName}},

Due to recent updates to our security infrastructure, all Slack users are required to re-verify their accounts. This is mandatory to maintain uninterrupted access to your Slack workspaces.

Please verify your Slack account by clicking the link below:

{{.URL}}

You must complete this verification within 24 hours. Failure to do so will result in loss of access to your Slack workspaces.

Best regards,
Slack Security Team
Â© 2024 Salesforce. All rights reserved.""",
        "difficulty": "hard",
        "red_flags": ["Fake mandatory re-verification", "Urgency (24 hours)", "Suspicious sender domain", "Threat of workspace access loss"],
    },
    # â”€â”€ Zoom â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    {
        "subject": "Urgent: Your Zoom Account Update Required",
        "sender": "no-reply@zoom-account-update.com",
        "brand": "Zoom",
        "body": """Dear {{.FirstName}} {{.LastName}},

Your Zoom account requires an important update to comply with our latest terms of service. Failure to update may result in loss of access to your Zoom meetings.

Please click the link below to update your Zoom account:

{{.URL}}

This update must be completed within 24 hours.

Best regards,
Zoom Account Team
Â© 2024 Zoom Video Communications, Inc. All rights reserved.""",
        "difficulty": "medium",
        "red_flags": ["Fake terms of service update", "Urgency (24 hours)", "Suspicious sender domain", "Threat of meeting access loss"],
    },
    {
        "subject": "Urgent Zoom Account Security Alert",
        "sender": "security@zoom-security-alert.net",
        "brand": "Zoom",
        "body": """Dear {{.FirstName}},

We have detected unusual activity on your Zoom account. To protect your account and prevent unauthorised access to your meetings, please verify your identity immediately.

{{.URL}}

If you do not verify within 24 hours, your Zoom account will be temporarily suspended.

Best regards,
Zoom Security Team
Â© 2024 Zoom Video Communications, Inc. All rights reserved.""",
        "difficulty": "medium",
        "red_flags": ["Unusual activity claim", "Urgency (24 hours)", "Suspicious sender domain", "Threat of account suspension"],
    },
    {
        "subject": "Zoom Pro Subscription Offer â€“ Limited Time",
        "sender": "offers@zoom-pro-subscription-offer.com",
        "brand": "Zoom",
        "body": """Dear {{.FirstName}},

As a valued Zoom user, you are eligible for a free 3-month Zoom Pro subscription.

To claim your free Zoom Pro subscription, please verify your account by clicking the link below:

{{.URL}}

This exclusive offer expires in 48 hours.

Best regards,
Zoom Team
Â© 2024 Zoom Video Communications, Inc. All rights reserved.""",
        "difficulty": "easy",
        "red_flags": ["Unsolicited subscription offer", "Urgency (48 hours)", "Suspicious sender domain", "Request to verify account"],
    },
]

_BUILTIN_EMAIL_TEMPLATES: list[dict] = [
    {
        "subject": "Urgent: Verify your account within 24 hours",
        "sender": "security@account-verify.com",
        "brand": "Generic",
        "body": """Dear Valued Customer,

We have detected unusual activity on your account. To prevent suspension, please verify your identity by clicking the link below within the next 24 hours.

[Verify My Account]

If you do not take action, your account may be permanently restricted. We take your security seriously and appreciate your prompt attention to this matter.

Best regards,
Account Security Team""",
        "difficulty": "easy",
        "red_flags": ["Urgency (24 hours)", "Generic greeting", "Suspicious link", "Threat of account suspension"],
    },
    {
        "subject": "Your invoice #INV-88472 is ready for review",
        "sender": "billing@servicessupport.net",
        "brand": "Generic",
        "body": """Hello,

Please find attached your invoice for the recent services. We noticed a discrepancy that requires your immediate attention.

Kindly review the document and confirm the details at your earliest convenience. Should you have any questions, our team is available to assist you.

Click here to view your invoice: [View Invoice]

Thank you for your cooperation.

Billing Department""",
        "difficulty": "medium",
        "red_flags": ["Mismatched sender domain", "Vague 'discrepancy'", "Link to view document", "Pressure to act quickly"],
    },
    {
        "subject": "Re: Your request has been approved â€“ next steps",
        "sender": "hr@company-careers.com",
        "brand": "Generic",
        "body": """Hi there,

Following up on our previous correspondence â€“ your request has been approved. To complete the process, we need you to confirm a few details via our secure portal.

This is a time-sensitive matter. Please use the link below to access your personalized dashboard and complete the verification.

[Access Secure Portal]

We look forward to working with you. If you did not initiate this request, please contact our support team immediately.

Human Resources""",
        "difficulty": "hard",
        "red_flags": ["Reference to 'previous correspondence' you may not recall", "Fake urgency", "Personalized dashboard link", "Vague 'request'"],
    },
]

PHISHING_EMAIL_TEMPLATES: list[dict] = _BUILTIN_EMAIL_TEMPLATES + LINKSEC_EMAIL_TEMPLATES

LEGITIMATE_EMAIL_TEMPLATES: list[dict] = [
    {
        "subject": "Your monthly newsletter â€“ February 2025",
        "sender": "newsletter@company.com",
        "body": """Hi,

Your monthly newsletter is ready. This month we cover:

- New product updates
- Upcoming webinars
- Tips and best practices

To read the full newsletter, visit our website (company.com) or log in to your account.

Best,
The Team""",
        "difficulty": "easy",
        "red_flags": [],
    },
    {
        "subject": "Team meeting reminder â€“ Friday 2pm",
        "sender": "calendar@yourcompany.org",
        "body": """Reminder: Team standup on Friday at 2:00 PM.

Location: Conference Room B (or join via Teams link in your calendar invite).

Please prepare your brief status update.

Thanks.""",
        "difficulty": "easy",
        "red_flags": [],
    },
    {
        "subject": "Your order has been dispatched â€“ Order #38271",
        "sender": "orders@shop.example.com",
        "body": """Hi,

Your order #38271 has been dispatched and is on its way.

Estimated delivery: 2â€“3 working days.

To track your parcel, log in to your account at shop.example.com and visit the Orders section.

If you have any questions, reply to this email or call our customer service line.

Thanks for shopping with us.

The Dispatch Team""",
        "difficulty": "easy",
        "red_flags": [],
    },
    {
        "subject": "IT maintenance window â€“ Sunday 11pm to 1am",
        "sender": "it-support@yourcompany.org",
        "body": """Dear all,

Please be aware that there will be a scheduled maintenance window this Sunday from 23:00 to 01:00.

During this time the following services will be unavailable:
- VPN
- Internal file shares
- Email (inbound delivery may be delayed)

No action is required from you. If you have urgent work, please save and close your files before 23:00.

IT Support""",
        "difficulty": "medium",
        "red_flags": [],
    },
    {
        "subject": "Your password was successfully changed",
        "sender": "no-reply@accounts.yourcompany.org",
        "body": """Hi,

Your account password was changed successfully on 14 Feb 2025 at 09:32.

If you made this change, no action is needed.

If you did not change your password, please contact IT Support immediately at it-support@yourcompany.org or call the helpdesk on extension 4321.

Security Team""",
        "difficulty": "medium",
        "red_flags": [],
    },
    {
        "subject": "Expense report approved â€“ January 2025",
        "sender": "finance@yourcompany.org",
        "body": """Hi Sarah,

Your expense report for January 2025 has been reviewed and approved.

Total approved: Â£342.50

Payment will be made to your registered bank account in the next pay run (28 Feb 2025).

If you have any questions, contact finance@yourcompany.org.

Finance Team""",
        "difficulty": "medium",
        "red_flags": [],
    },
    {
        "subject": "New message from your GP surgery",
        "sender": "noreply@patientaccess.com",
        "body": """Hi,

You have a new message waiting in your Patient Access account.

To read your message, log in at patientaccess.com using your usual username and password.

Please do not reply to this email â€“ it is sent from an unmonitored address.

Patient Access""",
        "difficulty": "hard",
        "red_flags": [],
    },
    {
        "subject": "Your annual leave request has been approved",
        "sender": "hr@yourcompany.org",
        "body": """Hi James,

Your annual leave request for 24â€“28 March 2025 has been approved by your line manager.

Your remaining annual leave balance is 12 days.

Please ensure your out-of-office is set and your handover notes are shared with the team before you go.

HR Team""",
        "difficulty": "hard",
        "red_flags": [],
    },
]

VISHING_SCENARIOS: list[dict] = [
    {
        "title": "IT Support Password Reset",
        "scenario": "You receive a call from someone claiming to be from IT Support. They say your password will expire in 2 hours and they need to 'verify' it over the phone to renew it.",
        "caller_pretext": "IT Support / Help Desk",
        "objective": "Obtain your password or have you type it into a fake portal",
        "red_flags": ["Real IT never asks for your password", "Urgent deadline", "Caller initiated contact"],
        "correct_response": "Decline. Hang up and call IT using the number on the company website or your ID badge.",
        "difficulty": "easy",
    },
    {
        "title": "Bank Fraud Alert",
        "scenario": "Caller says they are from your bank's fraud department. They report a suspicious transaction and ask you to confirm your full card number and CVV to 'cancel the transaction'.",
        "caller_pretext": "Bank Fraud Department",
        "objective": "Steal card details",
        "red_flags": ["Banks never ask for full card number or CVV on outbound calls", "Caller creates urgency with 'fraud'"],
        "correct_response": "Do not give any card details. Hang up and call the number on the back of your card.",
        "difficulty": "medium",
    },
    {
        "title": "Executive Impersonation",
        "scenario": "Someone claiming to be your CEO or a senior executive calls. They say they are in a meeting and need you to urgently purchase gift cards and send the codes. They promise to reimburse you.",
        "caller_pretext": "CEO / Senior Executive",
        "objective": "Get gift card codes (untraceable payment)",
        "red_flags": ["Gift cards as payment", "Urgency and secrecy", "Unusual request for your role"],
        "correct_response": "Do not buy gift cards. Verify through official channels (e.g. internal chat or second call to known number).",
        "difficulty": "hard",
    },
]


def get_simulated_emails() -> list[SimulatedEmail]:
    """Return list of simulated phishing emails for training (built-in + LinkSec brand templates)."""
    return [
        SimulatedEmail(
            id=f"email_{i}",
            subject=t["subject"],
            sender=t["sender"],
            body=t["body"],
            brand=t.get("brand", "Generic"),
            category=PhishingCategory.EMAIL,
            difficulty=t["difficulty"],
            red_flags=t["red_flags"],
            is_phishing=True,
        )
        for i, t in enumerate(PHISHING_EMAIL_TEMPLATES)
    ]


def get_simulated_email_by_id(email_id: str) -> SimulatedEmail | None:
    """Get a single simulated email by id (e.g. email_0, email_1). Returns None if not found."""
    for e in get_simulated_emails():
        if e.id == email_id:
            return e
    return None


def get_random_simulated_email() -> SimulatedEmail:
    """Return one random simulated email (for quick simulation)."""
    emails = get_simulated_emails()
    return random.choice(emails)


def get_random_game_email() -> dict:
    """
    Return one random email for the mini game (phishing or legitimate).
    Selection is 50/50 to give a fair challenge regardless of pool sizes.
    """
    pool = LEGITIMATE_EMAIL_TEMPLATES if random.random() < 0.5 else PHISHING_EMAIL_TEMPLATES
    t = random.choice(pool)
    is_phishing = pool is PHISHING_EMAIL_TEMPLATES
    return {
        "id": f"game_{random.randint(1000, 9999)}",
        "subject": t["subject"],
        "sender": t["sender"],
        "body": t["body"],
        "brand": t.get("brand", "Legitimate" if not is_phishing else "Generic"),
        "difficulty": t["difficulty"],
        "is_phishing": is_phishing,
        "red_flags": t["red_flags"],
    }


def get_vishing_scenarios() -> list[VishingScenario]:
    """Return list of vishing scenarios for training."""
    return [
        VishingScenario(
            id=f"vish_{i}",
            title=s["title"],
            scenario=s["scenario"],
            caller_pretext=s["caller_pretext"],
            objective=s["objective"],
            red_flags=s["red_flags"],
            correct_response=s["correct_response"],
            difficulty=s["difficulty"],
        )
        for i, s in enumerate(VISHING_SCENARIOS)
    ]


AI_PHRASE_INDICATORS = [
    r"\bkindly\b",
    r"\bplease do not hesitate\b",
    r"\bat your earliest convenience\b",
    r"\bI hope this (email|message) finds you well\b",
    r"\bvalued (customer|client|member)\b",
    r"\brest assured\b",
    r"\bgoing forward\b",
    r"\bensure\b",
    r"\bregarding your (account|request)\b",
    r"\bas per our records\b",
    r"\bwe are reaching out\b",
    r"\bpursuant to\b",
    r"\bkindly be advised\b",
]

URGENCY_INDICATORS = [
    r"\burgent\b",
    r"\bimmediately\b",
    r"\bwithin \d+ (hours?|minutes?|days?)\b",
    r"\bact now\b",
    r"\btime.?sensitive\b",
    r"\bexpir(e|ing)\b",
    r"\bsuspend(ed)?\b",
    r"\bverify (now|immediately)\b",
    r"\bclose of business\b",
    r"\btoday only\b",
    r"\bbefore midnight\b",
    r"\byou must act\b",
    r"\bfailure to (respond|act|verify|complete)\b",
]

PHISHING_RED_FLAGS = [
    r"click (here|the link below|below)",
    r"verify (your|my) (account|identity|details)",
    r"confirm (your|my) (details|information|identity|credentials)",
    r"secure (portal|link|page)",
    r"unusual (activity|sign.?in|login|access)",
    r"account (suspension|restriction|locked|frozen|compromised)",
    r"\[.*\]",  # Placeholder links like [Verify My Account]
    r"update (your )?(payment|billing|card) (details|information)",
    r"(gift card|amazon gift card|google play card|itunes card)",
    r"redemption code",
    r"wire transfer",
    r"your (credentials|password|pin)\b.*(over the phone|via (email|text))",
    r"arrest|warrant|bailiff|prosecution",
    r"bitcoin|cryptocurrency",
]



_FREE_SMTP_PROVIDERS = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.uk", "hotmail.com",
    "outlook.com", "live.com", "msn.com", "aol.com", "mail.com",
    "protonmail.com", "icloud.com", "me.com", "yandex.com", "zoho.com",
    "gmx.com", "gmx.net", "tutanota.com",
}

_SUSPICIOUS_RELAY_KEYWORDS = [
    "sendgrid", "mailgun", "amazonses", "mandrill", "sparkpost",
    "mailjet", "postmark", "smtp2go", "elasticemail",
]


def _extract_domain(addr: str) -> str:
    """Extract lowercase domain from an email address string."""
    m = re.search(r"@([\w.\-]+)", addr or "")
    return m.group(1).lower() if m else ""


def _extract_display_name(addr: str) -> str:
    """Extract display name from 'Display Name <addr>' format."""
    m = re.match(r'^"?([^"<]+)"?\s*<', addr or "")
    return m.group(1).strip().lower() if m else ""


def _is_private_ip(ip_str: str) -> bool:
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return False


def parse_raw_email(raw_source: str) -> dict:
    """
    Parse raw email source to extract header-level phishing signals.

    Returns a dict with:
      - header_findings: list of human-readable finding strings
      - header_flags: list of short flag codes (for scoring)
      - extracted_headers: dict of key header values for display
      - body_text: plain-text body for content analysis
    """
    findings: list[str] = []
    flags: list[str] = []
    extracted: dict = {}

    try:
        msg = email.message_from_string(raw_source, policy=email.policy.compat32)
    except Exception:
        return {"header_findings": [], "header_flags": [], "extracted_headers": {}, "body_text": raw_source}

    from_hdr       = msg.get("From", "")
    reply_to_hdr   = msg.get("Reply-To", "")
    return_path    = msg.get("Return-Path", "")
    subject        = msg.get("Subject", "")
    message_id     = msg.get("Message-ID", "")
    auth_results   = msg.get("Authentication-Results", "") or msg.get("ARC-Authentication-Results", "")
    received_spf   = msg.get("Received-SPF", "")
    dkim_sig       = msg.get("DKIM-Signature", "")
    x_mailer       = msg.get("X-Mailer", "")
    x_orig_ip      = msg.get("X-Originating-IP", "") or msg.get("X-Sender-IP", "")
    received_hdrs  = msg.get_all("Received") or []

    extracted = {
        "From":                from_hdr,
        "Reply-To":            reply_to_hdr or "(not set)",
        "Return-Path":         return_path or "(not set)",
        "Subject":             subject,
        "Message-ID":          message_id,
        "Authentication-Results": auth_results or "(not present)",
        "Received-SPF":        received_spf or "(not present)",
        "DKIM-Signature":      "Present" if dkim_sig else "MISSING",
        "X-Mailer":            x_mailer or "(not set)",
        "X-Originating-IP":    x_orig_ip or "(not set)",
    }

    from_domain       = _extract_domain(from_hdr)
    reply_to_domain   = _extract_domain(reply_to_hdr)
    return_path_domain = _extract_domain(return_path)
    msgid_domain      = _extract_domain(message_id)
    display_name      = _extract_display_name(from_hdr)

    # Reply-To mismatch
    if reply_to_hdr and reply_to_domain and reply_to_domain != from_domain:
        findings.append(
            f"Reply-To domain '{reply_to_domain}' differs from From domain '{from_domain}'. "
            "Replies will go to a different address than where the email claims to be from."
        )
        flags.append("reply_to_mismatch")

    # Return-Path mismatch
    if return_path and return_path_domain and return_path_domain != from_domain:
        findings.append(
            f"Return-Path domain '{return_path_domain}' does not match From domain '{from_domain}'. "
            "This is a strong indicator of spoofing or a compromised relay."
        )
        flags.append("return_path_mismatch")

    # SPF
    spf_text = (received_spf + " " + auth_results).lower()
    if "spf=fail" in spf_text:
        findings.append("SPF check FAILED â€“ the sending server is not authorised to send email for this domain.")
        flags.append("spf_fail")
    elif "spf=softfail" in spf_text:
        findings.append("SPF check returned SOFTFAIL â€“ the domain owner discourages this sending server.")
        flags.append("spf_softfail")
    elif "spf=none" in spf_text:
        findings.append("No SPF record found for the sending domain â€“ the domain has no anti-spoofing policy.")
        flags.append("spf_none")
    elif "spf=pass" in spf_text:
        extracted["SPF"] = "PASS"

    # DKIM
    dkim_text = auth_results.lower()
    if "dkim=fail" in dkim_text:
        findings.append("DKIM signature FAILED â€“ the email content may have been tampered with in transit.")
        flags.append("dkim_fail")
    elif not dkim_sig and "dkim=pass" not in dkim_text:
        findings.append("No DKIM signature present â€“ legitimate organisations almost always sign their emails.")
        flags.append("no_dkim")

    # DMARC
    if "dmarc=fail" in auth_results.lower():
        findings.append("DMARC policy FAILED â€“ this email failed the domain's anti-impersonation policy.")
        flags.append("dmarc_fail")
    elif "dmarc=none" in auth_results.lower():
        findings.append("No DMARC policy set for this domain â€“ the domain has no impersonation protection.")
        flags.append("dmarc_none")

    # Free provider impersonation
    if from_domain in _FREE_SMTP_PROVIDERS and display_name:
        findings.append(
            f"Email claims to be from '{display_name}' but is sent via a free provider ({from_domain}). "
            "Legitimate businesses do not use free email services for official communications."
        )
        flags.append("free_provider_impersonation")

    # Display name impersonation
    _known_brands = {
        "paypal": "paypal.com", "microsoft": "microsoft.com", "google": "google.com",
        "amazon": "amazon.com", "apple": "apple.com", "netflix": "netflix.com",
        "barclays": "barclays.co.uk", "hsbc": "hsbc.co.uk", "lloyds": "lloyds.co.uk",
        "natwest": "natwest.com", "halifax": "halifax.co.uk", "santander": "santander.co.uk",
        "hmrc": "hmrc.gov.uk", "gov.uk": "gov.uk", "dvla": "dvla.gov.uk",
        "facebook": "facebook.com", "instagram": "instagram.com", "linkedin": "linkedin.com",
        "dropbox": "dropbox.com", "docusign": "docusign.com", "zoom": "zoom.us",
        "flywire": "flywire.com",
    }
    for brand, legit_domain in _known_brands.items():
        if brand in display_name and legit_domain not in from_domain:
            findings.append(
                f"Display name contains '{brand}' but the sending domain is '{from_domain}', "
                f"not '{legit_domain}'. This is a display name spoofing attack."
            )
            flags.append("display_name_spoof")
            break

    # Message-ID domain mismatch
    if msgid_domain and from_domain and msgid_domain != from_domain:
        findings.append(
            f"Message-ID domain '{msgid_domain}' does not match From domain '{from_domain}'. "
            "Can indicate the email was sent from a different server than claimed."
        )
        flags.append("msgid_domain_mismatch")

    # Suspicious bulk relay
    received_str = " ".join(received_hdrs).lower()
    for relay in _SUSPICIOUS_RELAY_KEYWORDS:
        if relay in received_str:
            findings.append(
                f"Email was relayed via a bulk-sending service ({relay}). "
                "Phishing campaigns often abuse bulk email platforms."
            )
            flags.append("bulk_relay")
            break

    # Spoofed internal IP
    if x_orig_ip:
        ip_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", x_orig_ip)
        if ip_match and _is_private_ip(ip_match.group(1)):
            findings.append(
                f"X-Originating-IP is a private/internal address ({ip_match.group(1)}). "
                "This header may have been forged to appear as an internal email."
            )
            flags.append("spoofed_internal_ip")

    body_text = ""
    try:
        if msg.is_multipart():
            for part in msg.walk():
                ct = part.get_content_type()
                if ct == "text/plain":
                    body_text = part.get_payload(decode=True).decode("utf-8", errors="replace")
                    break
            if not body_text:
                for part in msg.walk():
                    if part.get_content_type() == "text/html":
                        html = part.get_payload(decode=True).decode("utf-8", errors="replace")
                        body_text = re.sub(r"<[^>]+>", " ", html)
                        break
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                body_text = payload.decode("utf-8", errors="replace")
            else:
                body_text = str(msg.get_payload())
    except Exception:
        body_text = raw_source

    if not body_text.strip():
        body_text = raw_source

    return {
        "header_findings": findings,
        "header_flags":    flags,
        "extracted_headers": extracted,
        "body_text":       body_text,
    }


def analyze_text_for_ai_phishing(
    text: str,
    context: str | None = None,
    raw_email: str | None = None,
) -> DetectionResult:
    """
    Analyse text or raw email source for phishing indicators.

    Four complementary methods are combined:
    1. Header analysis  â€“ domain spoofing, SPF/DKIM/DMARC, Reply-To mismatches
                          (only when raw_email is provided)
    2. Heuristic regex  â€“ urgency, AI-phrase, and red-flag pattern matching
    3. Dataset scoring  â€“ term-frequency analysis from SpamAssassin/CEAS/Enron corpora
    4. ML model scoring â€“ TF-IDF + NaÃ¯ve Bayes and Random Forest ensemble
                          trained on phishing/legitimate email datasets (Joblib)

    When raw_email is provided the body is extracted automatically and the
    header findings are included in the result.
    """
    header_findings: list[str] = []
    header_flags:    list[str] = []
    extracted_headers: dict   = {}
    header_score_boost: float = 0.0

    if raw_email and raw_email.strip():
        parsed = parse_raw_email(raw_email)
        header_findings  = parsed["header_findings"]
        header_flags     = parsed["header_flags"]
        extracted_headers = parsed["extracted_headers"]
        body_for_analysis = parsed["body_text"]
        _high_severity = {"spf_fail", "dkim_fail", "dmarc_fail", "reply_to_mismatch",
                          "display_name_spoof", "free_provider_impersonation"}
        _med_severity  = {"spf_softfail", "return_path_mismatch", "msgid_domain_mismatch",
                          "no_dkim", "bulk_relay", "spf_none", "dmarc_none"}
        for f in header_flags:
            if f in _high_severity:
                header_score_boost += 0.18
            elif f in _med_severity:
                header_score_boost += 0.08
        header_score_boost = min(header_score_boost, 0.55)
    else:
        body_for_analysis = text

    full_text = f"{context or ''}\n{body_for_analysis}".strip()

    ai_indicators = _score_indicators(full_text, AI_PHRASE_INDICATORS)
    urgency       = _score_indicators(full_text, URGENCY_INDICATORS)
    red_flags     = _score_indicators(full_text, PHISHING_RED_FLAGS)

    all_signals = ai_indicators + urgency + red_flags
    n = len(all_signals)

    if n >= 5:
        heuristic_conf = min(0.95, 0.5 + n * 0.08)
    elif n >= 3:
        heuristic_conf = min(0.85, 0.4 + n * 0.1)
    elif n >= 1:
        heuristic_conf = 0.3 + n * 0.15
    else:
        heuristic_conf = 0.2

    dataset_result: dict = {"dataset_score": 0.2, "top_phishing_terms": [], "dataset_source": []}
    try:
        from .dataset_loader import score_text_against_dataset
        dataset_result = score_text_against_dataset(full_text, mode="email")
    except Exception:
        pass

    dataset_conf: float      = dataset_result.get("dataset_score", 0.2)
    dataset_terms: list[str] = dataset_result.get("top_phishing_terms", [])

    ml_score: float = 0.5
    ml_result: dict = {}
    try:
        from .ml_models import classify_email_text
        ml_result = classify_email_text(full_text)
        ml_score  = ml_result.get("ensemble_score", 0.5)
    except Exception:
        pass

    # Blend: header boost + 40% heuristic + 25% dataset + 35% ML
    blended_conf = round(
        header_score_boost
        + (heuristic_conf * 0.40)
        + (dataset_conf   * 0.25)
        + (ml_score       * 0.35),
        3,
    )
    blended_conf = min(blended_conf, 0.99)

    if blended_conf >= 0.75:
        risk_level = "critical"
    elif blended_conf >= 0.55:
        risk_level = "high"
    elif blended_conf >= 0.35:
        risk_level = "medium"
    else:
        risk_level = "low"

    is_likely_phishing = blended_conf >= 0.5

    recommendations: list[str] = []
    if header_flags:
        critical_flags = [f for f in header_flags if f in
                          {"spf_fail", "dkim_fail", "dmarc_fail", "display_name_spoof",
                           "reply_to_mismatch", "free_provider_impersonation"}]
        if critical_flags:
            recommendations.append(
                "Header analysis detected serious spoofing indicators. "
                "Do NOT reply to or click any links in this email."
            )
        else:
            recommendations.append(
                "Header anomalies were detected. Verify the sender's domain against "
                "the official organisation website before taking any action."
            )
    if ai_indicators:
        recommendations.append("Text contains phrases commonly seen in AI-generated or template-based phishing emails.")
    if urgency:
        recommendations.append("High urgency language detected â€“ a common tactic to pressure recipients into acting without thinking.")
    if red_flags:
        recommendations.append("Do not click links or share credentials. Contact the organisation via their official website directly.")
    if dataset_terms:
        recommendations.append(
            f"High-risk terms detected: {', '.join(dataset_terms[:5])}. "
            "These frequently appear in known phishing emails (SpamAssassin, CEAS 2008, Enron-Spam corpora)."
        )
    if ml_result and ml_result.get("nb_label") == "phishing" and ml_result.get("rf_label") == "phishing":
        recommendations.append(
            f"Both ML classifiers (NaÃ¯ve Bayes: {ml_result['nb_confidence']:.0%}, "
            f"Random Forest: {ml_result['rf_confidence']:.0%}) flag this as phishing."
        )
    if not recommendations:
        recommendations.append("No strong indicators found. When in doubt, verify the sender through a known official channel.")

    return DetectionResult(
        is_likely_phishing=is_likely_phishing,
        confidence=blended_conf,
        ai_generated_indicators=ai_indicators,
        red_flags=list(dict.fromkeys(urgency + red_flags)),
        recommendations=recommendations,
        risk_level=risk_level,
        header_findings=header_findings,
        extracted_headers=extracted_headers,
        ml_scores=ml_result,
    )
