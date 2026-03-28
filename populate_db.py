import os
import django
import random
from datetime import timedelta
from django.utils import timezone

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "malwaredetection.settings")
django.setup()

from virus.models import Register, UserFile, Urls, Feedback
from detector.models import SMSMessage
from fraud_detection.models import UPIID

def populate():
    print("Clearing old data...")
    UserFile.objects.all().delete()
    Urls.objects.all().delete()
    SMSMessage.objects.all().delete()
    UPIID.objects.all().delete()
    Feedback.objects.all().delete()
    
    # Ensure there is at least one user
    user, created = Register.objects.get_or_create(
        email="testuser@example.com",
        defaults={"username": "Test User", "password": "password123"}
    )
    print("Populating Files...")
    # Safe files
    for i in range(12):
        UserFile.objects.create(
            user=user,
            file_name=f"document_safe_{i}.pdf",
            vt_harmless=10,
            vt_malicious=0,
            vt_suspicious=0,
            is_malicious=False,
            is_pending=False,
            malware_type=None
        )
    # Malicious files
    for i in range(5):
        UserFile.objects.create(
            user=user,
            file_name=f"invoice_fake_{i}.pdf.exe",
            vt_harmless=2,
            vt_malicious=45,
            vt_suspicious=2,
            is_malicious=True,
            is_pending=False,
            malware_type="Trojan"
        )
    # Suspicious files
    for i in range(3):
        UserFile.objects.create(
            user=user,
            file_name=f"unknown_setup_{i}.zip",
            vt_harmless=5,
            vt_malicious=0,
            vt_suspicious=5,
            is_malicious=False, # It might be marked false but has suspicious hits
            is_pending=False,
            malware_type="Adware"
        )

    print("Populating URLs...")
    for i in range(8):
        Urls.objects.create(user=user, link=f"https://example.com/safe/{i}", status="SAFE")
    for i in range(4):
        Urls.objects.create(user=user, link=f"https://paytmlm.com/login-{i}", status="SCAM")

    print("Populating SMS...")
    for i in range(15):
        SMSMessage.objects.create(message=f"Hey are we still meeting at {i} PM?", status="Safe", risk_score=0)
    for i in range(6):
        SMSMessage.objects.create(message=f"Dear user, your KYC is pending {i}. Click here to update.", status="SCAM", risk_score=85)

    print("Populating UPIs...")
    for i in range(10):
        UPIID.objects.create(upi_id=f"user{i}@okhdfcbank", status="Safe", risk_score=0, reported_count=0)
    for i in range(4):
        UPIID.objects.create(upi_id=f"sbi-refund{i}@okicici", status="Fraud", risk_score=95, reported_count=5)
    for i in range(3):
        UPIID.objects.create(upi_id=f"987654321{i}@paytm", status="Suspicious", risk_score=50, reported_count=2)

    print("Populating Feedback...")
    Feedback.objects.create(user=user, message="Great tool, really helped me identify a phishing link!", rating=5)
    Feedback.objects.create(user=user, message="Good but sometimes slow.", rating=4)
    Feedback.objects.create(user=user, message="Very useful for checking APKs.", rating=5)

    print("Done! Admin dashboard is now populated.")

if __name__ == '__main__':
    populate()
