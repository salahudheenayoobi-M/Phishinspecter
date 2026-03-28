from django.db import models
from django.utils import timezone


class UPIID(models.Model):

    STATUS_CHOICES = [
        ('Safe',        'Safe'),
        ('Suspicious',  'Suspicious'),
        ('Fraud',       'Fraud'),
    ]

    # Core identity
    upi_id         = models.CharField(max_length=100, unique=True, db_index=True)
    reported_count = models.PositiveIntegerField(default=0)
    risk_score     = models.FloatField(default=0.0)
    status         = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='Safe',
    )

    # Advanced risk signals
    scan_count          = models.PositiveIntegerField(default=0)
    last_scan_ip        = models.GenericIPAddressField(null=True, blank=True)
    is_blacklisted      = models.BooleanField(default=False)
    is_whitelisted      = models.BooleanField(default=False)
    fraud_type          = models.CharField(max_length=100, blank=True)
    threat_intel_hits   = models.PositiveIntegerField(default=0)
    geo_risk_score      = models.FloatField(default=0.0)

    # Transaction-level signals (aggregated)
    avg_txn_amount      = models.FloatField(default=0.0)
    max_txn_amount      = models.FloatField(default=0.0)
    txn_velocity_24h    = models.PositiveIntegerField(default=0)
    txn_velocity_1h     = models.PositiveIntegerField(default=0)
    failed_txn_count    = models.PositiveIntegerField(default=0)

    # Network linkage
    linked_fraud_count  = models.PositiveIntegerField(default=0)

    # Risk breakdown (JSON)
    risk_breakdown      = models.JSONField(default=dict)

    created_at   = models.DateTimeField(auto_now_add=True)
    last_checked = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name        = 'UPI ID'
        verbose_name_plural = 'UPI IDs'
        ordering            = ['-reported_count']

    def __str__(self):
        return f"{self.upi_id} [{self.status}]"


class FraudReport(models.Model):
    FRAUD_TYPES = [
        ('phishing',        'Phishing'),
        ('impersonation',   'Brand Impersonation'),
        ('investment_scam', 'Investment Scam'),
        ('lottery',         'Lottery / Prize Scam'),
        ('job_scam',        'Job / Recruitment Scam'),
        ('kyc_fraud',       'KYC / OTP Fraud'),
        ('delivery_scam',   'Delivery Scam'),
        ('other',           'Other'),
    ]

    upi         = models.ForeignKey(UPIID, on_delete=models.CASCADE, related_name='reports')
    fraud_type  = models.CharField(max_length=30, choices=FRAUD_TYPES, default='other')
    description = models.TextField(blank=True)
    amount_lost = models.FloatField(null=True, blank=True)
    reporter_ip = models.GenericIPAddressField(null=True, blank=True)
    reported_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-reported_at']

    def __str__(self):
        return f"Report: {self.upi.upi_id} [{self.fraud_type}]"


class TransactionSignal(models.Model):
    upi         = models.ForeignKey(UPIID, on_delete=models.CASCADE, related_name='transaction_signals')
    amount      = models.FloatField()
    success     = models.BooleanField(default=True)
    risk_flag   = models.BooleanField(default=False)
    signal_at   = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-signal_at']
        indexes  = [models.Index(fields=['upi', 'signal_at'])]
