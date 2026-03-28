from django.db import models

class SMSMessage(models.Model):
    message = models.TextField()
    prediction = models.CharField(max_length=10)  # old: 'spam' or 'ham'
    
    # New Advanced Risk Engine Fields
    risk_score = models.IntegerField(default=0)
    status = models.CharField(max_length=20, default="SAFE") # SAFE, SUSPICIOUS, SCAM
    risk_breakdown = models.JSONField(default=dict)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.message[:30]}... [{self.status} | Score: {self.risk_score}]"