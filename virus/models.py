from django.db import models

# Create your models here.

class Register(models.Model):
    username=models.CharField(max_length=100,null=True,blank=True)
    age=models.IntegerField(null=True,blank=True)
    email=models.EmailField(max_length=100,unique=True)
    password=models.CharField(max_length=100)
    image=models.FileField(upload_to='images/',null=True,blank=True)

    def __str__ (self):
        return self.username

class UserFile(models.Model):
    user = models.ForeignKey('Register', on_delete=models.CASCADE)
    file_name = models.CharField(max_length=255, blank=True, null=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    vt_analysis_id = models.CharField(max_length=255, blank=True, null=True)
    vt_malicious = models.PositiveIntegerField(default=0)
    vt_harmless = models.PositiveIntegerField(default=0)
    vt_suspicious = models.PositiveIntegerField(default=0)
    vt_undetected = models.PositiveIntegerField(default=0)

    is_malicious = models.BooleanField(default=False)
    is_pending = models.BooleanField(default=True)
    malware_type = models.CharField(max_length=100, null=True, blank=True)

    # Advanced scan fields
    file_sha256 = models.CharField(max_length=64, null=True, blank=True)
    file_size = models.PositiveBigIntegerField(null=True, blank=True)
    risk_score = models.PositiveIntegerField(default=0)
    scan_details = models.TextField(null=True, blank=True)  # JSON string of check results

class Urls(models.Model):
    user=models.ForeignKey(Register,on_delete=models.SET_NULL,null=True)
    link=models.URLField(null=True,blank=True)
    created_at=models.DateTimeField(auto_now_add=True,null=True)
    status=models.CharField(max_length=20,null=True,blank=True)

class Feedback(models.Model):
    user = models.ForeignKey('Register', on_delete=models.CASCADE, null=True, blank=True)
    message = models.TextField()
    rating = models.IntegerField(default=5)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Feedback from {self.user.username if self.user else 'Anonymous'}"
