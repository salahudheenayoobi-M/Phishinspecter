from django import forms
from .models import UserFile
class UserFileform(forms.ModelForm):
    class Meta:
        model=UserFile
        fields=['file_name']
