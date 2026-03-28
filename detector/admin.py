
from django.contrib import admin
from .models import SMSMessage

@admin.register(SMSMessage)
class SMSMessageAdmin(admin.ModelAdmin):
    list_display = ('message', 'prediction', 'created_at')
    list_filter = ('prediction', 'created_at')
    search_fields = ('message',)
    ordering = ('-created_at',)

# Register your models here.
