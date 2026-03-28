from django.contrib import admin
from .models import UPIID, FraudReport, TransactionSignal


@admin.register(UPIID)
class UPIIDAdmin(admin.ModelAdmin):
    list_display  = ('upi_id', 'status', 'risk_score', 'reported_count', 'scan_count',
                     'fraud_type', 'is_blacklisted', 'is_whitelisted', 'last_checked')
    list_filter   = ('status', 'is_blacklisted', 'is_whitelisted', 'fraud_type')
    search_fields = ('upi_id', 'fraud_type')
    ordering      = ('-reported_count',)
    readonly_fields = ('created_at', 'last_checked', 'risk_breakdown')
    actions       = ['mark_blacklisted', 'mark_whitelisted', 'clear_override']

    def mark_blacklisted(self, request, queryset):
        queryset.update(is_blacklisted=True, is_whitelisted=False)
    mark_blacklisted.short_description = "Blacklist selected UPI IDs"

    def mark_whitelisted(self, request, queryset):
        queryset.update(is_whitelisted=True, is_blacklisted=False)
    mark_whitelisted.short_description = "Whitelist selected UPI IDs"

    def clear_override(self, request, queryset):
        queryset.update(is_blacklisted=False, is_whitelisted=False)
    clear_override.short_description = "Clear blacklist/whitelist override"


@admin.register(FraudReport)
class FraudReportAdmin(admin.ModelAdmin):
    list_display  = ('upi', 'fraud_type', 'amount_lost', 'reporter_ip', 'reported_at')
    list_filter   = ('fraud_type',)
    search_fields = ('upi__upi_id', 'description')
    ordering      = ('-reported_at',)
    readonly_fields = ('reported_at', 'reporter_ip')


@admin.register(TransactionSignal)
class TransactionSignalAdmin(admin.ModelAdmin):
    list_display = ('upi', 'amount', 'success', 'risk_flag', 'signal_at')
    list_filter  = ('success', 'risk_flag')
    ordering     = ('-signal_at',)
