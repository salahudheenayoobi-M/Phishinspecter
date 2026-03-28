import json
import re

from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.db import transaction
from django.db.models import Avg

from .models import UPIID, FraudReport, TransactionSignal
from .risk_engine import calculate_risk

_UPI_RE = re.compile(r'^[\w.\-]{2,256}@[a-zA-Z]{2,64}$')


def _parse_json(request):
    try:
        return json.loads(request.body)
    except (json.JSONDecodeError, ValueError):
        raise ValueError("Invalid JSON body")


def _validate_upi(upi_id):
    if not upi_id:
        raise ValueError("upi_id is required")
    upi_id = upi_id.strip().lower()
    if len(upi_id) > 100:
        raise ValueError("upi_id is too long")
    if not _UPI_RE.match(upi_id):
        raise ValueError("Invalid UPI ID format (expected: user@bank)")
    return upi_id


def _get_client_ip(request):
    x_forwarded = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded:
        return x_forwarded.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR')


# ── CHECK UPI ─────────────────────────────────────────────────────────────────

@csrf_exempt
@require_http_methods(["POST"])
def check_upi(request):
    try:
        data   = _parse_json(request)
        upi_id = _validate_upi(data.get("upi_id"))
    except ValueError as exc:
        return JsonResponse({"error": str(exc)}, status=400)

    upi, _ = UPIID.objects.get_or_create(upi_id=upi_id)
    upi.scan_count += 1
    upi.last_scan_ip = _get_client_ip(request)

    risk_score, status, breakdown = calculate_risk(upi)
    upi.risk_score     = risk_score
    upi.status         = status
    upi.risk_breakdown = breakdown
    if breakdown.get('fraud_type'):
        upi.fraud_type = breakdown['fraud_type']
    upi.save(update_fields=["risk_score", "status", "risk_breakdown",
                             "fraud_type", "scan_count", "last_scan_ip"])

    return JsonResponse({
        "upi_id":      upi.upi_id,
        "risk_score":  upi.risk_score,
        "status":      upi.status,
        "fraud_type":  upi.fraud_type or None,
        "breakdown":   breakdown,
        "scan_count":  upi.scan_count,
        "keywords":    breakdown.get("keywords", []),
        "signals": {
            "brand_impersonation": breakdown.get("brand_impersonation", False),
            "typosquatting":       breakdown.get("typosquatting", False),
            "all_numeric":         breakdown.get("all_numeric", False),
            "random_string":       breakdown.get("random_string", False),
            "ml_detected":         breakdown.get("ml_prediction", False),
            "new_account":         breakdown.get("new_account", {}).get("points", 0) > 0,
            "network_links":       breakdown.get("network_fraud", {}).get("linked", 0),
        }
    })


# ── REPORT UPI ────────────────────────────────────────────────────────────────

@csrf_exempt
@require_http_methods(["POST"])
def report_upi(request):
    try:
        data   = _parse_json(request)
        upi_id = _validate_upi(data.get("upi_id"))
    except ValueError as exc:
        return JsonResponse({"error": str(exc)}, status=400)

    fraud_type  = data.get("fraud_type", "other")
    description = data.get("description", "")[:500]
    amount_lost = data.get("amount_lost")

    with transaction.atomic():
        upi, _ = UPIID.objects.select_for_update().get_or_create(upi_id=upi_id)
        upi.reported_count += 1

        # Create detailed report
        FraudReport.objects.create(
            upi         = upi,
            fraud_type  = fraud_type,
            description = description,
            amount_lost = amount_lost,
            reporter_ip = _get_client_ip(request),
        )

        risk_score, status, breakdown = calculate_risk(upi)
        upi.risk_score     = risk_score
        upi.status         = status
        upi.risk_breakdown = breakdown
        if breakdown.get('fraud_type'):
            upi.fraud_type = breakdown['fraud_type']
        upi.save(update_fields=["reported_count", "risk_score", "status",
                                  "risk_breakdown", "fraud_type"])

    return JsonResponse({
        "message":        "UPI reported successfully",
        "reported_count": upi.reported_count,
        "risk_score":     upi.risk_score,
        "status":         upi.status,
        "fraud_type":     upi.fraud_type,
    }, status=200)


# ── FRAUD HISTORY ─────────────────────────────────────────────────────────────

@require_http_methods(["GET"])
def fraud_history(request):
    qs = UPIID.objects.order_by("-reported_count")

    status_filter = request.GET.get("status")
    if status_filter:
        allowed = {"Fraud", "Suspicious", "Safe"}
        if status_filter not in allowed:
            return JsonResponse(
                {"error": f"Invalid status filter. Allowed: {', '.join(sorted(allowed))}"},
                status=400
            )
        qs = qs.filter(status=status_filter)

    result = list(qs.values(
        "upi_id", "reported_count", "risk_score", "status",
        "fraud_type", "scan_count", "created_at", "last_checked"
    ))

    return JsonResponse(result, safe=False)


# ── UPI DATABASE PAGE ─────────────────────────────────────────────────────────

@require_http_methods(["GET"])
def upi_database(request):
    if not request.session.get('admin_logged_in'):
        return redirect('admin_login')

    qs = UPIID.objects.all()

    q = request.GET.get("q", "").strip()
    if q:
        qs = qs.filter(upi_id__icontains=q)

    status_filter = request.GET.get("status", "").strip()
    if status_filter in ("Safe", "Suspicious", "Fraud"):
        qs = qs.filter(status=status_filter)

    qs = qs.order_by("-last_checked")

    all_records = UPIID.objects.all()
    stats = {
        "total":      all_records.count(),
        "fraud":      all_records.filter(status="Fraud").count(),
        "suspicious": all_records.filter(status="Suspicious").count(),
        "safe":       all_records.filter(status="Safe").count(),
        "avg_score":  round(all_records.aggregate(Avg("risk_score"))["risk_score__avg"] or 0, 1),
    }

    return render(request, "upi_database.html", {
        "records":       qs,
        "stats":         stats,
        "q":             q,
        "status_filter": status_filter,
    })


# ── HTML PAGE ─────────────────────────────────────────────────────────────────

def check_page(request):
    return render(request, "check_upi.html")


# ── ANALYTICS API ─────────────────────────────────────────────────────────────

@require_http_methods(["GET"])
def analytics_api(request):
    """Returns aggregated fraud analytics data."""
    from django.db.models import Count, Sum
    all_records = UPIID.objects.all()
    
    fraud_types = (
        FraudReport.objects
        .values('fraud_type')
        .annotate(count=Count('id'))
        .order_by('-count')
    )

    return JsonResponse({
        "totals": {
            "total":      all_records.count(),
            "fraud":      all_records.filter(status="Fraud").count(),
            "suspicious": all_records.filter(status="Suspicious").count(),
            "safe":       all_records.filter(status="Safe").count(),
        },
        "fraud_types": list(fraud_types),
        "top_reported": list(
            all_records.order_by('-reported_count')[:5]
            .values('upi_id', 'reported_count', 'status', 'risk_score')
        ),
    })
