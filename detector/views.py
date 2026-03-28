import json
from django.shortcuts import render, redirect
from django.utils import timezone
from .models import SMSMessage
from .risk_engine import calculate_sms_risk


def check_sms(request):
    result_data = None

    if request.method == "POST":
        message = request.POST.get("message", "").strip()

        if not message:
            result_data = {"message": "Please enter a message to scan.", "status": "ERROR"}
        elif len(message) > 5000:
            result_data = {"message": "Message too long (max 5000 characters).", "status": "ERROR"}
        else:
            # ── Run through 9-layer risk engine ─────────────────────────────
            try:
                score, status, breakdown = calculate_sms_risk(message)
            except Exception as e:
                result_data = {"message": f"Scan error: {str(e)}", "status": "ERROR"}
            else:
                # ── Determine result message ─────────────────────────────────
                if status == "SCAM":
                    verdict = "🚨 CRITICAL THREAT: This message is a confirmed scam or phishing attempt."
                    categories = breakdown.get("matched_categories", [])
                    if categories:
                        verdict += f" Detected: {', '.join(c.replace('_', ' ').title() for c in categories[:3])}."
                elif status == "SUSPICIOUS":
                    verdict = "⚠️ SUSPICIOUS: This message contains risky patterns. Treat with caution."
                else:
                    verdict = "✅ SAFE: No obvious scam indicators detected."

                # ── Save full telemetry to database ──────────────────────────
                SMSMessage.objects.create(
                    message=message,
                    prediction=breakdown.get("ml_prediction", "ham"),
                    risk_score=score,
                    status=status,
                    risk_breakdown=breakdown,
                )

                # ── Build human-readable signal summary ──────────────────────
                signals_summary = []

                # Categories
                for cat in breakdown.get("matched_categories", []):
                    pts = breakdown.get("category_scores", {}).get(cat, 0)
                    signals_summary.append({
                        "name": cat.replace("_", " ").title(),
                        "detail": f"+{pts} pts",
                        "severity": "high" if pts >= 30 else "medium" if pts >= 20 else "low",
                    })

                # UPI links
                for link in breakdown.get("upi_links", []):
                    signals_summary.append({
                        "name": "UPI Payment Deep-Link",
                        "detail": link[:60] + ("…" if len(link) > 60 else ""),
                        "severity": "high",
                    })

                # Phone pressure
                if breakdown.get("phone_pressure") == True:
                    signals_summary.append({
                        "name": "Phone Number Pressure",
                        "detail": "Message pushes victim to call a number",
                        "severity": "medium",
                    })

                # Brand spoof
                if breakdown.get("brand_spoof"):
                    signals_summary.append({
                        "name": "Brand Impersonation",
                        "detail": "Trusted brand name + scam action detected",
                        "severity": "high",
                    })

                # Suspicious URLs
                for url_info in breakdown.get("urls", []):
                    if url_info.get("is_suspicious"):
                        signals_summary.append({
                            "name": "Suspicious URL",
                            "detail": url_info.get("reason", "")[:80],
                            "severity": "high",
                        })

                # Structural
                for sig in breakdown.get("structural_signals", []):
                    signals_summary.append({
                        "name": "Message Structure Signal",
                        "detail": sig,
                        "severity": "medium",
                    })

                # Hinglish
                if breakdown.get("hinglish_scam"):
                    signals_summary.append({
                        "name": "Hinglish Scam Pattern",
                        "detail": "Indian language phishing phrase detected",
                        "severity": "medium",
                    })

                # Emojis
                for emoji_hit in breakdown.get("scam_emojis", []):
                    signals_summary.append({
                        "name": "Scam Emoji Cluster",
                        "detail": emoji_hit,
                        "severity": "low",
                    })

                # ML
                ml = breakdown.get("ml_prediction", "ham")
                if str(ml).lower() in ("spam", "scam", "1"):
                    signals_summary.append({
                        "name": "ML Model: SPAM",
                        "detail": "Naive Bayes classifier flagged as spam",
                        "severity": "high",
                    })

                # Compound attack
                if breakdown.get("compound_attack"):
                    signals_summary.append({
                        "name": "Compound Attack Detected",
                        "detail": "Multiple high-risk categories fired simultaneously",
                        "severity": "high",
                    })

                result_data = {
                    "message": verdict,
                    "score":   score,
                    "status":  status,
                    "breakdown": breakdown,
                    "signals_summary": signals_summary,
                    "matched_categories": breakdown.get("matched_categories", []),
                }

    # Last 10 scanned messages for history display
    messages = SMSMessage.objects.order_by('-created_at')[:10]
    return render(request, "detector/check_sms.html", {
        "result_data": result_data,
        "messages": messages,
    })


# ── Admin Dashboard ───────────────────────────────────────────────────────────
def sms_dashboard(request):
    if not request.session.get('admin_logged_in'):
        return redirect('admin_login')
    messages = SMSMessage.objects.order_by('-created_at')
    return render(request, 'detector/sms_dashboard.html', {'messages': messages})