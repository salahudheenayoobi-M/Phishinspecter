"""
Advanced Risk Scoring Engine for UPI Fraud Detection.

Design Principles:
  1. Trusted providers give a SAFE BIAS — a legitimate name@oksbi should score low.
  2. Structural checks are CONTEXT-AWARE — they fire harder on unknown providers.
  3. Keyword/brand checks look at the LOCAL PART only, with smart pattern matching.
  4. Thresholds are calibrated so normal names on known banks stay SAFE.

Score Breakdown (max 100):
  Layer 0 - Overrides:
    - Blacklist override           : instant 100
    - Whitelist override           : instant 0

  Layer 1 - Identity Signals (keyword + patterns):
    - Reported complaints          : up to 50 pts
    - Brand impersonation          : 40 pts
    - Typosquatting detection      : 30 pts
    - Scam keywords in local part  : up to 30 pts
    - Threat intelligence hits     : up to 25 pts

  Layer 2 - Structural Heuristics:
    - Suspicious provider          : 25 pts
    - Unknown provider             : 8 pts  (context-aware — less on known banks)
    - All-numeric local part       : 15 pts  (reduced if on known provider)
    - Random/entropy string        : 12 pts  (only on unknown providers)
    - Excessive length (>40 chars) : 10 pts

  Layer 3 - Behavioral Signals:
    - High transaction velocity    : up to 20 pts
    - High avg transaction amount  : up to 10 pts
    - Failed transaction ratio     : up to 15 pts
    - New account (<1 day)         : 8 pts

  Layer 4 - Network Intelligence:
    - Linked fraud accounts        : up to 20 pts
    - ML model prediction          : up to 30 pts

  Safe bias:
    - Known trusted provider       : -10 pts (minimum 0)

  Thresholds:
    - Fraud:      >= 70
    - Suspicious: >= 40
    - Safe:       <  40
"""

import re
import math
from django.utils import timezone
from .scam_keywords import (
    detect_keywords, matched_keywords, detect_brand_impersonation,
    detect_typosquatting, get_provider_risk
)

try:
    from .ml.predict import predict_upi_fraud
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

MAX_SCORE = 100

# ── Known legitimate UPI providers (banks/apps registered with NPCI) ──────────
_TRUSTED_PROVIDERS = {
    # Google Pay / PhonePe / Paytm handles
    'okaxis', 'okhdfcbank', 'okicici', 'oksbi',
    'waaxis', 'wahdfcbank', 'waicici', 'wasbi',
    'ybl',          # PhonePe
    'ibl',          # PhonePe
    'axl',          # Axis
    'apl',          # Amazon Pay
    'paytm',
    'freecharge',
    'airtel',
    'jiomoney',
    # Banks
    'hdfcbank', 'icici', 'sbi', 'axisbank',
    'kotak', 'pnb', 'barodampay', 'idfcbank', 'idfc',
    'indus', 'rbl', 'federal', 'cnrb',
    'yesbankltd', 'superyes',
    'uboi', 'ubi', 'unionbank', 'mahb', 'idbi',
    'citi', 'hsbc', 'dbs', 'scb',
    'equitas', 'esaf', 'jkb', 'kvb',
    'tmbl', 'ucobank', 'dcb', 'aubank',
    'jupiteraxis', 'naviaxis', 'timecosmos',
    'ikwik', 'rajgovhdfcbank',
    # UPI handle
    'upi',
}

# ── High-risk UPI providers (commonly spoofed / free TLDs) ────────────────────
_HIGH_RISK_PROVIDERS = {
    'xyz', 'tk', 'ml', 'ga', 'cf', 'gq', 'pw',
    'temp', 'fake', 'test', 'fraud', 'scam',
    'win', 'prize', 'lucky', 'free',
}

# ── Patterns that definitely indicate a phone number being used as UPI ────────
_PHONE_PATTERN = re.compile(r'^[6-9]\d{9}$')   # Indian mobile: 10-digit, starts 6-9


def _is_phone_number(local_part: str) -> bool:
    return bool(_PHONE_PATTERN.match(local_part))


def _is_all_numeric(local_part: str) -> bool:
    return bool(re.match(r'^\d+$', local_part))


def _string_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def _is_random_looking(local_part: str) -> bool:
    """
    Returns True only when the local part strongly resembles a randomly-generated
    string (high entropy, very few vowels, many digits).
    Threshold raised to avoid flagging real names.
    """
    s = local_part.lower()
    # Remove digits first for vowel check on the alpha portion
    alpha = re.sub(r'\d', '', s)
    if len(s) < 8:              # Short IDs are common legitimate names
        return False
    if len(alpha) == 0:         # All-digit — handled by _is_all_numeric
        return False
    entropy    = _string_entropy(s)
    vowels     = sum(1 for c in alpha if c in 'aeiou')
    digits     = sum(1 for c in s if c.isdigit())
    vowel_ratio = vowels / max(len(alpha), 1)
    digit_ratio = digits / len(s)
    # Must hit ALL three thresholds — much stricter than before
    return entropy > 3.5 and vowel_ratio < 0.10 and digit_ratio > 0.4


def _classify_fraud_type(breakdown: dict, local_part: str) -> str:
    """Infer the most likely fraud category from signals."""
    if breakdown.get('brand_impersonation') or breakdown.get('typosquatting'):
        return 'Brand Impersonation'
    keywords = breakdown.get('keywords', [])
    if any(k in keywords for k in ['kyc', 'kycupdate', 'kycverify', 'kycexpired', 'otp', 'otpverify', 'verify', 'verifynow', 'aadhaar']):
        return 'KYC / OTP Fraud'
    if any(k in keywords for k in ['lottery', 'prize', 'winner', 'winprize', 'lucky', 'jackpot', 'luckyuser']):
        return 'Lottery Scam'
    if any(k in keywords for k in ['crypto', 'bitcoin', 'forex', 'mlm', 'doubler', 'ponzi', 'nft', 'airdrop', 'staking', 'defi']):
        return 'Investment / Crypto Scam'
    if any(k in keywords for k in ['workfromhome', 'earndaily', 'earnmoney', 'parttime']):
        return 'Job Scam'
    if any(k in keywords for k in ['courierheld', 'customsfee', 'parcelblock']):
        return 'Delivery Scam'
    if any(k in keywords for k in ['scammer', 'hacker', 'phish', 'phishing', 'fraud', 'fake', 'cheat', 'scam', 'hack']):
        return 'Known Scam Account'
    if breakdown.get('all_numeric') and not breakdown.get('on_trusted_provider'):
        return 'Phone Number UPI (Unknown Bank)'
    if breakdown.get('ml_prediction'):
        return 'Pattern-Matched Fraud'
    return 'Suspicious Activity'


def calculate_risk(upi) -> tuple:
    """
    Calculate advanced risk score (0-100) and status.
    Returns: (risk_score: int, status: str, breakdown: dict)
    """
    score     = 0
    breakdown = {}

    local_part = upi.upi_id.split("@")[0] if "@" in upi.upi_id else upi.upi_id
    provider   = upi.upi_id.split("@")[1].lower() if "@" in upi.upi_id else ""

    on_trusted_provider   = provider in _TRUSTED_PROVIDERS
    on_high_risk_provider = provider in _HIGH_RISK_PROVIDERS

    breakdown['on_trusted_provider']   = on_trusted_provider
    breakdown['on_high_risk_provider'] = on_high_risk_provider

    # ── LAYER 0: Override checks ─────────────────────────────────────────────
    if upi.is_blacklisted:
        return 100, 'Fraud', {'override': 'blacklisted', 'fraud_type': 'Manually Blacklisted'}

    if upi.is_whitelisted:
        return 0, 'Safe', {'override': 'whitelisted'}

    # ── LAYER 1: Identity & Complaint Signals ────────────────────────────────

    # 1a. Reported complaints (weighted log scale)
    rc = upi.reported_count
    if rc >= 10:
        pts = 50
    elif rc >= 5:
        pts = 40
    elif rc >= 2:
        pts = 25
    elif rc == 1:
        pts = 12
    else:
        pts = 0
    score += pts
    breakdown['reports'] = {'count': rc, 'points': pts}

    # 1b. Brand impersonation (local part has "sbisupport", "hdfckyc" etc.)
    if detect_brand_impersonation(upi.upi_id):
        score += 40
        breakdown['brand_impersonation'] = True
    else:
        breakdown['brand_impersonation'] = False

    # 1c. Typosquatting
    if detect_typosquatting(upi.upi_id):
        score += 30
        breakdown['typosquatting'] = True
    else:
        breakdown['typosquatting'] = False

    # 1d. Scam keywords in local part
    found_keywords = matched_keywords(upi.upi_id)
    if found_keywords:
        kw_pts = min(len(found_keywords) * 10, 30)
        score += kw_pts
        breakdown['keywords'] = found_keywords
    else:
        breakdown['keywords'] = []

    # 1e. Threat intelligence hits
    if upi.threat_intel_hits > 0:
        ti_pts = min(upi.threat_intel_hits * 8, 25)
        score += ti_pts
        breakdown['threat_intel'] = {'hits': upi.threat_intel_hits, 'points': ti_pts}
    else:
        breakdown['threat_intel'] = {'hits': 0, 'points': 0}

    # ── LAYER 2: Structural Heuristics ──────────────────────────────────────

    # 2a. High-risk / suspicious provider
    if on_high_risk_provider:
        score += 25
        breakdown['suspicious_provider'] = True
    else:
        breakdown['suspicious_provider'] = False

    # 2b. Unknown provider — less weight on trusted providers
    if provider and not on_trusted_provider and not on_high_risk_provider:
        score += 8
        breakdown['unknown_provider'] = True
    else:
        breakdown['unknown_provider'] = False

    # 2c. All-numeric local part
    #     Phone numbers on trusted providers = slightly suspicious (people share numbers)
    #     Phone numbers on unknown providers = more suspicious
    if _is_all_numeric(local_part):
        is_phone = _is_phone_number(local_part)
        if on_trusted_provider:
            pts = 8   # Could be legitimate phone UPI
        else:
            pts = 18
        score += pts
        breakdown['all_numeric'] = True
        breakdown['is_phone_upi'] = is_phone
        breakdown['all_numeric_points'] = pts
    else:
        breakdown['all_numeric'] = False
        breakdown['is_phone_upi'] = False
        breakdown['all_numeric_points'] = 0

    # 2d. Random/high-entropy string — only meaningful on unknown providers
    if not on_trusted_provider and _is_random_looking(local_part):
        score += 12
        breakdown['random_string'] = True
    else:
        breakdown['random_string'] = False

    # 2e. Excessive length
    if len(local_part) > 40:
        score += 10
        breakdown['excessive_length'] = True
    else:
        breakdown['excessive_length'] = False

    # ── LAYER 3: Behavioral Signals ─────────────────────────────────────────

    # 3a. Transaction velocity (last 24h)
    v24 = upi.txn_velocity_24h
    if v24 > 50:
        vel_pts = 20
    elif v24 > 20:
        vel_pts = 12
    elif v24 > 10:
        vel_pts = 6
    else:
        vel_pts = 0
    score += vel_pts
    breakdown['velocity_24h'] = {'count': v24, 'points': vel_pts}

    # 3b. High average transaction amount
    avg = upi.avg_txn_amount
    if avg > 500000:
        amt_pts = 10
    elif avg > 100000:
        amt_pts = 5
    else:
        amt_pts = 0
    score += amt_pts
    breakdown['avg_txn_amount'] = {'value': avg, 'points': amt_pts}

    # 3c. Failed transaction ratio
    total_txn = upi.txn_velocity_24h or 1
    fail_ratio = upi.failed_txn_count / total_txn
    if fail_ratio > 0.5 and upi.failed_txn_count > 3:
        fail_pts = 15
    elif fail_ratio > 0.3 and upi.failed_txn_count > 2:
        fail_pts = 8
    else:
        fail_pts = 0
    score += fail_pts
    breakdown['failed_txns'] = {
        'count': upi.failed_txn_count,
        'ratio': round(fail_ratio, 2),
        'points': fail_pts
    }

    # 3d. New account
    now      = timezone.now()
    age_days = (now - upi.created_at).days
    if age_days < 1:
        score += 8
        breakdown['new_account'] = {'age_days': age_days, 'points': 8}
    elif age_days < 7:
        score += 4
        breakdown['new_account'] = {'age_days': age_days, 'points': 4}
    else:
        breakdown['new_account'] = {'age_days': age_days, 'points': 0}

    # ── LAYER 4: Network & ML Intelligence ──────────────────────────────────

    # 4a. Linked fraud accounts
    lfc = upi.linked_fraud_count
    if lfc > 0:
        net_pts = min(lfc * 5, 20)
        score += net_pts
        breakdown['network_fraud'] = {'linked': lfc, 'points': net_pts}
    else:
        breakdown['network_fraud'] = {'linked': 0, 'points': 0}

    # 4b. ML model prediction
    if ML_AVAILABLE:
        is_ml_fraud = predict_upi_fraud(upi.upi_id)
        if is_ml_fraud:
            score += 30
            breakdown['ml_prediction'] = True
        else:
            breakdown['ml_prediction'] = False
    else:
        breakdown['ml_prediction'] = False

    # ── SAFE BIAS: Trusted providers get a score reduction ───────────────────
    # A clean name@oksbi / name@ybl / name@paytm should score low
    if on_trusted_provider and score > 0:
        # Only apply bias when no hard signals are present
        hard_signals = (
            breakdown.get('brand_impersonation') or
            breakdown.get('typosquatting') or
            rc > 0 or
            breakdown.get('keywords') or
            on_high_risk_provider
        )
        if not hard_signals:
            score = max(0, score - 10)
            breakdown['trusted_provider_bias'] = -10

    # ── FINAL: Cap, classify, infer fraud type ───────────────────────────────
    score = min(score, MAX_SCORE)

    if score >= 70:
        status = 'Fraud'
    elif score >= 40:
        status = 'Suspicious'
    else:
        status = 'Safe'

    if status in ('Fraud', 'Suspicious'):
        breakdown['fraud_type'] = _classify_fraud_type(breakdown, local_part)
    else:
        breakdown['fraud_type'] = None

    return score, status, breakdown
