"""
Advanced SMS / Message Risk Scoring Engine — PhishInspect

Detection Layers:
  Layer 1 — Heuristic keyword patterns (12 scam categories, India-specific)
  Layer 2 — UPI deep-link / payment trap detection
  Layer 3 — Suspicious phone number pressure patterns
  Layer 4 — Brand spoofing / impersonation in message body
  Layer 5 — URL analysis (shorteners, malicious TLDs, IP links, homographs)
  Layer 6 — Structural message signals (caps, punctuation, length, urgency combos)
  Layer 7 — Hinglish / transliteration scam patterns
  Layer 8 — Scam emoji clusters
  Layer 9 — Machine Learning model (Naive Bayes trained on SMS Spam Corpus)

Score Thresholds:
  SCAM        : >= 75
  SUSPICIOUS  : >= 38
  SAFE        : < 38
"""

import re
import math

# ── Safe import of ML model ────────────────────────────────────────────────────
try:
    from .ml.predict import detect_scam as _ml_detect
    _ML_AVAILABLE = True
except Exception:
    _ML_AVAILABLE = False


# =============================================================================
# LAYER 1 — KEYWORD HEURISTICS  (12 scam categories)
# =============================================================================

_KW = {
    # Score 35 — Direct financial theft / critical threat
    "banking_kyc": re.compile(
        r'\b(kyc|update.{0,20}(pan|aadhaar|account)|aadhaar.{0,15}(link|update|verify)|'
        r'pan.{0,15}(update|link|verify)|net.{0,10}banking|mobile.{0,10}banking|'
        r'account.{0,15}(suspend|block|freeze|deactivate|verify)|'
        r'debit.{0,10}card.{0,10}(block|expire)|atm.{0,10}(pin|block|expire)|'
        r'(update|verify|link).{0,20}(kyc|pan|account|card))\b',
        re.IGNORECASE,
    ),

    "otp_phishing": re.compile(
        r'\b(share.{0,10}otp|enter.{0,10}otp.{0,20}(link|click|url)|'
        r'otp.{0,20}(link|click|forward|send|give|tell|type).{0,20}|'
        r'click.{0,20}otp|transaction.{0,10}otp.{0,15}(share|send|give))\b',
        re.IGNORECASE,
    ),

    "legal_threat": re.compile(
        r'\b(arrest.{0,10}warrant|fir.{0,10}(filed|register)|'
        r'cybercrime|court.{0,10}notice|police.{0,10}(case|complaint|notice)|'
        r'narcotics|money.{0,10}laundering|cbi.{0,10}notice|ed.{0,10}notice|'
        r'money.{0,10}laundering|legal.{0,10}action|summons|jail|'
        r'enforcement.{0,10}directorate|warrant.{0,10}(issued|against))\b',
        re.IGNORECASE,
    ),

    # Score 28 — High-confidence fraud
    "prize_lottery": re.compile(
        r'\b(you.{0,10}won|won.{0,10}(cash|prize|rs|rupee|lakh)|'
        r'lucky.{0,10}(winner|draw|number)|congratulations.{0,30}won|'
        r'claim.{0,20}(prize|reward|gift|amount|cash)|'
        r'lottery.{0,15}(winner|result|amount)|jackpot|bumper.{0,10}prize|'
        r'scratch.{0,10}card|spin.{0,10}win|selected.{0,10}winner|'
        r'free.{0,10}(iphone|laptop|cash|gift)|cashback.{0,15}claim)\b',
        re.IGNORECASE,
    ),

    "crypto_investment": re.compile(
        r'\b(bitcoin|crypto.{0,15}invest|double.{0,10}money|'
        r'guaranteed.{0,10}(return|profit)|binance|wallet.{0,10}connect|'
        r'trading.{0,10}profit|forex.{0,10}(trading|invest)|'
        r'ponzi|mlm.{0,10}(scheme|plan)|passive.{0,10}income|'
        r'crypto.{0,10}wallet|nft.{0,15}(invest|profit)|airdrop.{0,10}claim|'
        r'staking.{0,10}reward|defi|cryptomining|yield.{0,10}farm)\b',
        re.IGNORECASE,
    ),

    "government_impersonation": re.compile(
        r'\b(pm.{0,5}kisan|pmkisan|mnrega|ration.{0,10}card|'
        r'income.{0,10}tax.{0,15}(refund|notice|department)|'
        r'it.{0,10}department.{0,10}refund|gst.{0,10}refund|'
        r'government.{0,15}(scheme|grant|subsidy|aid)|modi.{0,10}scheme|'
        r'pm.{0,5}awas|ayushman|epfo.{0,10}(claim|withdraw)|'
        r'pf.{0,10}(withdraw|claim|balance)|esi.{0,10}(claim|refund)|'
        r'subsidy.{0,15}(credit|amount|transfer))\b',
        re.IGNORECASE,
    ),

    # Score 22 — Medium confidence
    "urgency_pressure": re.compile(
        r'\b(urgent(ly)?|immediate.{0,10}(action|response)|act.{0,5}now|'
        r'last.{0,5}chance|expir(e|ing|ed).{0,15}(today|now|soon)|'
        r'final.{0,10}notice|deadline.{0,10}today|within.{0,10}24.{0,10}hour|'
        r'limited.{0,10}time|time.{0,10}sensitive|failure.{0,15}(respond|comply)|'
        r'account.{0,15}(will.{0,5}be.{0,5}(blocked|suspend|terminated))|'
        r'respond.{0,10}immediately|action.{0,10}required)\b',
        re.IGNORECASE,
    ),

    "delivery_scam": re.compile(
        r'\b(package.{0,15}(pending|held|undelivered)|customs?.{0,10}(fee|charge|clearance)|'
        r'dhl|fedex|pay.{0,10}shipping|parcel.{0,15}(held|blocked|pending)|'
        r'courier.{0,15}(charge|fee|pay)|india.{0,10}post.{0,15}(pending|held)|'
        r'shipment.{0,15}(on.{0,5}hold|failed)|delivery.{0,15}failed|'
        r'delivery.{0,30}(click|link|pay)|re.?schedule.{0,15}delivery)\b',
        re.IGNORECASE,
    ),

    "job_scam": re.compile(
        r'\b(work.{0,10}from.{0,10}home.{0,20}earn|part.{0,5}time.{0,10}(job|earn)|'
        r'data.{0,10}entry.{0,10}job|earn.{0,15}(rs\.?|rupee|\d+).{0,10}per.{0,10}day|'
        r'earn.{0,10}daily|registration.{0,10}fee.{0,20}job|'
        r'placement.{0,10}fee|hiring.{0,10}fee|joining.{0,10}fee|'
        r'easy.{0,10}money.{0,10}online|earn.{0,10}without.{0,15}investment|'
        r'whatsapp.{0,15}(job|task|earn)|per.{0,5}click.{0,10}earn)\b',
        re.IGNORECASE,
    ),

    "insurance_scam": re.compile(
        r'\b(insurance.{0,15}claim|policy.{0,15}(expire|lapse|renew|bonus)|'
        r'lic.{0,15}(policy|claim|bonus|premium)|premium.{0,15}(due|overdue|pending)|'
        r'maturity.{0,15}amount|bonus.{0,10}declare|insurance.{0,15}refund)\b',
        re.IGNORECASE,
    ),

    "electricity_gas": re.compile(
        r'\b(electricity.{0,20}(disconnect|cut|suspend)|'
        r'power.{0,15}(cut|disconnect|suspend|off).{0,20}(bill|pay|today)|'
        r'(electricity|electric|power).{0,10}bill.{0,20}(overdue|pending|due|unpaid)|'
        r'disconnect.{0,20}(due.{0,10}to|for).{0,20}(bill|payment|non.?payment|overdue)|'
        r'mseb|bescom|tneb|gas.{0,10}bill.{0,15}(overdue|pending)|'
        r'lpg.{0,15}(subsidy|connection|block)|gas.{0,10}connection.{0,10}block)\b',
        re.IGNORECASE,
    ),

    "charity_fraud": re.compile(
        r'\b(donate.{0,15}(now|today|urgent)|flood.{0,10}relief|'
        r'earthquake.{0,10}relief|covid.{0,15}(relief|fund|donate)|'
        r'pm.{0,5}relief.{0,10}fund|disaster.{0,15}relief|'
        r'help.{0,20}(children|poor|victim).{0,15}donate|'
        r'cancer.{0,15}(fund|donate))\b',
        re.IGNORECASE,
    ),

    "romance_sextortion": re.compile(
        r'\b(send.{0,10}(me.{0,5})?money|i.{0,5}(need|am.{0,5}in).{0,15}(money|trouble|hospital)|'
        r'stuck.{0,20}(abroad|airport|country)|wire.{0,10}transfer.{0,10}urgent|'
        r'western.{0,10}union|moneygram|'
        r'(photo|video).{0,15}(leak|viral|share|expose)|'
        r'recording.{0,20}pay|pay.{0,15}or.{0,15}(share|expose|leak|post))\b',
        re.IGNORECASE,
    ),
}

# Points per category
_KW_SCORES = {
    "banking_kyc":              35,
    "otp_phishing":             35,
    "legal_threat":             35,
    "prize_lottery":            28,
    "crypto_investment":        28,
    "government_impersonation": 28,
    "urgency_pressure":         22,
    "delivery_scam":            22,
    "job_scam":                 22,
    "insurance_scam":           22,
    "electricity_gas":          25,
    "charity_fraud":            20,
    "romance_sextortion":       35,
}


# =============================================================================
# LAYER 2 — UPI PAYMENT DEEP-LINK DETECTION
# =============================================================================

_UPI_DEEPLINK = re.compile(
    r'(upi://[^\s]+|tez://[^\s]+|phonepe://[^\s]+|'
    r'pay\?pa=[^\s&]+|bhim://[^\s]+|gpay://[^\s]+|'
    r'paytmmp://[^\s]+)',
    re.IGNORECASE,
)

# UPI ID embedded in message text (scammers write "send to user@paytm")
_UPI_ID_IN_TEXT = re.compile(
    r'\b[\w.\-]{2,64}@(paytm|ybl|okaxis|okhdfcbank|okicici|oksbi|upi|'
    r'ibl|axl|apl|freecharge|airtel|jiomoney|hdfcbank|icici|sbi)\b',
    re.IGNORECASE,
)


# =============================================================================
# LAYER 3 — PHONE NUMBER PRESSURE
# =============================================================================

_PHONE_PRESSURE = re.compile(
    r'(?:call|contact|helpline|whatsapp|reach\s*us|dial|ring|'
    r'callback|toll\s*free|customer\s*care)\s*'
    r'(?:at|on|now|us|:|-|—)?\s*'
    r'(?:\+91[-\s]?)?[6-9]\d{9}',
    re.IGNORECASE,
)

# Standalone phone number (10 digit Indian mobile) with no preceding "call" word — less weight
_BARE_PHONE = re.compile(r'(?<!\d)(?:\+91[-\s]?)?[6-9]\d{9}(?!\d)')


# =============================================================================
# LAYER 4 — BRAND SPOOFING / IMPERSONATION
# =============================================================================

_BRAND_SPOOF = re.compile(
    r'\b(sbi|hdfc|icici|axis\s*bank|paytm|phonepe|google\s*pay|gpay|'
    r'amazon\s*pay|flipkart|navi|mobikwik|airtel|jio|bsnl|lic|npci|rbi|sebi|'
    r'income\s*tax|customs|cbi|narcotics|uidai|irctc|nse|bse|zerodha|groww)\b'
    r'.{0,80}'
    r'\b(support|helpdesk|customer\s*care|helpline|refund|verify|update|confirm|'
    r'alert|representative|team|official|notify|block|suspend|freeze|kyc)',
    re.IGNORECASE | re.DOTALL,
)


# =============================================================================
# LAYER 5 — URL ANALYSIS
# =============================================================================

_URL_PATTERN = re.compile(
    r'(https?://[^\s<>"]+|www\.[^\s<>"]+|[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
    r'\.[a-zA-Z]{2,}(?:/[^\s<>"]*)?)'
)

_SUSPICIOUS_TLDS = {
    '.xyz', '.top', '.club', '.online', '.site', '.click',
    '.cc', '.ru', '.tk', '.cn', '.pw', '.ga', '.cf', '.ml',
    '.work', '.party', '.loan', '.download', '.zip', '.gq',
    '.gov.tk', '.info', '.biz',
}

_URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
    'is.gd', 'buff.ly', 'cutt.ly', 'shorturl.at', 'rb.gy',
    'tiny.cc', 'snip.ly', 'shrtco.de', 'yourls.org',
    'bl.ink', 'clicky.me', 'short.io', 'link.tl', 'rebrand.ly',
}

_BRAND_DOMAINS = [
    'google', 'facebook', 'amazon', 'instagram', 'whatsapp',
    'netflix', 'paypal', 'apple', 'microsoft', 'sbi', 'hdfc',
    'icici', 'paytm', 'phonepe', 'flipkart', 'uidai', 'irctc',
    'infosys', 'tcs', 'reliance', 'airtel', 'jio',
]

_HOMOGRAPH = str.maketrans({'0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't'})


def _domain_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def _analyze_urls(text: str) -> list:
    urls = _URL_PATTERN.findall(text)
    results = []
    for url in urls:
        flags = []
        url_lower = url.lower()

        # UPI deep-link in URL
        if re.search(r'(upi://|tez://|phonepe://|pay\?pa=)', url_lower):
            flags.append("UPI deep-link embedded in URL (payment trap)")

        # Known shortener
        if any(s in url_lower for s in _URL_SHORTENERS):
            flags.append("URL shortener (hides real destination)")

        # Suspicious TLD
        if any(url_lower.endswith(t) or (t + '/') in url_lower or (t + '?') in url_lower
               for t in _SUSPICIOUS_TLDS):
            flags.append("Suspicious domain extension (high-risk TLD)")

        # Direct numeric IP
        if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url_lower):
            flags.append("Direct IP address URL (bypasses domain trust)")

        try:
            domain_part = (
                url_lower
                .replace('https://', '')
                .replace('http://', '')
                .replace('www.', '')
                .split('/')[0]
                .split('?')[0]
            )
            # Homograph brand impersonation
            normalized = domain_part.translate(_HOMOGRAPH)
            for brand in _BRAND_DOMAINS:
                if brand in normalized and brand not in domain_part:
                    flags.append(f"Brand typosquatting: '{brand}' spoofed")
                    break

            # High-entropy random-looking subdomain
            labels = domain_part.split('.')
            for label in labels[:-1]:
                if len(label) > 8 and _domain_entropy(label) > 3.5:
                    flags.append("Random subdomain (generated phishing domain)")
                    break

            # Excessive subdomain depth
            if len(labels) > 5:
                flags.append("Excessive subdomains (common phishing structure)")

            # Brand name in subdomain path but not the main domain
            for brand in _BRAND_DOMAINS:
                if brand in '/'.join(url_lower.split('/')[1:]) and brand not in domain_part:
                    flags.append(f"Brand '{brand}' in URL path (impersonation trick)")
                    break
        except Exception:
            pass

        results.append({
            "url": url,
            "is_suspicious": len(flags) > 0,
            "flags": flags,
            "reason": "; ".join(flags) if flags else "No issues detected",
        })
    return results


# =============================================================================
# LAYER 6 — STRUCTURAL MESSAGE SIGNALS
# =============================================================================

def _structural_score(message: str) -> tuple:
    """Returns (score, signals_list) from message structure analysis."""
    score = 0
    signals = []

    # Excessive CAPS (>40% of alpha chars are uppercase — scam hallmark)
    alpha = [c for c in message if c.isalpha()]
    if alpha:
        caps_ratio = sum(1 for c in alpha if c.isupper()) / len(alpha)
        if caps_ratio > 0.55:
            score += 12
            signals.append(f"High CAPS ratio ({caps_ratio:.0%}) — typical scam formatting")
        elif caps_ratio > 0.40:
            score += 6
            signals.append(f"Moderate CAPS ({caps_ratio:.0%})")

    # Excessive exclamation marks
    exclaim_count = message.count('!')
    if exclaim_count >= 3:
        score += 8
        signals.append(f"{exclaim_count} exclamation marks — urgency manipulation")

    # Message too short to be legitimate (one-liner bait)
    words = message.split()
    if 2 <= len(words) <= 8 and any(
        kw in message.lower() for kw in ['click', 'win', 'claim', 'otp', 'verify']
    ):
        score += 10
        signals.append("Very short message with high-risk action word")

    # Contains both a phone number AND a URL — common attack vector
    has_phone = bool(_BARE_PHONE.search(message))
    has_url   = bool(_URL_PATTERN.search(message))
    if has_phone and has_url:
        score += 15
        signals.append("Contains both phone number AND URL (double-trap pattern)")

    # Numbered list impersonating official notice
    if re.search(r'(step\s*\d|note\s*\d|\d\s*\.\s*(click|call|visit|pay|verify))', message, re.IGNORECASE):
        score += 8
        signals.append("Numbered action steps (fake official notice format)")

    return score, signals


# =============================================================================
# LAYER 7 — HINGLISH / TRANSLITERATION SCAM PATTERNS
# =============================================================================

_HINGLISH_SCAM = re.compile(
    r'\b(aapka\s*(account|kyc|card)|'
    r'aap\s*ka\s*(bank|paisa)|'
    r'jaldi\s*(karo|karen|verify)|'
    r'turant\s*(karen|karo|call)|'
    r'paisa\s*(double|earn|milega)|'
    r'free\s*mein\s*(paise|iphone|laptop)|'
    r'lucky\s*(vijeta|winner)|'
    r'inaam\s*(jeeta|mila|claim)|'
    r'khata\s*(band|block)|'
    r'ration\s*(card\s*update|band)|'
    r'bijli\s*(bill|katna|kaat)|'
    r'naukri\s*(milegi|chahiye|fraud)|'
    r'ghar\s*baithe\s*kamao|'
    r'rojana\s*(earn|kamai)|'
    r'paise\s*bhejo|'
    r'recharge\s*(free|offer|jaldi))\\b',
    re.IGNORECASE,
)


# =============================================================================
# LAYER 8 — SCAM EMOJI CLUSTERS
# =============================================================================

_SCAM_EMOJI_MAP = {
    "🎉🎊🏆🥇🎁💰💵💸🤑": "Prize/lottery bait emojis",
    "⚠️🚨🔴❗‼️": "Urgency/threat emojis",
    "🔗📲💳🏦": "Payment/link pressure emojis",
    "👮‍♂️⚖️🔒🚔": "Legal threat emojis",
    "📦📬📮": "Delivery scam emojis",
}

def _emoji_score(message: str) -> tuple:
    score = 0
    found = []
    for emoji_group, label in _SCAM_EMOJI_MAP.items():
        hits = [e for e in emoji_group if e in message]
        if len(hits) >= 2:
            score += 8
            found.append(f"{label} ({', '.join(hits)})")
        elif len(hits) == 1:
            score += 3
    return score, found


# =============================================================================
# MAIN SCORING ENGINE
# =============================================================================

def calculate_sms_risk(message: str) -> tuple:
    """
    Multi-layer SMS/message scam detection.

    Returns:
        risk_score (int):  0–100
        status     (str):  SAFE | SUSPICIOUS | SCAM
        breakdown  (dict): Detailed signal telemetry
    """
    risk_score = 0
    breakdown = {
        "ml_prediction":       "ham",
        "ml_confidence":        0,
        "matched_categories":  [],
        "category_scores":     {},
        "upi_links":           [],
        "upi_ids_in_text":     [],
        "phone_pressure":      False,
        "brand_spoof":         False,
        "urls":                [],
        "structural_signals":  [],
        "hinglish_scam":       False,
        "scam_emojis":         [],
        "total_score":          0,
    }

    # ── Layer 1: Keyword Heuristics ───────────────────────────────────────────
    for category, pattern in _KW.items():
        if pattern.search(message):
            pts = _KW_SCORES[category]
            risk_score += pts
            breakdown["matched_categories"].append(category)
            breakdown["category_scores"][category] = pts

    # ── Layer 2: UPI Deep-Link and Embedded UPI IDs ───────────────────────────
    upi_links = _UPI_DEEPLINK.findall(message)
    if upi_links:
        breakdown["upi_links"] = upi_links
        risk_score += 55   # Payment deep-link in SMS = almost certainly fraud

    upi_ids = _UPI_ID_IN_TEXT.findall(message)
    if upi_ids:
        breakdown["upi_ids_in_text"] = upi_ids
        risk_score += 20   # UPI ID in message text — possible payment scam

    # ── Layer 3: Phone Pressure ───────────────────────────────────────────────
    if _PHONE_PRESSURE.search(message):
        breakdown["phone_pressure"] = True
        risk_score += 20
    elif _BARE_PHONE.search(message):
        # Bare phone number without explicit "call" — minor signal
        breakdown["phone_pressure"] = "bare_number"
        risk_score += 8

    # ── Layer 4: Brand Spoofing ───────────────────────────────────────────────
    if _BRAND_SPOOF.search(message):
        breakdown["brand_spoof"] = True
        risk_score += 25

    # ── Layer 5: URL Analysis ─────────────────────────────────────────────────
    analyzed_urls = _analyze_urls(message)
    breakdown["urls"] = analyzed_urls
    suspicious_urls = [u for u in analyzed_urls if u["is_suspicious"]]
    if suspicious_urls:
        risk_score += min(len(suspicious_urls) * 40, 80)
    elif analyzed_urls:
        risk_score += 8  # Any link in SMS = slight caution

    # ── Layer 6: Structural Signals ───────────────────────────────────────────
    struct_score, struct_signals = _structural_score(message)
    risk_score += struct_score
    breakdown["structural_signals"] = struct_signals

    # ── Layer 7: Hinglish Scam Patterns ──────────────────────────────────────
    if _HINGLISH_SCAM.search(message):
        breakdown["hinglish_scam"] = True
        risk_score += 18

    # ── Layer 8: Scam Emoji Clusters ─────────────────────────────────────────
    emoji_score, emoji_hits = _emoji_score(message)
    risk_score += emoji_score
    breakdown["scam_emojis"] = emoji_hits

    # ── Layer 9: ML Model Prediction ─────────────────────────────────────────
    if _ML_AVAILABLE:
        try:
            ml_result = _ml_detect(message)
            ml_label = str(ml_result).lower()
            breakdown["ml_prediction"] = ml_label
            if ml_label in ("spam", "scam", "1"):
                risk_score += 30
                breakdown["ml_confidence"] = 30
        except Exception as e:
            breakdown["ml_prediction"] = f"error: {e}"

    # ── Category combination bonus ────────────────────────────────────────────
    # If multiple high-risk categories fire together — compound threat
    high_risk_cats = {"banking_kyc", "otp_phishing", "legal_threat", "romance_sextortion"}
    matched_high = high_risk_cats & set(breakdown["matched_categories"])
    if len(matched_high) >= 2:
        risk_score += 15   # Compound attack: e.g., "urgent KYC + legal threat"
        breakdown["compound_attack"] = list(matched_high)

    # ── Final cap and classify ────────────────────────────────────────────────
    risk_score = min(risk_score, 100)
    breakdown["total_score"] = risk_score

    if risk_score >= 65:
        status = "SCAM"
    elif risk_score >= 25:
        status = "SUSPICIOUS"
    else:
        status = "SAFE"

    return risk_score, status, breakdown
