"""
Advanced scam keyword & pattern detection for UPI IDs.

Key design principle: We scan the LOCAL PART of the UPI ID only.
We must NOT flag common English words that appear in legitimate UPI IDs
(e.g., names like 'sanjay', 'ram') — only clear scam signals matter.
"""

import re

# ── Explicit scam action/intent words ─────────────────────────────────────────
# These are words that ONLY appear in scam/impersonation UPI IDs, not in real names.
# Deliberately conservative — avoid common words like 'bank', 'service', 'care', 'team'.
_SCAM_KEYWORDS = {
    # Fake prize / lottery bait
    "lottery", "prize", "cashback", "reward", "freegift", "lucky",
    "jackpot", "promo", "winner", "winprize", "luckyuser",

    # Financial scam signals (specific compound words only)
    "refundnow", "claimreward", "grantmoney", "subsidynow",
    "relieffund", "schemepay",

    # KYC / OTP / verification urgency — standalone only when scam-specific
    "kycupdate", "otpverify", "kycverify", "verifynow", "kycexpired",
    "kycblock",

    # Authority spoofing — compound words only
    "govtgrant", "govtaid", "govtscheme", "pmkisan", "mnrega",
    "ayushman", "epfoclaim", "pf",

    # Crypto / investment scam — specific terms
    "crypto", "bitcoin", "forex", "mlm", "doubler", "ponzi", "nft",
    "airdrop", "staking", "defi", "cryptomining",

    # Delivery scam
    "courierheld", "customsfee", "parcelblock",

    # Job scam — specific compound scam words
    "workfromhome", "earndaily", "earnmoney", "parttime",

    # Account threat / social engineering
    "accountblocked", "accountfrozen", "accountsuspended",
    "blocked", "frozen", "suspended",

    # Obvious fraudster keywords
    "scammer", "hacker", "phish", "phishing", "fraud", "fake",
    "cheat", "cheater", "scam", "hack",

    # Impersonation patterns (brand + action combined)
    "sbisupport", "hdfcsupport", "icicisupport", "axissupport",
    "paytmsupport", "phonepesupport", "gpaysupport",
    "sbicard", "hdfccard", "icicifastag",
    "sbikyc", "hdfckyc", "icickyc",
    "payments", "upi",  # 'upi' in local part is suspicious, but 'upi' as @provider is legit
}

# ── Words that are ONLY suspicious in the local part, NOT when standalone real names ──
# These patterns must be word-boundary matched (not substring)
_WORD_BOUNDARY_KEYWORDS = {
    "kyc", "otp", "verify", "refund", "grant", "subsidy",
    "helpdesk", "helpline", "urgent", "alert",
    "tax", "income", "police", "court",
    "cashfree", "razorpay", "mobikwik", "freecharge",
    "tollfree", "tollfreenumber",
    "deposit", "withdraw", "withdrawal", "transfer",
    "activate", "password", "reset", "confirm",
    "notify", "notice", "official", "admin",
}

# ── Brand impersonation patterns ──────────────────────────────────────────────
# Brand + scam_action or scam_action + brand
_BRANDS = r'(sbi|hdfc|icici|axis|paytm|phonepe|gpay|googlepay|bhim|amazon|flipkart|uidai|rbi|sebi|lic|npci|irctc|jio|airtel|bsnl|nse|bse|zerodha|groww|upstox|ybl|okaxis|okhdfcbank|okicici|oksbi)'
_SCAM_ACTIONS = r'(support|helpdesk|care|refund|kyc|verify|reward|prize|claim|helpline|customercare|alert|update|help|assist|official|admin|team|notify|block|freeze|suspend)'

BRAND_IMPERSONATION_PATTERN = re.compile(
    r'(' + _BRANDS + r'[\.\-_]?' + _SCAM_ACTIONS + r'|' + _SCAM_ACTIONS + r'[\.\-_]?' + _BRANDS + r')',
    re.IGNORECASE
)

# ── Typosquatting patterns ─────────────────────────────────────────────────────
_TYPOSQUAT_MAP = {
    'sbi':      ['sb1', 's-b-i', 'st4tebank', 'sbioficial', 'sbiibank', 'sbii'],
    'hdfc':     ['hdfcc', 'h-d-f-c', 'hdfc0', 'hdfcbankk'],
    'icici':    ['icicii', '1cici', 'icic1', 'iciccibank'],
    'paytm':    ['paytmlm', 'pay-tm', 'paytmm', 'paytmofficial', 'p4ytm'],
    'phonepe':  ['ph0nepe', 'phonep3', 'phonepeofficial', 'ph0nep3'],
    'gpay':     ['g-pay', 'googlpay', 'g00gpay', 'googlepayy'],
    'bhim':     ['bh1m', 'bhimm', 'bh-im'],
    'rbi':      ['rb1', 'rbiofficial', 'rbii'],
    'uidai':    ['uid4i', 'uidaii', 'uidai1'],
    'irctc':    ['irctcc', '1rctc', 'irtcc'],
    'amazon':   ['amaz0n', 'amzon', 'am4zon'],
    'flipkart': ['flipkart0', 'fIipkart', 'flipkartt'],
}

# ── Known malicious UPI providers ─────────────────────────────────────────────
_SUSPICIOUS_PROVIDERS = {
    'xyz', 'tk', 'ml', 'ga', 'cf', 'gq', 'pw',
    'temp', 'fake', 'test123', 'fraud', 'scam',
    'win', 'prize', 'lucky', 'free',
}

# ── Compiled regexes ──────────────────────────────────────────────────────────
# Exact keyword matches (full word, not substring)
_EXACT_PATTERN = re.compile(
    r'(?<![a-z])(' + '|'.join(re.escape(k) for k in _SCAM_KEYWORDS) + r')(?![a-z])',
    re.IGNORECASE,
)

# Word-boundary pattern for less specific keywords
_WB_PATTERN = re.compile(
    r'\b(' + '|'.join(re.escape(k) for k in _WORD_BOUNDARY_KEYWORDS) + r')\b',
    re.IGNORECASE,
)


def detect_keywords(upi_id: str) -> bool:
    local_part = upi_id.split("@")[0] if "@" in upi_id else upi_id
    return bool(_EXACT_PATTERN.search(local_part) or _WB_PATTERN.search(local_part))


def matched_keywords(upi_id: str) -> list:
    local_part = upi_id.split("@")[0] if "@" in upi_id else upi_id
    found = set()
    for m in _EXACT_PATTERN.finditer(local_part):
        found.add(m.group().lower())
    for m in _WB_PATTERN.finditer(local_part):
        found.add(m.group().lower())
    return list(found)


def detect_brand_impersonation(upi_id: str) -> bool:
    local_part = upi_id.split("@")[0] if "@" in upi_id else upi_id
    return bool(BRAND_IMPERSONATION_PATTERN.search(local_part))


def detect_typosquatting(upi_id: str) -> bool:
    """Detect common typosquatting patterns of major brands."""
    local_part = upi_id.split("@")[0].lower() if "@" in upi_id else upi_id.lower()
    for brand, variants in _TYPOSQUAT_MAP.items():
        for v in variants:
            if v in local_part:
                return True
    return False


def get_provider_risk(upi_id: str) -> str:
    """Returns 'suspicious' if provider looks malicious, else 'ok'."""
    if "@" not in upi_id:
        return 'ok'
    provider = upi_id.split("@")[1].lower()
    if provider in _SUSPICIOUS_PROVIDERS:
        return 'suspicious'
    return 'ok'
