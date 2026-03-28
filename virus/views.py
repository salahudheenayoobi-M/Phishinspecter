from django.shortcuts import render,redirect,HttpResponse
from .import models
from.forms import UserFileform

def index(request):
    return render(request,'index.html')

def dashboard(request):
    if 'email'in request.session:
        email=request.session['email']
        client=models.Register.objects.get(email=email)
        return render(request,'dashboard.html',{'user':client})
    return render(request,'dashboard.html')


def register(request):
    if request.method ==  'POST':
        username = request.POST.get('username')
        age = request.POST.get('age')
        email = request.POST.get('email')
        password = request.POST.get('password')
        image = request.FILES.get('image')

        if models.Register.objects.filter(email=email).exists():
            return HttpResponse("email already exists")
        else:
            user = models.Register(username=username,age=age,email=email,password=password,image=image)
            user.save()
            return HttpResponse("""<script>
                alert('Registered successfully!!!');
                window.location.href='/login/';
            </script>""")
    
    
    
    
    return render(request,'register.html')

def submit_feedback(request):
    if request.method == 'POST':
        message = request.POST.get('message')
        rating = request.POST.get('rating', 5)
        
        feedback = models.Feedback(message=message, rating=rating)
        # Attempt to link to the logged-in user if available in the session
        if 'email' in request.session:
            try:
                user = models.Register.objects.get(email=request.session['email'])
                feedback.user = user
            except models.Register.DoesNotExist:
                pass
        
        feedback.save()
        return HttpResponse("""
            <script>
                alert('Thank you for sharing your valuable feedback!');
                window.location.href='/dashboard/';
            </script>
        """)
    return redirect('dashboard')



def feedback_list(request):
    feedbacks = models.Feedback.objects.all().order_by('-created_at')
    return render(request, 'feedback_list.html', {'feedbacks': feedbacks})

def editprofile(request):
    if 'email' in request.session:
        email = request.session['email']
        try:
            user = models.Register.objects.get(email=email)
        except models.Register.DoesNotExist:
            return HttpResponse("User not found")

        if request.method == 'POST':
            username = request.POST.get('username')
            age = request.POST.get('age')
            new_email = request.POST.get('email')
            password = request.POST.get('password')
            image = request.FILES.get('image')

            
            if new_email != user.email and models.Register.objects.filter(email=new_email).exists():
                return HttpResponse("Email already exists")

            
            user.username = username
            user.age = age
            user.email = new_email
            if password:  
                user.password = password
            if image:  
                user.image = image

            user.save()
            request.session['email'] = user.email  
            return redirect('profile')  

        
        return render(request, 'editprofile.html', {'user': user})

    else:
        return redirect('login')

from django.shortcuts import render
from django.http import HttpResponse
from . import models

def login(request):
    if request.method == "POST":
        email = request.POST.get('email')
        password = request.POST.get('password')

        try:
            user = models.Register.objects.get(email=email)

            if user.password == password:
                request.session['email'] = email

                return HttpResponse("""
                    <script>
                        alert('Login successfully!!!');
                        window.location.href='/dashboard/';
                    </script>
                """)
            else:
                return HttpResponse("""<script>
                        alert('Invalid User!!!');
                        window.location.href='/login/';
                    </script>""")
        
        except models.Register.DoesNotExist:
            return HttpResponse("""<script>
                        alert('Invalid User!!!');
                        window.location.href='/login/';
                    </script>""")
        
    return render(request, 'login.html')








def profile(request):
    if 'email' in request.session:
        email=request.session['email']

        try:
            client=models.Register.objects.get(email=email)
            return render(request,'profile.html',{'client':client})
        
        except models.Register.DoesNotExist:
            return HttpResponse('user not found')
        
    return HttpResponse('page not found')


import os
import requests
import time
from django.shortcuts import render, get_object_or_404
from django.conf import settings
from django.core.files.base import ContentFile
from . import models


# ==============================
# VIRUSTOTAL CONFIG
# ==============================
VIRUSTOTAL_API_KEY = "49352b4a577e5baf902c4027473565a56a03c12a23942b8a5f1fb1d10945391c"

VIRUSTOTAL_UPLOAD_URL = "https://www.virustotal.com/api/v3/files"
VIRUSTOTAL_ANALYSIS_URL = "https://www.virustotal.com/api/v3/analyses/"
VIRUSTOTAL_FILE_REPORT_URL = "https://www.virustotal.com/api/v3/files/"


# ======================================================================
# LOCAL HEURISTIC PRE-SCAN HELPERS  (zero-shot — no training data needed)
# ======================================================================
import re as _re
import math as _math
import hashlib as _hashlib
import json as _json

# ── URL Pre-scan ──────────────────────────────────────────────────────
_UPI_SCHEME_RE = _re.compile(r'(upi://|tez://|phonepe://|bhim://|gpay://|pay\?pa=)', _re.IGNORECASE)
_SUSPICIOUS_TLDS = {
    '.xyz', '.top', '.club', '.online', '.site', '.click',
    '.cc', '.ru', '.tk', '.cn', '.pw', '.ga', '.cf', '.ml',
    '.work', '.party', '.loan', '.download', '.zip', '.gq',
    '.info', '.biz', '.ws', '.vip', '.cyou',
}
_URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
    'is.gd', 'buff.ly', 'cutt.ly', 'shorturl.at', 'rb.gy',
    'tiny.cc', 'snip.ly', 'shrtco.de', 'bl.ink', 'rebrand.ly',
    'short.io', 'link.tl', 'clicky.me',
}
_BRAND_DOMAINS = [
    'google', 'facebook', 'amazon', 'instagram', 'whatsapp',
    'netflix', 'paypal', 'apple', 'microsoft', 'sbi', 'hdfc',
    'icici', 'paytm', 'phonepe', 'flipkart', 'uidai', 'irctc',
    'npci', 'bhim', 'lic', 'rbi', 'zerodha', 'groww', 'airtel',
    'jio', 'infosys', 'reliance', 'tcs', 'bajaj',
]
_HOMOGRAPH_TABLE = str.maketrans({'0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't'})


def _url_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * _math.log2(f / n) for f in freq.values())


def local_url_prescan(url: str) -> dict:
    """
    Advanced 17-check zero-shot URL heuristic pre-scanner.
    Returns {"is_scam": bool, "reason": str, "score": int, "checks": list}
    before calling VirusTotal — saving API quota for ambiguous URLs.
    """
    url_lower = url.lower()
    score = 0
    reasons = []
    checks = []

    def _add(name, status, detail, pts=0):
        nonlocal score
        checks.append({"name": name, "status": status, "detail": detail})
        if status == "FAIL":
            score += pts
            reasons.append(detail)

    # Check 1: Dangerous schemes
    if url_lower.startswith("javascript:"):
        _add("Scheme", "FAIL", "javascript: scheme — code injection risk", 100)
    elif url_lower.startswith("data:"):
        _add("Scheme", "FAIL", "data: URI — used to embed malicious content", 90)
    elif url_lower.startswith("vbscript:"):
        _add("Scheme", "FAIL", "vbscript: scheme — code execution risk", 100)
    else:
        _add("Scheme", "PASS", "Normal http/https/upi scheme")

    # Check 2: UPI payment deep-link
    if _UPI_SCHEME_RE.search(url):
        _add("UPI Deep-Link", "FAIL", "UPI payment deep-link detected (upi://, tez://, pay?pa=)", 100)
    else:
        _add("UPI Deep-Link", "PASS", "No UPI payment deep-link")

    # Check 3: UPI VPA in query string
    if _re.search(r'[?&]pa=[^&]+@[^&]+', url_lower):
        _add("UPI VPA in URL", "FAIL", "UPI VPA (pa=...) embedded in URL — payment trap", 80)
    else:
        _add("UPI VPA in URL", "PASS", "No UPI VPA in query string")

    # Domain / path parsing
    try:
        after_scheme = url_lower.split('//', 1)[1] if '//' in url_lower else url_lower
        authority    = after_scheme.split('/')[0].split('?')[0].split('#')[0]

        # Check 4: @ trick in URL authority
        if '@' in authority:
            _add("@ Trick", "FAIL", "@ in URL authority — real destination hidden behind displayed domain", 70)
            authority = authority.rsplit('@', 1)[1]
        else:
            _add("@ Trick", "PASS", "No @ character in URL authority")

        m = _re.match(r'^(.+?):(\d+)$', authority)
        if m:
            domain = m.group(1)
            port   = int(m.group(2))
        else:
            domain = authority
            port   = None

        path_q = after_scheme.split('/', 1)[1] if '/' in after_scheme else ''
        path   = '/' + path_q.split('?')[0]
        query  = path_q.split('?', 1)[1] if '?' in path_q else ''

    except Exception:
        domain, port, path, query = '', None, '/', ''

    # Check 5: Non-standard port
    if port and port not in {80, 443, 8080, 8443}:
        _add("Non-Standard Port", "FAIL", f"Port :{port} is unusual — phishing servers often avoid standard ports", 35)
    else:
        _add("Non-Standard Port", "PASS", "Standard or no port specified")

    # Check 6: Direct IP address
    if domain and _re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
        _add("Direct IP Address", "FAIL", "IP address used instead of domain — high phishing risk", 75)
    else:
        _add("Direct IP Address", "PASS", "Uses domain name (not raw IP)")

    # Check 7: Suspicious TLD
    tld_hit = next((t for t in _SUSPICIOUS_TLDS if domain.endswith(t)), None)
    if tld_hit:
        _add("Suspicious TLD", "FAIL", f"High-risk domain extension '{tld_hit}' detected", 50)
    else:
        _add("Suspicious TLD", "PASS", "Domain extension looks normal")

    # Check 8: URL shortener
    if any(s in domain for s in _URL_SHORTENERS):
        _add("URL Shortener", "FAIL", "URL shortener hides real destination — common in phishing", 40)
    else:
        _add("URL Shortener", "PASS", "Not a URL shortener")

    # Check 9: Brand homograph / typosquatting
    normalized = domain.translate(_HOMOGRAPH_TABLE)
    brand_typo = next((b for b in _BRAND_DOMAINS if b in normalized and b not in domain), None)
    if brand_typo:
        _add("Brand Typosquatting", "FAIL", f"Possible homograph impersonation of '{brand_typo}' (digit/letter substitution)", 65)
    else:
        _add("Brand Typosquatting", "PASS", "No brand homograph detected")

    # Check 10: High-entropy random subdomain
    labels    = domain.split('.') if domain else ['']
    rnd_label = next((l for l in labels[:-1] if len(l) > 8 and _url_entropy(l) > 3.5), None)
    if rnd_label:
        _add("Random Subdomain", "FAIL", f"High-entropy subdomain '{rnd_label[:24]}' — generated phishing domain pattern", 35)
    else:
        _add("Random Subdomain", "PASS", "Subdomains look human-readable")

    # Check 11: Excessive subdomain depth
    if len(labels) > 5:
        _add("Excessive Subdomains", "FAIL", f"{len(labels)} subdomain levels — phishing trick to mimic trusted URL structure", 30)
    else:
        _add("Excessive Subdomains", "PASS", f"Normal subdomain depth ({len(labels)} level(s))")

    # Check 12: Brand keyword in URL path (not domain)
    path_lower = path.lower()
    brand_path = next((b for b in _BRAND_DOMAINS if b in path_lower and b not in domain), None)
    if brand_path:
        _add("Brand in Path", "FAIL", f"Brand '{brand_path}' in URL path but not in domain — impersonation trick", 40)
    else:
        _add("Brand in Path", "PASS", "No suspicious brand keyword in path")

    # Check 13: Scam keywords in URL path/query
    _SCAM_KW = _re.compile(
        r'(kyc|otp|verify|login|secure|account|update|confirm|payment|wallet|'
        r'prize|lottery|reward|claim|refund|credential|password|signin|auth|'
        r'token|reset|alert|unlock|suspend|blocked|validate|authorize)',
        _re.IGNORECASE
    )
    kw_hits = list(set(_SCAM_KW.findall(path + '?' + query)))
    if len(kw_hits) >= 3:
        _add("Scam Keywords", "FAIL", f"Multiple scam keywords in URL: {', '.join(kw_hits[:5])}", 35)
    elif kw_hits:
        _add("Scam Keywords", "WARN", f"Scam keyword(s) in URL: {', '.join(kw_hits)}")
    else:
        _add("Scam Keywords", "PASS", "No scam keywords in URL path")

    # Check 14: Punycode / IDN domain
    if 'xn--' in domain:
        _add("Punycode/IDN", "FAIL", "Punycode domain — may visually impersonate a legitimate site using special chars", 60)
    else:
        _add("Punycode/IDN", "PASS", "No punycode internationalized domain")

    # Check 15: Embedded credentials in URL
    if _re.search(r'(user|username|pass|password|pwd)=[^&\s]+', url_lower):
        _add("Embedded Credentials", "FAIL", "Username/password in URL parameters — credential harvesting risk", 55)
    else:
        _add("Embedded Credentials", "PASS", "No credentials embedded in URL")

    # Check 16: Heavy hex/percent-encoding obfuscation
    hex_count = len(_re.findall(r'%[0-9a-fA-F]{2}', url))
    if hex_count > 10:
        _add("URL Obfuscation", "FAIL", f"{hex_count} percent-encoded characters — extensive encoding to hide malicious content", 35)
    elif hex_count > 4:
        _add("URL Obfuscation", "WARN", f"{hex_count} percent-encoded characters — moderate obfuscation")
    else:
        _add("URL Obfuscation", "PASS", f"Minimal encoding ({hex_count} encoded chars)")

    # Check 17: Open redirect parameter
    redir_hits = _re.findall(r'(redirect|return|next|goto|redir|forward)=https?://', url_lower)
    if redir_hits:
        _add("Open Redirect", "FAIL", f"Open redirect param '{redir_hits[0]}' detected — used in phishing chains", 45)
    else:
        _add("Open Redirect", "PASS", "No open redirect parameters")

    # Final scoring
    score   = min(score, 100)
    is_scam = score >= 80   # Only skip VT for very high-confidence threats

    return {
        "is_scam": is_scam,
        "score":   score,
        "reason":  "; ".join(reasons) if reasons else "No local threats found",
        "checks":  checks,
    }


# ── File Pre-scan ─────────────────────────────────────────────────────

# File extensions considered inherently dangerous
_DANGEROUS_EXTENSIONS = {
    '.exe', '.bat', '.cmd', '.vbs', '.ps1', '.scr',
    '.msi', '.com', '.pif', '.reg', '.jar', '.hta',
    '.lnk', '.wsf', '.js', '.jse', '.vbe', '.apk',
}

# Magic bytes (file header signatures) for common file types
_MAGIC_BYTES = {
    '.pdf':  b'%PDF-',
    '.png':  b'\x89PNG',
    '.jpg':  b'\xff\xd8\xff',
    '.jpeg': b'\xff\xd8\xff',
    '.gif':  b'GIF8',
    '.zip':  b'PK\x03\x04',
    '.apk':  b'PK\x03\x04',
    '.docx': b'PK\x03\x04',
    '.xlsx': b'PK\x03\x04',
    '.rar':  b'Rar!',
    '.7z':   b"7z\xbc\xaf'\x1c",
    '.bmp':  b'BM',
    '.mp3':  b'ID3',
    '.class': b'\xca\xfe\xba\xbe',
}

# Suspicious string patterns (compiled for performance)
_SUSPICIOUS_PATTERNS = [
    (_re.compile(rb'powershell', _re.IGNORECASE), 'PowerShell invocation detected'),
    (_re.compile(rb'cmd\.exe|cmd\s*/c', _re.IGNORECASE), 'cmd.exe command execution detected'),
    (_re.compile(rb'WScript\.Shell|Wscript\.Run', _re.IGNORECASE), 'WScript shell execution detected'),
    (_re.compile(rb'CreateObject\s*\(', _re.IGNORECASE), 'COM object creation detected (VBS/VBA)'),
    (_re.compile(rb'HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER', _re.IGNORECASE), 'Windows Registry manipulation detected'),
    (_re.compile(rb'net\s+user\s+', _re.IGNORECASE), 'User account manipulation command detected'),
    (_re.compile(rb'\\\\[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\\', _re.IGNORECASE), 'UNC path to IP address detected (possible C2)'),
    (_re.compile(rb'FromBase64String|atob\s*\(|base64\s*-d', _re.IGNORECASE), 'Base64 decode operation detected'),
    (_re.compile(rb'Invoke-Expression|IEX\s*\(|iex\s+', _re.IGNORECASE), 'PowerShell Invoke-Expression detected'),
    (_re.compile(rb'DownloadFile|DownloadString|WebClient|Invoke-WebRequest', _re.IGNORECASE), 'Remote file download detected'),
    (_re.compile(rb'Start-Process|ShellExecute', _re.IGNORECASE), 'Process execution command detected'),
    (_re.compile(rb'/etc/passwd|/etc/shadow', _re.IGNORECASE), 'Linux credential file access detected'),
]

# Embedded script markers inside documents
_SCRIPT_MARKERS = [
    (b'<script', 'Embedded JavaScript tag'),
    (b'VBA', 'VBA macro indicator'),
    (b'Auto_Open', 'Auto-executing Office macro (Auto_Open)'),
    (b'AutoOpen', 'Auto-executing Office macro (AutoOpen)'),
    (b'Workbook_Open', 'Auto-executing Excel macro (Workbook_Open)'),
    (b'Document_Open', 'Auto-executing Word macro (Document_Open)'),
    (b'/JavaScript', 'JavaScript action in PDF'),
    (b'/OpenAction', 'Auto-open action in PDF'),
    (b'/Launch', 'Launch action in PDF'),
    (b'/AA', 'Additional action trigger in PDF'),
]

# EICAR test file hash (standard antivirus test)
_EICAR_SHA256 = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'

# Known malicious file hashes (expandable)
_KNOWN_BAD_HASHES = {
    _EICAR_SHA256,  # EICAR test file
}


def _shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte data. High entropy (>7.0) suggests encryption/packing."""
    if not data:
        return 0.0
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    n = len(data)
    return -sum((count / n) * _math.log2(count / n) for count in freq.values())


def _compute_file_sha256(file_bytes: bytes) -> str:
    """Compute SHA-256 hash of file bytes."""
    return _hashlib.sha256(file_bytes).hexdigest()


def local_file_prescan(filename: str, file_bytes: bytes) -> dict:
    """
    Run advanced zero-shot local heuristics on an uploaded file.
    Returns dict with:
      - is_malicious: bool
      - risk_level: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS'
      - risk_score: int (0-100)
      - reason: str (summary)
      - should_skip_vt: bool
      - checks: list of {name, status, detail}
      - sha256: str
    """
    name_lower = filename.lower()
    reasons = []
    risk_score = 0
    checks = []

    def _add_check(name, status, detail, score_add=0):
        nonlocal risk_score
        checks.append({"name": name, "status": status, "detail": detail})
        if status == "FAIL":
            risk_score += score_add
            reasons.append(detail)

    # ── Compute SHA-256 hash ──────────────────────────────────────────
    file_hash = _compute_file_sha256(file_bytes) if file_bytes else ''

    # ── Parse filename parts ──────────────────────────────────────────
    parts = name_lower.split('.')
    ext = '.' + parts[-1] if len(parts) > 1 else ''

    # ── CHECK 1: Null-byte in filename ────────────────────────────────
    if '\x00' in filename or '%00' in filename:
        _add_check("Null-Byte Injection", "FAIL",
                    "Null byte in filename — possible path traversal attack", 40)
    else:
        _add_check("Null-Byte Injection", "PASS", "No null bytes in filename")

    # ── CHECK 2: RTLO Unicode character ───────────────────────────────
    if '\u202e' in filename:
        _add_check("RTLO Character", "FAIL",
                    "Right-to-Left Override character detected — file extension is visually reversed", 50)
    else:
        _add_check("RTLO Character", "PASS", "No Unicode direction override characters")

    # ── CHECK 3: Double-extension detection ───────────────────────────
    if len(parts) >= 3:
        last_ext = '.' + parts[-1]
        second_last_ext = '.' + parts[-2]
        safe_exts = {'.pdf', '.doc', '.docx', '.xls', '.xlsx', '.jpg', '.jpeg',
                     '.png', '.gif', '.txt', '.bmp', '.mp3', '.mp4', '.zip'}
        if last_ext in _DANGEROUS_EXTENSIONS and second_last_ext in safe_exts:
            _add_check("Double Extension", "FAIL",
                        f"Double extension '{second_last_ext}{last_ext}' — classic malware disguise", 50)
        else:
            _add_check("Double Extension", "PASS", "No suspicious double extension")
    else:
        _add_check("Double Extension", "PASS", "Single extension filename")

    # ── CHECK 4: Dangerous extension ──────────────────────────────────
    if ext in _DANGEROUS_EXTENSIONS:
        _add_check("Dangerous Extension", "FAIL",
                    f"Dangerous file type '{ext}' — executable or script file", 40)
    else:
        _add_check("Dangerous Extension", "PASS", f"Extension '{ext}' is not in dangerous list")

    # ── CHECK 5: Zero-byte / empty file ───────────────────────────────
    if not file_bytes or len(file_bytes) == 0:
        _add_check("Empty File", "FAIL",
                    "File is empty (0 bytes) — possible exploit placeholder", 15)
    else:
        _add_check("Empty File", "PASS", f"File contains {len(file_bytes)} bytes")

    # ── CHECK 6: Magic-byte vs extension mismatch ─────────────────────
    if ext in _MAGIC_BYTES and file_bytes:
        expected_magic = _MAGIC_BYTES[ext]
        if not file_bytes[:len(expected_magic)].startswith(expected_magic):
            actual_hex = file_bytes[:4].hex()
            _add_check("Magic Byte Mismatch", "FAIL",
                        f"Header mismatch for '{ext}': expected {expected_magic!r}, got 0x{actual_hex}", 35)
        else:
            _add_check("Magic Byte Mismatch", "PASS", f"File header matches '{ext}' signature")
    else:
        _add_check("Magic Byte Mismatch", "PASS", "No magic byte check applicable for this format")

    # ── CHECK 7: PE header detection in non-executable files ──────────
    if file_bytes and ext not in _DANGEROUS_EXTENSIONS:
        # MZ header = Windows PE executable
        if file_bytes[:2] == b'MZ':
            _add_check("Hidden Executable", "FAIL",
                        f"Windows PE executable header (MZ) found inside '{ext}' file — disguised executable", 50)
        else:
            _add_check("Hidden Executable", "PASS", "No hidden PE executable header")
    else:
        _add_check("Hidden Executable", "PASS", "Check not applicable")

    # ── CHECK 8: Shannon entropy analysis ─────────────────────────────
    # Skip for naturally-compressed formats (they always have high entropy)
    _COMPRESSED_EXTS = {'.jpg', '.jpeg', '.png', '.gif', '.zip', '.rar', '.7z',
                        '.mp3', '.mp4', '.apk', '.docx', '.xlsx', '.gz', '.bz2',
                        '.webp', '.mp4', '.avi', '.mkv', '.flac', '.ogg'}
    if file_bytes and len(file_bytes) > 256 and ext not in _COMPRESSED_EXTS:
        entropy = _shannon_entropy(file_bytes)
        if entropy > 7.5:
            _add_check("Entropy Analysis", "FAIL",
                        f"Very high entropy ({entropy:.2f}/8.0) — likely encrypted or packed malware payload", 30)
        elif entropy > 7.2:
            _add_check("Entropy Analysis", "WARN",
                        f"High entropy ({entropy:.2f}/8.0) — possibly compressed or packed content", 0)
        else:
            _add_check("Entropy Analysis", "PASS", f"Normal entropy level ({entropy:.2f}/8.0)")
    else:
        _add_check("Entropy Analysis", "PASS",
                    f"Skipped — {'compressed format' if ext in _COMPRESSED_EXTS else 'file too small'}")

    # ── CHECK 9: Embedded scripts / macros ────────────────────────────
    # Only check document types where embedded scripts are meaningful
    _DOCUMENT_EXTS = {'.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
                      '.html', '.htm', '.xml', '.rtf', '.odt', '.ods'}
    if file_bytes and ext in _DOCUMENT_EXTS:
        script_findings = []
        for marker, desc in _SCRIPT_MARKERS:
            if marker in file_bytes:
                script_findings.append(desc)
        if script_findings:
            detail = "Embedded scripts detected: " + "; ".join(script_findings)
            score = 25 if any(x in detail for x in ['Auto_Open', 'AutoOpen', 'Workbook_Open', 'Document_Open', '/Launch']) else 15
            _add_check("Script/Macro Detection", "FAIL", detail, score)
        else:
            _add_check("Script/Macro Detection", "PASS", "No embedded scripts or macros detected")
    else:
        _add_check("Script/Macro Detection", "PASS",
                    "Skipped — not a document format" if ext not in _DOCUMENT_EXTS else "No content to scan")

    # ── CHECK 10: Suspicious string patterns ──────────────────────────
    # Only scan text-like / document / script files (not images/media/archives)
    _TEXT_SCANNABLE_EXTS = {'.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
                            '.html', '.htm', '.xml', '.rtf', '.txt', '.csv', '.json',
                            '.js', '.vbs', '.ps1', '.bat', '.cmd', '.py', '.sh',
                            '.odt', '.ods', '.svg', '.php', '.asp', '.jsp'}
    if file_bytes and ext in _TEXT_SCANNABLE_EXTS:
        string_findings = []
        for pattern, desc in _SUSPICIOUS_PATTERNS:
            if pattern.search(file_bytes):
                string_findings.append(desc)
        if string_findings:
            detail = "Suspicious patterns: " + "; ".join(string_findings[:5])
            if len(string_findings) > 5:
                detail += f" (+{len(string_findings) - 5} more)"
            _add_check("Suspicious Strings", "FAIL", detail, min(len(string_findings) * 10, 40))
        else:
            _add_check("Suspicious Strings", "PASS", "No suspicious command/code patterns found")
    else:
        _add_check("Suspicious Strings", "PASS",
                    "Skipped — not a text/document format" if ext not in _TEXT_SCANNABLE_EXTS else "No content to scan")

    # ── CHECK 11: Large text file ─────────────────────────────────────
    if ext == '.txt' and file_bytes and len(file_bytes) > 10 * 1024 * 1024:
        _add_check("Oversized Text File", "FAIL",
                    "Text file is larger than 10 MB — possible data exfiltration payload", 15)
    else:
        _add_check("Oversized Text File", "PASS", "File size is within normal range")

    # ── CHECK 12: Known malware hash ──────────────────────────────────
    if file_hash and file_hash in _KNOWN_BAD_HASHES:
        hash_type = "EICAR test file" if file_hash == _EICAR_SHA256 else "known malware"
        _add_check("Known Malware Hash", "FAIL",
                    f"SHA-256 matches {hash_type} ({file_hash[:16]}…)", 60)
    else:
        _add_check("Known Malware Hash", "PASS",
                    f"SHA-256 not in known-bad database" + (f" ({file_hash[:16]}…)" if file_hash else ""))

    # ── Compute final risk level ──────────────────────────────────────
    risk_score = min(risk_score, 100)

    if risk_score >= 50:
        risk_level = 'MALICIOUS'
    elif risk_score >= 35:
        risk_level = 'SUSPICIOUS'
    else:
        risk_level = 'SAFE'

    return {
        "is_malicious": risk_level == 'MALICIOUS',
        "risk_level": risk_level,
        "risk_score": risk_score,
        "reason": "; ".join(reasons) if reasons else "No local threats found",
        "should_skip_vt": any("Known Malware Hash" in c["name"] for c in checks),  # Only skip VT for known malware
        "checks": checks,
        "sha256": file_hash,
    }



# =====================================
# Upload file to VirusTotal
# =====================================
def upload_to_virustotal(file_path):
    print("\n===== UPLOADING TO VIRUSTOTAL =====")

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        with open(file_path, "rb") as f:
            files = {"file": (os.path.basename(file_path), f)}
            response = requests.post(
                VIRUSTOTAL_UPLOAD_URL,
                headers=headers,
                files=files
            )

        print("Upload Status:", response.status_code)
        print("Upload Response:", response.text)

        data = response.json()

        if response.status_code == 200:
            return {"type": "analysis", "id": data["data"]["id"]}

        elif response.status_code == 409:
            sha256 = data.get("meta", {}).get("file_info", {}).get("sha256")
            return {"type": "file", "id": sha256}

        else:
            return {"error": response.text}

    except Exception as e:
        print("Upload Error:", str(e))
        return {"error": str(e)}


# =====================================
# Get VirusTotal Report
# =====================================
def get_virustotal_report(vt_type, vt_id):
    print("\n===== FETCHING VIRUSTOTAL REPORT =====")

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        # If we got analysis ID → get SHA256 with retry backoff
        if vt_type == "analysis":
            analysis_response = requests.get(
                VIRUSTOTAL_ANALYSIS_URL + vt_id,
                headers=headers,
                timeout=15
            )

            analysis_json = analysis_response.json()

            sha256 = analysis_json["meta"]["file_info"]["sha256"]
            vt_id = sha256

            print("SHA256:", sha256)

        # Retry with backoff: 5, 10, 15, 20 seconds (total ~50s max)
        RETRY_DELAYS = [5, 10, 15, 20]
        response = None

        for delay in RETRY_DELAYS:
            print(f"Waiting {delay}s before fetching report...")
            time.sleep(delay)

            response = requests.get(
                VIRUSTOTAL_FILE_REPORT_URL + vt_id,
                headers=headers,
                timeout=15
            )

            if response.status_code == 200:
                data = response.json().get("data", {})
                attrs = data.get("attributes", {})
                # Check if analysis is actually complete
                stats = attrs.get("last_analysis_stats", {})
                total = sum(stats.values()) if stats else 0
                if total > 0:
                    print("Report ready after waiting.")
                    break
            print(f"Report not ready yet (HTTP {response.status_code}), retrying...")

        if not response or response.status_code != 200:
            return {"error": "Failed to fetch file report after retries"}

        attributes = response.json()["data"]["attributes"]

        stats = attributes.get("last_analysis_stats", {})
        results = attributes.get("last_analysis_results", {})

        detected_engines = []

        for engine_name, engine_data in results.items():
            if engine_data.get("category") == "malicious":
                detected_engines.append({
                    "engine": engine_name,
                    "result": engine_data.get("result")
                })

        # =====================================
        # Detect Malware Type (expanded 15 types)
        # =====================================
        _MALWARE_KEYWORDS = [
            ("ransom",      "Ransomware"),
            ("trojan",      "Trojan"),
            ("worm",        "Worm"),
            ("spyware",     "Spyware"),
            ("backdoor",    "Backdoor"),
            ("adware",      "Adware"),
            ("rootkit",     "Rootkit"),
            ("keylog",      "Keylogger"),
            ("coinminer",   "Cryptominer"),
            ("cryptominer", "Cryptominer"),
            ("miner",       "Cryptominer"),
            ("dropper",     "Dropper"),
            ("exploit",     "Exploit"),
            ("phish",       "Phishing"),
            ("pup",         "PUP (Potentially Unwanted)"),
            ("pua",         "PUP (Potentially Unwanted)"),
            ("infostealer", "Infostealer"),
            ("stealer",     "Infostealer"),
            ("eicar",       "Test Malware (EICAR)"),
        ]

        malware_type = None
        for engine in detected_engines:
            result_name = (engine.get("result") or "").lower()
            for keyword, label in _MALWARE_KEYWORDS:
                if keyword in result_name:
                    malware_type = label
                    break
            if malware_type:
                break

        if not malware_type and detected_engines:
            malware_type = "Malware (Generic)"

        print("Detected Malware Type:", malware_type)

        return {
            "stats": stats,
            "engines": detected_engines,
            "malware_type": malware_type
        }

    except Exception as e:
        print("Report Error:", str(e))
        return {"error": str(e)}


# =====================================
# MAIN VIEW
# =====================================
def upload_and_scan(request, user_id):
    print("\n===== NEW SCAN REQUEST =====")

    user = get_object_or_404(models.Register, id=user_id)

    result = None
    error = None
    is_malicious = None
    prescan_data = None

    if request.method == "POST":
        uploaded_file = request.FILES.get("file")

        if not uploaded_file:
            error = "No file uploaded"

        else:
            # ── Read full file bytes for deep local analysis ──────────────────
            file_bytes = uploaded_file.read()
            uploaded_file.seek(0)   # rewind so chunks() still works
            file_size = uploaded_file.size

            # ── Local File Pre-scan (12-check heuristic engine) ───────────────
            prescan = local_file_prescan(uploaded_file.name, file_bytes)
            prescan_data = prescan  # Save for template context
            file_hash = prescan.get("sha256", "")

            if prescan["is_malicious"] and prescan["should_skip_vt"]:
                print("Local scan high-confidence threat! Skipping VirusTotal.")
                is_malicious = True
                result = {
                    "malicious": 1,
                    "harmless": 0,
                    "suspicious": 0,
                    "undetected": 0,
                    "engines": [{"engine": "Local Heuristic Engine", "result": prescan["reason"]}],
                    "malware_type": "Known Malware (Local Hash Match)",
                    "prescan_reason": prescan["reason"],
                }
                models.UserFile.objects.create(
                    user=user,
                    file_name=uploaded_file.name,
                    vt_analysis_id="LOCAL_SCAN",
                    vt_malicious=1,
                    vt_harmless=0,
                    vt_suspicious=0,
                    vt_undetected=0,
                    malware_type="Known Malware (Local Hash Match)",
                    is_malicious=True,
                    is_pending=False,
                    file_sha256=file_hash,
                    file_size=file_size,
                    risk_score=prescan.get("risk_score", 0),
                    scan_details=_json.dumps(prescan.get("checks", [])),
                )
            else:
                if prescan["risk_level"] == 'SUSPICIOUS' or prescan["risk_level"] == 'MALICIOUS':
                    print(f"Local warning: {prescan['reason']}. Verifying with VirusTotal...")
                    error = f"\u26a0\ufe0f Local Warning: {prescan['reason']}. Verifying with VirusTotal..."
                
                print("Uploading to VirusTotal...")
                # Upload to VirusTotal for cloud analysis
                temp_dir = os.path.join(settings.MEDIA_ROOT, "temp")
                os.makedirs(temp_dir, exist_ok=True)
                temp_path = os.path.join(temp_dir, uploaded_file.name)

                with open(temp_path, "wb+") as f:
                    for chunk in uploaded_file.chunks():
                        f.write(chunk)

                vt_response = upload_to_virustotal(temp_path)

                if "error" in vt_response:
                    error = vt_response["error"]

                else:
                    vt_data = get_virustotal_report(
                        vt_response["type"],
                        vt_response["id"]
                    )

                    if "error" in vt_data:
                        error = vt_data["error"]

                    else:
                        stats = vt_data.get("stats", {})

                        malicious = stats.get("malicious", 0)
                        harmless = stats.get("harmless", 0)
                        suspicious = stats.get("suspicious", 0)
                        undetected = stats.get("undetected", 0)

                        # Logic: VT overrides local heuristics if it finds 0 threats
                        # but local heuristics WIN if they detect a known malicious hash.
                        is_malicious = malicious > 0 or (prescan["is_malicious"] and prescan["should_skip_vt"])
                        
                        malware_type = vt_data.get("malware_type")
                        if is_malicious and not malware_type:
                            malware_type = "Locally Flagged"
                        elif not is_malicious:
                            malware_type = None  # Force "SECURE" logic in template

                        result = {
                            "malicious": malicious,
                            "harmless": harmless,
                            "suspicious": suspicious,
                            "undetected": undetected,
                            "engines": vt_data.get("engines", []),
                            "malware_type": malware_type
                        }

                        models.UserFile.objects.create(
                            user=user,
                            file_name=uploaded_file.name,
                            vt_analysis_id=vt_response["id"],
                            vt_malicious=malicious,
                            vt_harmless=harmless,
                            vt_suspicious=suspicious,
                            vt_undetected=undetected,
                            malware_type=malware_type,
                            is_malicious=is_malicious,
                            is_pending=False,
                            file_sha256=file_hash,
                            file_size=file_size,
                            risk_score=prescan.get("risk_score", 0),
                            scan_details=_json.dumps(prescan.get("checks", [])),
                        )

                if os.path.exists(temp_path):
                    os.remove(temp_path)

    files = models.UserFile.objects.filter(user=user).order_by("-uploaded_at")

    return render(request, "upload_file.html", {
        "user": user,
        "files": files,
        "result": result,
        "is_malicious": is_malicious,
        "error": error,
        "prescan": prescan_data,
    })

def admin_login(request):
    if request.method=="POST":
        uname=request.POST.get('username')
        password=request.POST.get('password')
        u = 'admin'
        p='123456'

        if uname==u and password==p:
            request.session['admin_logged_in'] = True
            return HttpResponse("""
                <script>
                    alert('Login Successfully');
                    window.location.href='/admin_dashboard/';
                </script>
            """)
        else:
            return HttpResponse("""
                <script>
                    alert('Invalid Admin Username or Password!');
                    window.location.href='/admin_login/';
                </script>
            """)
        
    return render(request,'admin_login.html')

from django.utils import timezone
from .models import UserFile, Urls, Feedback
from detector.models import SMSMessage
from fraud_detection.models import UPIID

def admin_dashboard(request):
    if not request.session.get('admin_logged_in'):
        return redirect('admin_login')

    safe_count = UserFile.objects.filter(is_malicious=False).count()
    threat_count = UserFile.objects.filter(is_malicious=True).count()
    suspicious_count = UserFile.objects.filter(vt_suspicious__gt=0).count()

    today = timezone.now().date()
    today_scans = UserFile.objects.filter(uploaded_at__date=today).count()

    recent_threats = UserFile.objects.filter(
        is_malicious=True
    ).order_by("-uploaded_at")[:10]

    # Global Module Usage Counts for Chart
    file_scan_count = UserFile.objects.count()
    url_scan_count = Urls.objects.count()
    sms_scan_count = SMSMessage.objects.count()
    upi_scan_count = UPIID.objects.count()
    feedback_count = Feedback.objects.count()

    return render(request, "admin_dashboard.html", {
        "safe_count": safe_count,
        "threat_count": threat_count,
        "suspicious_count": suspicious_count,
        "today_scans": today_scans,
        "recent_threats": recent_threats,
        # Chart data
        "file_scan_count": file_scan_count,
        "url_scan_count": url_scan_count,
        "sms_scan_count": sms_scan_count,
        "upi_scan_count": upi_scan_count,
        "feedback_count": feedback_count,
    })


def user_list(request):
    if not request.session.get('admin_logged_in'):
        return redirect('admin_login')
    users = models.Register.objects.all()
    return render(request,'user_list.html',{'users':users})


def deleteuser(request,id):
    if not request.session.get('admin_logged_in'):
        return redirect('admin_login')
    u=models.Register.objects.get(id=id)
    u.delete()
    return redirect('user_list')

def deletefile(request, id):
    if not request.session.get('admin_logged_in'):
        return redirect('admin_login')
    file_obj = models.UserFile.objects.get(id=id)
    file_obj.delete()
    return redirect('admin_file_list')


def admin_file_list(request):
    if not request.session.get('admin_logged_in'):
        return redirect('admin_login')
    files = models.UserFile.objects.all().order_by('-uploaded_at')
    return render(request, 'admin_file_list.html', {
        'files': files,
    })

def logout(request):
    request.session.flush() 
    return redirect('index')



# ==============================
# URL SCANNER
# ==============================
VT_URL_SCAN      = "https://www.virustotal.com/api/v3/urls"
VT_URL_HEADERS   = {
    "x-apikey": VIRUSTOTAL_API_KEY,
    "Content-Type": "application/x-www-form-urlencoded"
}


def urlscanner(request):
    context = {}

    # Guard: require login
    if 'email' not in request.session:
        from django.shortcuts import redirect
        return redirect('login')

    if request.method != "POST":
        return render(request, "urlscanner.html", context)

    link = request.POST.get("link", "").strip()

    # Basic input validation — also accept upi:// deep-links for detection
    if not link:
        context["error"] = "Please enter a URL to scan."
        return render(request, "urlscanner.html", context)

    # ── Local heuristic pre-scan (zero-shot) ──────────────────────────────────
    # Run BEFORE VirusTotal to catch UPI deep-links, typosquats, etc.
    # and to save VirusTotal API quota for genuinely ambiguous URLs.
    prescan = local_url_prescan(link)
    if prescan["is_scam"]:
        # We're confident enough — skip VirusTotal entirely
        try:
            user = models.Register.objects.get(email=request.session['email'])
            url_obj = models.Urls.objects.create(user=user, link=link, status="SCAM")
        except Exception:
            pass
        context.update({
            "url":              link,
            "final_status":     "SCAM",
            "malicious":        1,
            "suspicious":       0,
            "harmless":         0,
            "undetected":       0,
            "detected_engines": [{"engine": "Local Heuristic Engine", "result": prescan["reason"]}],
            "stats":            {"malicious": 1, "suspicious": 0, "harmless": 0, "undetected": 0},
            "prescan_reason":   prescan["reason"],
        })
        return render(request, "result.html", context)

    # Require http/https for the VirusTotal path
    if not (link.startswith("http://") or link.startswith("https://")):
        context["error"] = "Please enter a valid URL starting with http:// or https://"
        return render(request, "urlscanner.html", context)

    try:
        user = models.Register.objects.get(email=request.session['email'])
    except models.Register.DoesNotExist:
        context["error"] = "Session user not found. Please log in again."
        return render(request, "urlscanner.html", context)

    # Persist the scan record early
    url_obj = models.Urls.objects.create(user=user, link=link, status="SCANNING")

    # ── Step 1: Submit URL to VirusTotal ──────────────────────────────────────
    try:
        response = requests.post(
            VT_URL_SCAN,
            headers=VT_URL_HEADERS,
            data={"url": link},
            timeout=15        # don't hang forever on submit
        )
    except requests.exceptions.RequestException as exc:
        url_obj.status = "ERROR"
        url_obj.save()
        context["error"] = f"Network error while submitting URL: {exc}"
        return render(request, "urlscanner.html", context)

    if response.status_code not in (200, 201):
        url_obj.status = "ERROR"
        url_obj.save()
        context["error"] = f"VirusTotal rejected the request (HTTP {response.status_code})"
        return render(request, "urlscanner.html", context)

    try:
        analysis_id = response.json()["data"]["id"]
    except (ValueError, KeyError):
        url_obj.status = "ERROR"
        url_obj.save()
        context["error"] = "Unexpected response from VirusTotal."
        return render(request, "urlscanner.html", context)

    # ── Step 2: Poll with exponential back-off (max ~60 s total) ─────────────
    # Delays: 3, 5, 8, 12, 17 … seconds — totals ~45 s before giving up
    POLL_DELAYS = [3, 5, 8, 12, 17]

    for delay in POLL_DELAYS:
        time.sleep(delay)

        try:
            report = requests.get(
                VIRUSTOTAL_ANALYSIS_URL + analysis_id,
                headers={"x-apikey": VIRUSTOTAL_API_KEY},
                timeout=10
            )
        except requests.exceptions.RequestException:
            continue  # transient error — try again

        if report.status_code != 200:
            continue

        try:
            data       = report.json()["data"]
            attributes = data["attributes"]
        except (ValueError, KeyError):
            continue

        if attributes.get("status") != "completed":
            continue

        # ── Step 3: Parse results ─────────────────────────────────────────────
        stats = attributes.get("stats", {})
        malicious   = stats.get("malicious",   0)
        suspicious  = stats.get("suspicious",  0)
        harmless    = stats.get("harmless",    0)
        undetected  = stats.get("undetected",  0)

        # Collect engines that flagged the URL
        results = attributes.get("results", {})
        detected_engines = [
            {"engine": eng, "result": info.get("result")}
            for eng, info in results.items()
            if info.get("category") in ("malicious", "suspicious")
        ]

        final_status = "SCAM" if (malicious > 0 or suspicious > 0) else "SAFE"

        # ── Step 4: Persist ───────────────────────────────────────────────────
        url_obj.status = final_status
        url_obj.save()

        # ── Step 5: Render ────────────────────────────────────────────────────
        context.update({
            "url":              link,
            "stats":            stats,
            "final_status":     final_status,
            "malicious":        malicious,
            "suspicious":       suspicious,
            "harmless":         harmless,
            "undetected":       undetected,
            "detected_engines": detected_engines,
        })
        return render(request, "result.html", context)

    # ── Timed out waiting for analysis ────────────────────────────────────────
    url_obj.status = "PENDING"
    url_obj.save()
    context["final_status"] = "PENDING"
    context["error"] = "VirusTotal is still processing the URL. Please check back in a moment."

    return render(request, "urlscanner.html", context)




#history
def reports(request):
    qs = models.Urls.objects.all().order_by("-id")

    # Search by URL link
    q = request.GET.get("q", "").strip()
    if q:
        qs = qs.filter(link__icontains=q)

    # Filter by status
    status_filter = request.GET.get("status", "").strip()
    if status_filter in ("SAFE", "SCAM", "PENDING", "ERROR"):
        qs = qs.filter(status=status_filter)

    # Global stats (unfiltered)
    all_records = models.Urls.objects.all()
    stats = {
        "total":   all_records.count(),
        "scam":    all_records.filter(status="SCAM").count(),
        "safe":    all_records.filter(status="SAFE").count(),
        "pending": all_records.filter(status="PENDING").count(),
        "error":   all_records.filter(status="ERROR").count(),
    }

    return render(request, 'reports.html', {
        'urls':          qs,
        'stats':         stats,
        'q':             q,
        'status_filter': status_filter,
    })



#APPLICATION SCAN

def app_scan(request, user_id):
    print("\n===== NEW SCAN REQUEST =====")

    user = get_object_or_404(models.Register, id=user_id)

    result = None
    error = None
    is_malicious = None

    if request.method == "POST":
        uploaded_file = request.FILES.get("file")

        if not uploaded_file:
            error = "No file uploaded"

        else:
            # ── Local File Pre-scan (zero-shot heuristics) ────────────────────
            file_header = uploaded_file.read(16)
            uploaded_file.seek(0)
            file_bytes_for_check = file_header + b'\x00' * max(0, 16 - len(file_header))

            prescan = local_file_prescan(uploaded_file.name, file_bytes_for_check)

            if prescan["is_malicious"]:
                is_malicious = True
                result = {
                    "malicious": 1,
                    "harmless": 0,
                    "suspicious": 0,
                    "undetected": 0,
                    "engines": [{"engine": "Local Heuristic Engine", "result": prescan["reason"]}],
                    "malware_type": "Suspicious File (Local Detection)",
                    "prescan_reason": prescan["reason"],
                }
                models.UserFile.objects.create(
                    user=user,
                    file_name=uploaded_file.name,
                    vt_analysis_id="LOCAL_SCAN",
                    vt_malicious=1,
                    vt_harmless=0,
                    vt_suspicious=0,
                    vt_undetected=0,
                    malware_type="Suspicious File (Local Detection)",
                    is_malicious=True,
                    is_pending=False
                )
            elif prescan["risk_level"] == 'SUSPICIOUS':
                error = f"⚠️ Warning: {prescan['reason']}. Proceeding to VirusTotal for deeper scan."

            if not prescan["should_skip_vt"]:
                temp_dir = os.path.join(settings.MEDIA_ROOT, "temp")
                os.makedirs(temp_dir, exist_ok=True)
                temp_path = os.path.join(temp_dir, uploaded_file.name)

                with open(temp_path, "wb+") as f:
                    for chunk in uploaded_file.chunks():
                        f.write(chunk)

                vt_response = upload_to_virustotal(temp_path)

                if "error" in vt_response:
                    error = vt_response["error"]

                else:
                    vt_data = get_virustotal_report(
                        vt_response["type"],
                        vt_response["id"]
                    )

                    if "error" in vt_data:
                        error = vt_data["error"]

                    else:
                        stats = vt_data.get("stats", {})

                        malicious = stats.get("malicious", 0)
                        harmless = stats.get("harmless", 0)
                        suspicious = stats.get("suspicious", 0)
                        undetected = stats.get("undetected", 0)

                        is_malicious = malicious > 0
                        malware_type = vt_data.get("malware_type")

                        result = {
                            "malicious": malicious,
                            "harmless": harmless,
                            "suspicious": suspicious,
                            "undetected": undetected,
                            "engines": vt_data.get("engines", []),
                            "malware_type": malware_type
                        }

                        models.UserFile.objects.create(
                            user=user,
                            file_name=uploaded_file.name,
                            vt_analysis_id=vt_response["id"],
                            vt_malicious=malicious,
                            vt_harmless=harmless,
                            vt_suspicious=suspicious,
                            vt_undetected=undetected,
                            malware_type=malware_type,
                            is_malicious=is_malicious,
                            is_pending=False
                        )

                if os.path.exists(temp_path):
                    os.remove(temp_path)

    files = models.UserFile.objects.filter(user=user).order_by("-uploaded_at")

    return render(request, "application_scan.html", {
        "user": user,
        "files": files,
        "result": result,
        "is_malicious": is_malicious,
        "error": error
    })
