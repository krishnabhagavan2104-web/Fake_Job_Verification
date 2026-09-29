from urllib.parse import urlparse
import re


SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "cutt.ly",
    "rb.gy",
    "ow.ly",
}


SUSPICIOUS_TLDS = {
    ".xyz",
    ".top",
    ".click",
    ".work",
    ".download",
}


def normalize_url(url):
    """Normalize URL by adding HTTPS when scheme is missing."""

    url = url.strip()

    if not url:
        return ""

    if not re.match(
        r"^https?://",
        url,
        re.IGNORECASE
    ):
        url = "https://" + url

    return url


def check_url(url):
    """Analyse a single URL without visiting it."""

    url = normalize_url(url)

    if not url:

        return {
            "provided": False,
            "valid": False,
            "findings": []
        }

    try:

        parsed = urlparse(url)

    except ValueError:

        return {
            "provided": True,
            "valid": False,
            "findings": [
                {
                    "category": "URL",
                    "indicator": "Invalid URL format",
                    "weight": 20
                }
            ]
        }

    findings = []

    # ---------------------------------------------------------
    # HTTPS
    # ---------------------------------------------------------

    if parsed.scheme != "https":

        findings.append({
            "category": "URL Security",
            "indicator": "Website does not use HTTPS",
            "weight": 15
        })

    # ---------------------------------------------------------
    # Domain
    # ---------------------------------------------------------

    hostname = (
        parsed.hostname or ""
    ).lower()

    if hostname.startswith("www."):

        hostname = hostname[4:]

    if not hostname:

        findings.append({
            "category": "URL",
            "indicator": "Missing domain",
            "weight": 20
        })

        return {
            "provided": True,
            "valid": False,
            "findings": findings
        }

    # ---------------------------------------------------------
    # Shortener
    # ---------------------------------------------------------

    if hostname in SHORTENERS:

        findings.append({
            "category": "URL",
            "indicator": "URL shortener detected",
            "weight": 15
        })

    # ---------------------------------------------------------
    # TLD
    # ---------------------------------------------------------

    if any(
        hostname.endswith(tld)
        for tld in SUSPICIOUS_TLDS
    ):

        findings.append({
            "category": "Domain Pattern",
            "indicator": (
                "Higher-risk domain extension detected"
            ),
            "weight": 10
        })

    # ---------------------------------------------------------
    # @ symbol
    # ---------------------------------------------------------

    if "@" in url:

        findings.append({
            "category": "URL",
            "indicator": (
                "URL contains @ symbol"
            ),
            "weight": 20
        })

    # ---------------------------------------------------------
    # Very long URL
    # ---------------------------------------------------------

    if len(url) > 150:

        findings.append({
            "category": "URL Pattern",
            "indicator": (
                "Unusually long URL"
            ),
            "weight": 8
        })

    # ---------------------------------------------------------
    # Suspicious path keywords
    # ---------------------------------------------------------

    suspicious_words = [
        "login",
        "verify",
        "payment",
        "fee",
        "reward",
        "claim",
        "urgent",
        "password",
        "otp",
    ]

    path = parsed.path.lower()

    for word in suspicious_words:

        if word in path:

            findings.append({
                "category": "URL Pattern",
                "indicator": (
                    f"Suspicious URL keyword: {word}"
                ),
                "weight": 8
            })

    return {
        "provided": True,
        "valid": True,
        "scheme": parsed.scheme,
        "domain": hostname,
        "path": parsed.path,
        "findings": findings
    }