import re
from urllib.parse import urlparse
from detector.company_verifier import verify_company

# Common public/free email providers.
# Using these providers is NOT proof of fraud.
FREE_EMAIL_DOMAINS = {
    "gmail.com",
    "yahoo.com",
    "hotmail.com",
    "outlook.com",
    "rediffmail.com",
    "icloud.com",
    "proton.me",
    "protonmail.com",
}


# Common URL shortening services.
URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "cutt.ly",
    "rb.gy",
    "ow.ly",
}


# Common email marketing/tracking platforms.
# Tracking links are NOT automatically suspicious.
TRACKING_DOMAINS = {
    "moengage.com",
    "mailchimp.com",
    "sendgrid.net",
    "sendgrid.com",
    "hubspot.com",
    "mandrillapp.com",
}


# Terms that can be useful risk signals in email content.
EMAIL_RISK_PATTERNS = {
    "urgent": 5,
    "immediately": 5,
    "payment": 8,
    "fee": 8,
    "refund": 5,
    "claim": 3,
    "otp": 15,
    "password": 15,
    "cvv": 20,
    "upi pin": 20,
    "bank details": 15,
    "bank account": 12,
}


def normalize_domain(domain):
    """Return a normalized lowercase domain."""

    if not domain:
        return ""

    domain = domain.strip().lower()

    if domain.startswith("www."):
        domain = domain[4:]

    return domain


def is_same_or_subdomain(domain, parent_domain):
    """
    Check whether domain is the same as parent_domain
    or a subdomain of it.
    """

    domain = normalize_domain(domain)
    parent_domain = normalize_domain(parent_domain)

    if not domain or not parent_domain:
        return False

    return (
        domain == parent_domain
        or domain.endswith("." + parent_domain)
    )


def extract_email_addresses(text):
    """Extract email addresses from text."""

    if not text:
        return []

    pattern = (
        r"\b[A-Za-z0-9._%+\-]+"
        r"@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
    )

    matches = re.findall(pattern, text)

    unique_emails = []

    for email in matches:
        email = email.lower()

        if email not in unique_emails:
            unique_emails.append(email)

    return unique_emails


def extract_urls(text):
    """Extract HTTP/HTTPS URLs from text."""

    if not text:
        return []

    pattern = r"https?://[^\s<>\"]+"

    matches = re.findall(
        pattern,
        text,
        flags=re.IGNORECASE
    )

    urls = []

    for url in matches:

        # Remove punctuation accidentally attached to URL.
        url = url.rstrip(
            ".,;:!?)]}>\"'"
        )

        if url not in urls:
            urls.append(url)

    return urls


def get_domain_from_email(email):
    """Extract domain from email address."""

    if not email or "@" not in email:
        return ""

    domain = email.rsplit("@", 1)[1]

    return normalize_domain(domain)


def get_domain_from_url(url):
    """Extract hostname from URL."""

    try:

        parsed = urlparse(url)

        hostname = parsed.hostname

        if not hostname:
            return ""

        return normalize_domain(hostname)

    except ValueError:
        return ""


def check_email(email):
    """
    Analyse a single email address.

    This checks structure and basic domain signals.
    It does NOT verify the identity of the sender.
    """

    email = email.strip().lower()

    if not email:

        return {
            "provided": False,
            "valid": False,
            "email": "",
            "domain": "",
            "findings": []
        }

    pattern = (
        r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
    )

    if not re.match(pattern, email):

        return {
            "provided": True,
            "valid": False,
            "email": email,
            "domain": "",
            "findings": [
                {
                    "category": "Email",
                    "indicator": "Invalid email format",
                    "weight": 10
                }
            ]
        }

    domain = get_domain_from_email(email)

    findings = []

    # Free email provider.
    if domain in FREE_EMAIL_DOMAINS:

        findings.append({
            "category": "Email Domain",
            "indicator": "Free/public email provider used",
            "weight": 8
        })

    # Recruitment-related local-part patterns.
    local_part = email.split("@", 1)[0]

    recruitment_words = [
        "recruitment",
        "recruiter",
        "recruit",
        "job",
        "jobs",
        "career",
        "careers",
        "hr",
        "placement",
        "offer",
        "hiring",
    ]

    for word in recruitment_words:

        if word in local_part:

            findings.append({
                "category": "Email Pattern",
                "indicator": (
                    f"Recruitment-related email pattern: {word}"
                ),
                "weight": 3
            })

    return {
        "provided": True,
        "valid": True,
        "email": email,
        "domain": domain,
        "findings": findings
    }


def analyze_email_content(
    text,
    supplied_sender_email=""
):
    """
    Analyse a complete email message.

    This function:
    - extracts email addresses
    - extracts URLs
    - identifies domains
    - detects tracking URLs
    - detects URL shorteners
    - compares sender domain with linked domains
    - checks selected risky terms

    It does NOT prove whether an email is genuine or fake.
    """

    if not text:

        return {
            "emails_detected": [],
            "sender_email": "",
            "sender_domain": "",
            "urls_detected": [],
            "domains_detected": [],
            "tracking_urls": [],
            "url_shorteners": [],
            "domain_mismatch": False,
            "findings": []
        }

    findings = []

    # ---------------------------------------------------------
    # 1. Extract emails
    # ---------------------------------------------------------

    detected_emails = extract_email_addresses(text)

    sender_email = (
        supplied_sender_email.strip().lower()
    )

    # If sender field wasn't supplied,
    # use the first detected email.
    if not sender_email and detected_emails:

        sender_email = detected_emails[0]

    sender_domain = get_domain_from_email(
        sender_email
    )

    # ---------------------------------------------------------
    # 2. Analyse sender email
    # ---------------------------------------------------------

    if sender_email:

        sender_result = check_email(
            sender_email
        )

        findings.extend(
            sender_result.get(
                "findings",
                []
            )
        )

    # ---------------------------------------------------------
    # 3. Extract URLs
    # ---------------------------------------------------------

    urls = extract_urls(text)

    url_details = []
    domains = []
    tracking_urls = []
    shortener_urls = []

    for url in urls:

        domain = get_domain_from_url(url)

        try:

            parsed = urlparse(url)

            scheme = (
                parsed.scheme.lower()
            )

        except ValueError:

            scheme = ""

        url_info = {
            "url": url,
            "domain": domain,
            "https": scheme == "https",
            "tracking": False,
            "shortener": False
        }

        if domain and domain not in domains:

            domains.append(domain)

        # -----------------------------------------------------
        # Tracking domain
        # -----------------------------------------------------

        is_tracking = False

        for tracking_domain in TRACKING_DOMAINS:

            if is_same_or_subdomain(
                domain,
                tracking_domain
            ):
                is_tracking = True
                break

        if is_tracking:

            url_info["tracking"] = True

            tracking_urls.append(url)

        # -----------------------------------------------------
        # URL shortener
        # -----------------------------------------------------

        if domain in URL_SHORTENERS:

            url_info["shortener"] = True

            shortener_urls.append(url)

            findings.append({
                "category": "Email URL",
                "indicator": (
                    f"URL shortener detected: {domain}"
                ),
                "weight": 10
            })

        # -----------------------------------------------------
        # HTTP instead of HTTPS
        # -----------------------------------------------------

        if scheme == "http":

            findings.append({
                "category": "Email URL Security",
                "indicator": (
                    f"Email link does not use HTTPS: {domain}"
                ),
                "weight": 10
            })

        url_details.append(url_info)

    # ---------------------------------------------------------
    # 4. Sender domain vs linked domains
    # ---------------------------------------------------------

    domain_mismatch = False

    non_tracking_domains = []

    for domain in domains:

        is_tracking = False

        for tracking_domain in TRACKING_DOMAINS:

            if is_same_or_subdomain(
                domain,
                tracking_domain
            ):
                is_tracking = True
                break

        if not is_tracking:
            non_tracking_domains.append(domain)

    if sender_domain and non_tracking_domains:

        unrelated_domains = []

        for domain in non_tracking_domains:

            if not is_same_or_subdomain(
                domain,
                sender_domain
            ):
                unrelated_domains.append(domain)

        if unrelated_domains:

            domain_mismatch = True

            findings.append({
                "category": "Email Domain Relationship",
                "indicator": (
                    "Email contains links to domains "
                    "different from the sender domain"
                ),
                "weight": 5
            })

    # ---------------------------------------------------------
    # 5. Risk-related words
    # ---------------------------------------------------------

    normalized_text = text.lower()

    for word, weight in EMAIL_RISK_PATTERNS.items():

        if word in normalized_text:

            findings.append({
                "category": "Email Content",
                "indicator": (
                    f"Sensitive/suspicious email term: {word}"
                ),
                "weight": weight
            })

    # ---------------------------------------------------------
    # Final result
    # ---------------------------------------------------------

    return {
        "emails_detected": detected_emails,
        "sender_email": sender_email,
        "sender_domain": sender_domain,
        "urls_detected": url_details,
        "domains_detected": domains,
        "tracking_urls": tracking_urls,
        "url_shorteners": shortener_urls,
        "domain_mismatch": domain_mismatch,
        "findings": findings
    }