from flask import Blueprint, request, jsonify
import re

from detector.analyzer import analyze_text
from detector.url_checker import check_url
from detector.email_checker import (
    check_email,
    analyze_email_content
)
from detector.company_checker import check_company
from detector.risk_engine import calculate_risk
from models.scan import save_scan


scan_bp = Blueprint(
    "scan",
    __name__
)


def looks_like_email_content(text):
    """
    Check whether the supplied text looks like
    a complete email.
    """

    if not text:
        return False

    text_lower = text.lower()

    # Common email headers
    email_headers = [
        "from:",
        "to:",
        "subject:",
        "sent:",
        "reply-to:"
    ]

    header_count = 0

    for header in email_headers:
        if header in text_lower:
            header_count += 1

    # Two or more email headers
    if header_count >= 2:
        return True

    # Newsletter / marketing email
    if "unsubscribe" in text_lower:
        return True

    # Email address + URL
    email_count = len(
        re.findall(
            r"\b[A-Za-z0-9._%+\-]+"
            r"@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
            text
        )
    )

    url_count = len(
        re.findall(
            r"https?://",
            text,
            flags=re.IGNORECASE
        )
    )

    if email_count >= 1 and url_count >= 1:
        return True

    return False


@scan_bp.post("/scan")
def scan():

    # ---------------------------------------------------------
    # Read JSON
    # ---------------------------------------------------------

    data = request.get_json(
        silent=True
    )

    if not data:
        return jsonify({
            "success": False,
            "error": "JSON request body is required."
        }), 400

    # ---------------------------------------------------------
    # Read fields
    # ---------------------------------------------------------

    text = str(
        data.get("text", "")
    ).strip()

    url = str(
        data.get("url", "")
    ).strip()

    email = str(
        data.get("email", "")
    ).strip()

    input_type = str(
        data.get(
            "input_type",
            "job"
        )
    ).strip().lower()

    # ---------------------------------------------------------
    # Validation
    # ---------------------------------------------------------

    if not text and not url and not email:
        return jsonify({
            "success": False,
            "error": (
                "Please provide job text, URL, or email."
            )
        }), 400

    if len(text) > 10000:
        return jsonify({
            "success": False,
            "error": (
                "Text is too long. "
                "Maximum is 10,000 characters."
            )
        }), 400

    # ---------------------------------------------------------
    # Store all findings
    # ---------------------------------------------------------

    all_findings = []

    # ---------------------------------------------------------
    # JOB / TEXT ANALYSIS
    # ---------------------------------------------------------

    if text:

        text_result = analyze_text(text)

        all_findings.extend(
            text_result.get(
                "findings",
                []
            )
        )

        # Company detection
        company_result = check_company(text)

        all_findings.extend(
            company_result.get(
                "findings",
                []
            )
        )

    else:

        company_result = {
            "companies_detected": [],
            "findings": []
        }

    # ---------------------------------------------------------
    # Detect email content
    # ---------------------------------------------------------

    email_content_detected = (
        input_type == "email"
        or bool(email)
        or looks_like_email_content(text)
    )

    # ---------------------------------------------------------
    # Advanced email analysis
    # ---------------------------------------------------------

    if email_content_detected and text:

        advanced_email_result = analyze_email_content(
            text=text,
            supplied_sender_email=email
        )

        all_findings.extend(
            advanced_email_result.get(
                "findings",
                []
            )
        )

    else:

        advanced_email_result = {
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

    # ---------------------------------------------------------
    # Email field analysis
    # ---------------------------------------------------------

    email_result = check_email(email)

    # If email is provided separately and there is
    # no text, analyse the email address.
    if email and not text:

        all_findings.extend(
            email_result.get(
                "findings",
                []
            )
        )

    # If text exists but it is not detected as a
    # complete email, analyse the supplied email separately.
    elif email and text and not email_content_detected:

        all_findings.extend(
            email_result.get(
                "findings",
                []
            )
        )

    # ---------------------------------------------------------
    # URL field analysis
    # ---------------------------------------------------------

    url_result = check_url(url)

    all_findings.extend(
        url_result.get(
            "findings",
            []
        )
    )

    # ---------------------------------------------------------
    # URLs found inside email
    # ---------------------------------------------------------

    email_body_urls = (
        advanced_email_result.get(
            "urls_detected",
            []
        )
    )

    for email_url_info in email_body_urls:

        email_url = email_url_info.get(
            "url",
            ""
        )

        if not email_url:
            continue

        # Tracking links have already been analysed
        if email_url_info.get(
            "tracking",
            False
        ):
            continue

        extracted_url_result = check_url(
            email_url
        )

        all_findings.extend(
            extracted_url_result.get(
                "findings",
                []
            )
        )

    # ---------------------------------------------------------
    # Calculate risk
    # ---------------------------------------------------------

    risk = calculate_risk(
        all_findings
    )

    # ---------------------------------------------------------
    # Save scan to database
    # ---------------------------------------------------------

    saved = save_scan(
        input_type=input_type,
        input_text=text,
        url=url,
        email=email,
        score=risk["score"],
        risk_level=risk["level"],
        findings=all_findings
    )

    # ---------------------------------------------------------
    # Response
    # ---------------------------------------------------------

    return jsonify({

        "success": True,

        "risk": risk,

        "findings": all_findings,

        "company_analysis": company_result,

        "url_analysis": url_result,

        "email_analysis": email_result,

        "advanced_email_analysis": (
            advanced_email_result
        ),

        "database_saved": saved
    })