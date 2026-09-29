import re

from detector.company_verifier import verify_company


def extract_company_names(text):

    patterns = [

        # ABC Technologies is hiring
        r"(?m)^\s*([A-Z][A-Za-z0-9&.-]*(?:\s+[A-Z][A-Za-z0-9&.-]*){0,3})\s+is\s+(?:hiring|recruiting|looking)",

        # Company: ABC Technologies
        r"\bcompany\s*:\s*([A-Z][A-Za-z0-9&.-]*(?:\s+[A-Z][A-Za-z0-9&.-]*){0,3})",

        # at ABC Technologies
        r"\bat\s+([A-Z][A-Za-z0-9&.-]*(?:\s+[A-Z][A-Za-z0-9&.-]*){0,3})",

        # from ABC Technologies
        r"\bfrom\s+([A-Z][A-Za-z0-9&.-]*(?:\s+[A-Z][A-Za-z0-9&.-]*){0,3})",

        # ABC Technologies is looking for
        r"\b([A-Z][A-Za-z0-9&.-]*(?:\s+[A-Z][A-Za-z0-9&.-]*){0,3})\s+is\s+looking\s+for",

        # Join ABC Technologies
        r"\bjoin\s+([A-Z][A-Za-z0-9&.-]*(?:\s+[A-Z][A-Za-z0-9&.-]*){0,3})",

        # ABC Technologies Pvt Ltd / Limited / Ltd
        r"\b([A-Z][A-Za-z0-9&.-]*(?:\s+[A-Z][A-Za-z0-9&.-]*){0,3})\s+(?:Pvt\.?\s*Ltd\.?|Private Limited|Limited|Ltd\.?)\b"
    ]

    companies = set()

    for pattern in patterns:

        matches = re.findall(
            pattern,
            text
        )

        for match in matches:

            cleaned = match.strip(
                " .,;:-"
            )

            if 2 <= len(cleaned) <= 60:
                companies.add(cleaned)

    return list(companies)


def check_company(text):

    companies = extract_company_names(text)

    findings = []
    verification = []

    if not companies:

        findings.append({
            "category": "Company Verification",
            "indicator": "No clear company name detected",
            "weight": 5
        })

    else:

        for company in companies:

            result = verify_company(company)

            verification.append(result)

    return {
        "companies_detected": companies,
        "verification": verification,
        "findings": findings
    }