import re


PAYMENT_PATTERNS = {
    "registration fee": 25,
    "registration fees": 25,
    "processing fee": 25,
    "processing fees": 25,
    "security deposit": 30,
    "training fee": 25,
    "training fees": 25,
    "pay upfront": 30,
    "pay first": 30,
    "send money": 25,
    "payment required": 25,
    "pay to apply": 30,
}

URGENCY_PATTERNS = {
    "act now": 10,
    "urgent": 10,
    "immediately": 10,
    "limited seats": 8,
    "limited time": 8,
    "today only": 10,
    "last chance": 10,
    "respond now": 10,
}

CONTACT_PATTERNS = {
    "whatsapp": 8,
    "telegram": 8,
    "personal number": 8,
}

DATA_PATTERNS = {
    "otp": 25,
    "one time password": 25,
    "bank account": 20,
    "bank details": 20,
    "credit card": 25,
    "debit card": 25,
    "cvv": 30,
    "password": 30,
    "upi pin": 30,
}

PROMISE_PATTERNS = {
    "guaranteed job": 20,
    "guaranteed placement": 20,
    "100% job guarantee": 25,
    "no interview": 15,
    "work from home": 5,
}

SALARY_PATTERNS = {
    "earn ₹1 lakh": 15,
    "earn 1 lakh": 15,
    "earn ₹2 lakh": 20,
    "earn 2 lakh": 20,
    "daily income": 10,
    "easy money": 10,
}


def normalize_text(text):
    return re.sub(r"\s+", " ", text.strip().lower())


def find_patterns(text, patterns, category):
    findings = []

    for phrase, weight in patterns.items():
        if phrase in text:
            findings.append({
                "category": category,
                "indicator": phrase,
                "weight": weight
            })

    return findings


def analyze_text(text):
    text = normalize_text(text)

    findings = []

    findings.extend(
        find_patterns(
            text,
            PAYMENT_PATTERNS,
            "Payment Request"
        )
    )

    findings.extend(
        find_patterns(
            text,
            URGENCY_PATTERNS,
            "Urgency"
        )
    )

    findings.extend(
        find_patterns(
            text,
            CONTACT_PATTERNS,
            "Contact Pattern"
        )
    )

    findings.extend(
        find_patterns(
            text,
            DATA_PATTERNS,
            "Sensitive Information"
        )
    )

    findings.extend(
        find_patterns(
            text,
            PROMISE_PATTERNS,
            "Suspicious Promise"
        )
    )

    findings.extend(
        find_patterns(
            text,
            SALARY_PATTERNS,
            "Salary Pattern"
        )
    )

    # Detect phone numbers
    phone_numbers = re.findall(r"\b\d{10}\b", text)

    if phone_numbers:
        findings.append({
            "category": "Contact Information",
            "indicator": "Phone number detected",
            "weight": 3
        })

    # Detect email addresses
    emails = re.findall(
        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        text
    )

    if emails:
        findings.append({
            "category": "Email",
            "indicator": "Email address detected",
            "weight": 2
        })

    return {
        "findings": findings,
        "normalized_text": text
    }