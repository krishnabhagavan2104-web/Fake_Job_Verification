def calculate_risk(findings):
    """
    Calculate overall risk from detected indicators.
    """

    if not findings:

        return {
            "score": 0,
            "level": "LOW",
            "recommendation": (
                "No major risk indicators were detected "
                "by this scan. This does not guarantee "
                "that the opportunity is genuine."
            )
        }

    total = 0

    for item in findings:

        weight = item.get(
            "weight",
            0
        )

        try:
            weight = int(weight)
        except (TypeError, ValueError):
            weight = 0

        if weight > 0:
            total += weight

    # Maximum score = 100
    score = min(
        total,
        100
    )

    # ---------------------------------------------------------
    # Risk level
    # ---------------------------------------------------------

    if score >= 61:

        level = "HIGH"

        recommendation = (
            "Proceed with extreme caution. "
            "Do not send money, OTPs, passwords, "
            "bank credentials, UPI PINs, CVV, "
            "or other sensitive information."
        )

    elif score >= 31:

        level = "MEDIUM"

        recommendation = (
            "Verify the employer independently "
            "before sharing personal information, "
            "paying money, or proceeding."
        )

    else:

        level = "LOW"

        recommendation = (
            "No major risk indicators were detected "
            "by this scan. This does not guarantee "
            "that the opportunity is genuine."
        )

    return {
        "score": score,
        "level": level,
        "recommendation": recommendation
    }