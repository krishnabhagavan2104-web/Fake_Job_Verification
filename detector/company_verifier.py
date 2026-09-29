import requests
from bs4 import BeautifulSoup
from urllib.parse import quote_plus, urlparse


def verify_company(company_name):
    """
    Performs a basic online search for the company name.

    This does NOT prove that a company is genuine.
    It only looks for online evidence.
    """

    company_name = company_name.strip()

    if not company_name:
        return {
            "company": "",
            "status": "UNKNOWN",
            "message": "No company name provided.",
            "evidence": []
        }

    search_url = (
        "https://html.duckduckgo.com/html/?q="
        + quote_plus(f'"{company_name}" company')
    )

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 "
            "(KHTML, like Gecko) "
            "Chrome/120.0 Safari/537.36"
        )
    }

    try:
        response = requests.get(
            search_url,
            headers=headers,
            timeout=10
        )

        response.raise_for_status()

        soup = BeautifulSoup(
            response.text,
            "html.parser"
        )

        results = soup.select(".result")

        evidence = []

        for result in results[:5]:

            title_element = result.select_one(
                ".result__title"
            )

            link_element = result.select_one(
                ".result__a"
            )

            snippet_element = result.select_one(
                ".result__snippet"
            )

            title = (
                title_element.get_text(
                    " ",
                    strip=True
                )
                if title_element
                else ""
            )

            link = (
                link_element.get("href", "")
                if link_element
                else ""
            )

            snippet = (
                snippet_element.get_text(
                    " ",
                    strip=True
                )
                if snippet_element
                else ""
            )

            if title or link:

                domain = ""

                try:
                    domain = urlparse(link).netloc
                except Exception:
                    domain = ""

                evidence.append({
                    "title": title,
                    "url": link,
                    "domain": domain,
                    "snippet": snippet
                })

        if evidence:

            return {
                "company": company_name,
                "status": "FOUND",
                "message": (
                    "Online references were found "
                    "for this company name."
                ),
                "evidence": evidence
            }

        return {
            "company": company_name,
            "status": "NOT_FOUND",
            "message": (
                "No clear online references were "
                "found for this company name."
            ),
            "evidence": []
        }

    except requests.RequestException:

        return {
            "company": company_name,
            "status": "UNKNOWN",
            "message": (
                "Online verification could not "
                "be completed."
            ),
            "evidence": []
        }

    except Exception:

        return {
            "company": company_name,
            "status": "UNKNOWN",
            "message": (
                "An unexpected error occurred "
                "during verification."
            ),
            "evidence": []
        }