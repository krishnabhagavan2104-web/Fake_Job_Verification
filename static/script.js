const scanButton = document.getElementById("scanButton");
const loading = document.getElementById("loading");
const resultSection = document.getElementById("resultSection");

const jobText = document.getElementById("jobText");
const jobUrl = document.getElementById("jobUrl");
const recruiterEmail = document.getElementById("recruiterEmail");
const inputType = document.getElementById("inputType");

const riskScore = document.getElementById("riskScore");
const riskLevel = document.getElementById("riskLevel");
const recommendation = document.getElementById("recommendation");

const findingsContainer = document.getElementById("findings");

const companyAnalysis = document.getElementById("companyAnalysis");
const urlAnalysis = document.getElementById("urlAnalysis");
const emailAnalysis = document.getElementById("emailAnalysis");


scanButton.addEventListener("click", async () => {

    const payload = {
        input_type: inputType.value,
        text: jobText.value.trim(),
        url: jobUrl.value.trim(),
        email: recruiterEmail.value.trim()
    };


    if (!payload.text && !payload.url && !payload.email) {
        alert("Please provide job text, URL, or recruiter email.");
        return;
    }


    loading.classList.remove("hidden");
    resultSection.classList.add("hidden");

    scanButton.disabled = true;


    try {

        const response = await fetch("/api/scan", {
            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify(payload)
        });


        const data = await response.json();


        if (!response.ok || !data.success) {
            throw new Error(
                data.error || "Scan failed."
            );
        }


        displayResult(data);

    } catch (error) {

        alert(error.message);

    } finally {

        loading.classList.add("hidden");
        scanButton.disabled = false;
    }
});


function displayResult(data) {

    resultSection.classList.remove("hidden");

    const score = data.risk.score;
    const level = data.risk.level;


    riskScore.textContent = `${score}/100`;
    riskLevel.textContent = level;
    recommendation.textContent =
        data.risk.recommendation;


    findingsContainer.innerHTML = "";


    if (data.findings.length === 0) {

        findingsContainer.innerHTML =
            "<p>No specific risk indicators detected.</p>";

    } else {

        data.findings.forEach((finding) => {

            const element = document.createElement("div");

            element.className = "finding";

            const title = document.createElement("strong");

            title.textContent =
                `${finding.category}`;

            const description =
                document.createElement("span");

            description.textContent =
                `${finding.indicator} (+${finding.weight})`;

            element.appendChild(title);
            element.appendChild(description);

            findingsContainer.appendChild(element);
        });
    }


    const companies =
        data.company_analysis.companies_detected;

    companyAnalysis.textContent =
        companies.length
            ? companies.join(", ")
            : "No clear company name detected.";


    if (data.url_analysis.provided) {

        urlAnalysis.textContent =
            data.url_analysis.domain
                ? `Domain detected: ${data.url_analysis.domain}`
                : "URL could not be fully analyzed.";

    } else {

        urlAnalysis.textContent =
            "No URL provided.";
    }


    if (data.email_analysis.provided) {

        emailAnalysis.textContent =
            data.email_analysis.domain
                ? `Email domain: ${data.email_analysis.domain}`
                : "Invalid email format.";

    } else {

        emailAnalysis.textContent =
            "No email provided.";
    }
}