from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import joblib
import pandas as pd
import socket
import re
from pathlib import Path
from urllib.parse import urlparse

from .feature_extraction import extract_features, FEATURES


# ============================================================
# PATH CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parents[2]
MODEL_DIR = BASE_DIR / "model"
DATASET_PATH = BASE_DIR / "dataset" / "PhiUSIIL_Phishing_URL_Dataset.csv"
MODEL_PATH = MODEL_DIR / "phishing_model.pkl"


# ============================================================
# FASTAPI
# ============================================================

app = FastAPI(
    title="PhishLens API",
    description="AI-powered phishing URL detection and explainable risk analysis",
    version="1.0.0"
)


# ============================================================
# CORS - CONNECT REACT FRONTEND
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# LOAD ML MODEL
# ============================================================

print("Loading PhishLens model...")

try:
    model = joblib.load(MODEL_PATH)
    print("Model loaded successfully!")
except Exception as e:
    print("Model loading failed:", e)
    model = None


# ============================================================
# LOAD DATASET
# ============================================================

print("Loading dataset...")

url_labels = {}

try:

    dataset = pd.read_csv(DATASET_PATH)

    dataset["URL"] = (
        dataset["URL"]
        .astype(str)
        .str.strip()
        .str.lower()
    )

    url_labels = dict(
        zip(
            dataset["URL"],
            dataset["label"]
        )
    )

    print("Dataset loaded successfully!")
    print("Known URLs:", len(url_labels))

except Exception as e:

    print("Dataset loading failed:", e)


# ============================================================
# REQUEST MODEL
# ============================================================

class URLRequest(BaseModel):
    url: str


# ============================================================
# TRUSTED DOMAINS
# ============================================================

TRUSTED_DOMAINS = {

    "google.com",
    "www.google.com",

    "microsoft.com",
    "www.microsoft.com",

    "apple.com",
    "www.apple.com",

    "amazon.com",
    "www.amazon.com",

    "github.com",
    "www.github.com",

    "linkedin.com",
    "www.linkedin.com",

    "youtube.com",
    "www.youtube.com",

    "wikipedia.org",
    "www.wikipedia.org",

    "openai.com",
    "www.openai.com",

    "stackoverflow.com",
    "www.stackoverflow.com",

    "oracle.com",
    "www.oracle.com",

    "ibm.com",
    "www.ibm.com"
}


# ============================================================
# SUSPICIOUS KEYWORDS
# ============================================================

SUSPICIOUS_KEYWORDS = [

    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "account",
    "password",
    "passwd",
    "confirm",
    "confirmation",
    "secure",
    "security",
    "update",
    "authenticate",
    "auth",
    "wallet",
    "banking",
    "payment",
    "billing",
    "recover",
    "reset",
    "unlock",
    "suspended",
    "claim",
    "urgent"
]


# ============================================================
# DOMAIN EXTRACTION
# ============================================================

def get_domain(url):

    try:

        parsed = urlparse(url)

        domain = parsed.netloc.lower()

        if "@" in domain:
            domain = domain.split("@")[-1]

        if ":" in domain:
            domain = domain.split(":")[0]

        return domain.strip()

    except Exception:

        return ""


# ============================================================
# NORMALIZE URL
# ============================================================

def normalize_url(url):

    url = url.strip()

    if not url:
        return ""

    if not re.match(r"^https?://", url, re.IGNORECASE):

        url = "https://" + url

    return url


# ============================================================
# VALID URL FORMAT
# ============================================================

def is_valid_url(url):

    try:

        parsed = urlparse(url)

        return (
            parsed.scheme in ["http", "https"]
            and bool(parsed.netloc)
        )

    except Exception:

        return False


# ============================================================
# CHECK DOMAIN EXISTENCE
# ============================================================

def domain_exists(domain):

    if not domain:
        return False

    try:

        socket.gethostbyname_ex(domain)

        return True

    except socket.gaierror:

        return False

    except Exception:

        return False


# ============================================================
# DOMAIN AGE / REPUTATION PLACEHOLDER
# ============================================================

def get_domain_reputation(domain):

    if domain in TRUSTED_DOMAINS:

        return {
            "trusted": True,
            "reason": "Domain belongs to a recognized trusted website"
        }

    return {
        "trusted": False,
        "reason": ""
    }


# ============================================================
# SECURITY RULE ENGINE
# ============================================================

def security_rules(url, domain):

    reasons = []

    rule_risk = 0

    normalized = url.lower()


    # --------------------------------------------------------
    # HTTP
    # --------------------------------------------------------

    if not normalized.startswith("https://"):

        rule_risk += 15

        reasons.append(
            "Connection is not using HTTPS"
        )


    # --------------------------------------------------------
    # @ SYMBOL
    # --------------------------------------------------------

    if "@" in url:

        rule_risk += 20

        reasons.append(
            "URL contains @ symbol which can hide the real destination"
        )


    # --------------------------------------------------------
    # VERY LONG URL
    # --------------------------------------------------------

    if len(url) > 75:

        rule_risk += 15

        reasons.append(
            "Unusually long URL detected"
        )


    # --------------------------------------------------------
    # MANY SUBDOMAINS
    # --------------------------------------------------------

    if domain.count(".") >= 3:

        rule_risk += 15

        reasons.append(
            "Multiple subdomains detected"
        )


    # --------------------------------------------------------
    # IP ADDRESS
    # --------------------------------------------------------

    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    if re.match(ip_pattern, domain):

        rule_risk += 25

        reasons.append(
            "URL uses an IP address instead of a normal domain"
        )


    # --------------------------------------------------------
    # DIGITS
    # --------------------------------------------------------

    digit_count = sum(
        character.isdigit()
        for character in url
    )

    if digit_count >= 5:

        rule_risk += 10

        reasons.append(
            "High number of digits detected in URL"
        )


    # --------------------------------------------------------
    # SUSPICIOUS KEYWORDS
    # --------------------------------------------------------

    found_words = [

        word
        for word in SUSPICIOUS_KEYWORDS
        if word in normalized

    ]

    if found_words:

        keyword_risk = min(
            len(found_words) * 8,
            30
        )

        rule_risk += keyword_risk

        reasons.append(
            "Suspicious keyword(s): "
            + ", ".join(found_words)
        )


    # --------------------------------------------------------
    # HYPHENATED DOMAIN
    # --------------------------------------------------------

    domain_name = domain.split(".")[0]

    if "-" in domain_name:

        rule_risk += 10

        reasons.append(
            "Hyphenated domain pattern detected"
        )


    # --------------------------------------------------------
    # RANDOM LOOKING DOMAIN
    # --------------------------------------------------------

    if len(domain_name) >= 12:

        vowel_count = sum(
            char in "aeiou"
            for char in domain_name.lower()
        )

        if vowel_count <= 2:

            rule_risk += 10

            reasons.append(
                "Domain contains an unusual random-looking character pattern"
            )


    # --------------------------------------------------------
    # SPECIAL CHARACTERS
    # --------------------------------------------------------

    special_count = sum(

        not char.isalnum()
        and char not in "/:.-_"

        for char in url

    )

    if special_count >= 3:

        rule_risk += 10

        reasons.append(
            "High number of unusual special characters detected"
        )


    return min(rule_risk, 100), reasons


# ============================================================
# RISK LEVEL
# ============================================================

def get_risk_level(score):

    if score < 30:

        return "LOW"

    elif score < 60:

        return "MEDIUM"

    elif score < 80:

        return "HIGH"

    else:

        return "CRITICAL"


# ============================================================
# HOME
# ============================================================

@app.get("/")
def home():

    return {

        "message": "PhishLens API",

        "status": "online",

        "version": "1.0.0",

        "features": [

            "URL validation",

            "Domain existence check",

            "Dataset verification",

            "Machine Learning",

            "Security rule engine",

            "Explainable AI",

            "Risk scoring"

        ]

    }


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health():

    return {

        "status": "healthy",

        "model_loaded": model is not None,

        "known_urls": len(url_labels)

    }


# ============================================================
# MAIN ANALYZER
# ============================================================

@app.post("/analyze")
def analyze(data: URLRequest):

    # ========================================================
    # 1. INPUT
    # ========================================================

    original_url = data.url.strip()

    if not original_url:

        return {

            "result": "INVALID",

            "risk_score": 0,

            "phishing_probability": 0,

            "legitimate_probability": 0,

            "reasons": [
                "URL input is empty"
            ],

            "recommended_action":
                "Enter a valid URL and try again."

        }


    # ========================================================
    # 2. NORMALIZE
    # ========================================================

    url = normalize_url(original_url)

    normalized_url = url.lower().strip()


    # ========================================================
    # 3. URL FORMAT VALIDATION
    # ========================================================

    if not is_valid_url(url):

        return {

            "url": original_url,

            "result": "INVALID",

            "risk_score": 0,

            "phishing_probability": 0,

            "legitimate_probability": 0,

            "reasons": [

                "Invalid URL format"

            ],

            "recommended_action":
                "Enter a valid URL such as https://example.com"

        }


    # ========================================================
    # 4. DOMAIN
    # ========================================================

    domain = get_domain(url)


    if not domain:

        return {

            "url": original_url,

            "result": "INVALID",

            "risk_score": 0,

            "phishing_probability": 0,

            "legitimate_probability": 0,

            "reasons": [

                "Unable to extract domain from URL"

            ],

            "recommended_action":
                "Check the URL and try again."

        }


    # ========================================================
    # 5. DOMAIN EXISTENCE CHECK
    # ========================================================

    exists = domain_exists(domain)


    # IMPORTANT:
    # If domain does NOT exist, don't call it SAFE
    # and don't call it SUSPICIOUS.
    #
    # Return NOT_FOUND.

    if not exists:

        return {

            "url": original_url,

            "domain": domain,

            "result": "NOT_FOUND",

            "risk_score": None,

            "phishing_probability": None,

            "legitimate_probability": None,

            "reasons": [

                "Domain does not appear to exist",

                "DNS resolution failed",

                "No active domain was found for this URL"

            ],

            "recommended_action":
                "Check the URL spelling. Do not enter sensitive information into unknown links."

        }


    # ========================================================
    # 6. EXACT DATASET CHECK
    # ========================================================

    if normalized_url in url_labels:

        dataset_label = int(
            url_labels[normalized_url]
        )


        # PhiUSIIL dataset:
        # Based on your trained model:
        # 0 = Legitimate
        # 1 = Phishing

        if dataset_label == 1:

            return {

                "url": original_url,

                "domain": domain,

                "result": "SUSPICIOUS",

                "risk_score": 95,

                "risk_level": "CRITICAL",

                "phishing_probability": 100,

                "legitimate_probability": 0,

                "source": "Known phishing dataset",

                "reasons": [

                    "URL matches a known phishing record in the dataset"

                ],

                "recommended_action":
                    "Do not open the link or enter passwords, OTPs or personal information."

            }


        else:

            return {

                "url": original_url,

                "domain": domain,

                "result": "SAFE",

                "risk_score": 5,

                "risk_level": "LOW",

                "phishing_probability": 0,

                "legitimate_probability": 100,

                "source": "Verified legitimate dataset",

                "reasons": [

                    "URL matches a known legitimate record in the dataset"

                ],

                "recommended_action":
                    "URL appears legitimate. Still verify the domain before entering sensitive information."

            }


    # ========================================================
    # 7. TRUSTED DOMAIN CHECK
    # ========================================================

    reputation = get_domain_reputation(domain)


    if reputation["trusted"]:

        return {

            "url": original_url,

            "domain": domain,

            "result": "SAFE",

            "risk_score": 5,

            "risk_level": "LOW",

            "phishing_probability": 0,

            "legitimate_probability": 100,

            "source": "Trusted domain",

            "reasons": [

                "Domain matches a recognized trusted website",

                "Domain is currently reachable"

            ],

            "recommended_action":
                "URL appears safe. Always verify the domain before entering sensitive information."

        }


    # ========================================================
    # 8. FEATURE EXTRACTION
    # ========================================================

    if model is None:

        return {

            "url": original_url,

            "domain": domain,

            "result": "ERROR",

            "risk_score": None,

            "reasons": [

                "Machine learning model is not loaded"

            ],

            "recommended_action":
                "Start the backend again after checking the model file."

        }


    try:

        features = extract_features(url)

        X = pd.DataFrame(
            [features],
            columns=FEATURES
        )

    except Exception as e:

        return {

            "url": original_url,

            "domain": domain,

            "result": "ERROR",

            "risk_score": None,

            "reasons": [

                "Feature extraction failed",

                str(e)

            ],

            "recommended_action":
                "Check the feature extraction module."

        }


    # ========================================================
    # 9. MACHINE LEARNING PREDICTION
    # ========================================================

    try:

        prediction = model.predict(X)[0]

        probabilities = model.predict_proba(X)[0]

    except Exception as e:

        return {

            "url": original_url,

            "domain": domain,

            "result": "ERROR",

            "risk_score": None,

            "reasons": [

                "Machine learning prediction failed",

                str(e)

            ],

            "recommended_action":
                "Check the trained model and feature configuration."

        }


    # Your model:
    # 0 = Legitimate
    # 1 = Phishing

    phishing_probability = float(
        probabilities[1]
    )

    legitimate_probability = float(
        probabilities[0]
    )


    ml_risk = phishing_probability * 100


    # ========================================================
    # 10. SECURITY RULES
    # ========================================================

    rule_risk, reasons = security_rules(
        url,
        domain
    )


    # ========================================================
    # 11. FINAL RISK SCORE
    # ========================================================

    risk_score = (

        (ml_risk * 0.65)

        +

        (rule_risk * 0.35)

    )


    risk_score = round(

        min(
            max(
                risk_score,
                0
            ),
            100
        ),

        2

    )


    # ========================================================
    # 12. CLASSIFICATION
    # ========================================================

    if risk_score >= 60:

        result = "SUSPICIOUS"

        action = (

            "Do not open the link or enter passwords, "
            "OTPs, banking details or personal information."

        )

    else:

        result = "SAFE"

        action = (

            "URL appears low risk. "
            "Verify the domain before entering sensitive information."

        )


    # ========================================================
    # 13. XAI FALLBACK
    # ========================================================

    if not reasons:

        if prediction == 1:

            reasons.append(

                "Machine learning model detected "
                "phishing-like URL characteristics"

            )

        else:

            reasons.append(

                "No major suspicious URL characteristics detected"

            )


    # ========================================================
    # 14. RESPONSE
    # ========================================================

    return {

        "url": original_url,

        "domain": domain,

        "result": result,

        "risk_score": risk_score,

        "risk_level": get_risk_level(
            risk_score
        ),

        "phishing_probability": round(

            phishing_probability * 100,
            2

        ),

        "legitimate_probability": round(

            legitimate_probability * 100,
            2

        ),

        "source": "Machine Learning + Security Rules",

        "threat_indicators": len(reasons),

        "reasons": reasons,

        "recommended_action": action

    }