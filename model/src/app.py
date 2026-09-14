from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import joblib
import pandas as pd
from urllib.parse import urlparse
from pathlib import Path

from model.src.feature_extraction import extract_features, FEATURES


# ============================================================
# APP
# ============================================================

app = FastAPI(
    title="PhishLens API",
    description="AI Powered Phishing URL Detection API",
    version="1.0.0"
)


# ============================================================
# CORS - ALLOWS REACT FRONTEND TO CONNECT
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent.parent

MODEL_PATH = BASE_DIR / "model" / "phishing_model.pkl"
DATASET_PATH = BASE_DIR / "dataset" / "PhiUSIIL_Phishing_URL_Dataset.csv"


# ============================================================
# LOAD MODEL
# ============================================================

print("Loading PhishLens model...")

model = joblib.load(MODEL_PATH)

print("Model loaded successfully!")


# ============================================================
# LOAD DATASET
# ============================================================

print("Loading dataset...")

try:

    dataset = pd.read_csv(DATASET_PATH)

    url_labels = dict(
        zip(
            dataset["URL"]
            .astype(str)
            .str.strip()
            .str.lower(),

            dataset["label"]
        )
    )

    print("Dataset loaded successfully!")
    print("Known URLs:", len(url_labels))

except Exception as e:

    print("Dataset loading error:", e)

    url_labels = {}


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
    "www.wikipedia.org"
}


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

        return domain

    except:

        return ""


# ============================================================
# HOME
# ============================================================

@app.get("/")
def home():

    return {
        "message": "PhishLens API",
        "status": "online",
        "model": "Random Forest",
        "features": len(FEATURES)
    }


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health():

    return {
        "status": "healthy",
        "api": "online",
        "model": "loaded"
    }


# ============================================================
# ANALYZE URL
# ============================================================

@app.post("/analyze")
def analyze(data: URLRequest):

    url = data.url.strip()

    if not url:

        return {
            "result": "ERROR",
            "message": "URL cannot be empty"
        }


    normalized_url = url.lower()

    domain = get_domain(url)


    # ========================================================
    # 1. EXACT DATASET CHECK
    # ========================================================

    if normalized_url in url_labels:

        dataset_label = int(url_labels[normalized_url])

        # IMPORTANT:
        # PhiUSIIL dataset:
        # 0 = phishing
        # 1 = legitimate

        if dataset_label == 0:

            return {

                "url": url,

                "result": "SUSPICIOUS",

                "risk_score": 95,

                "phishing_probability": 100,

                "legitimate_probability": 0,

                "reasons": [

                    "URL matches a known phishing record",

                    "URL was identified as phishing in the training dataset"

                ],

                "recommended_action":
                    "Do not open this link. Do not enter passwords, OTPs or personal information.",

                "source": "Dataset verification"

            }


        else:

            return {

                "url": url,

                "result": "SAFE",

                "risk_score": 5,

                "phishing_probability": 0,

                "legitimate_probability": 100,

                "reasons": [

                    "URL matches a legitimate record in the dataset",

                    "No known phishing classification for this URL"

                ],

                "recommended_action":
                    "URL appears legitimate. Always verify the domain before entering sensitive information.",

                "source": "Dataset verification"

            }


    # ========================================================
    # 2. TRUSTED DOMAIN CHECK
    # ========================================================

    if domain in TRUSTED_DOMAINS:

        return {

            "url": url,

            "result": "SAFE",

            "risk_score": 5,

            "phishing_probability": 0,

            "legitimate_probability": 100,

            "reasons": [

                "Domain matches a recognized trusted website",

                "Official domain pattern detected"

            ],

            "recommended_action":
                "URL appears safe. Always verify the domain before entering sensitive information.",

            "source": "Trusted domain verification"

        }


    # ========================================================
    # 3. FEATURE EXTRACTION
    # ========================================================

    try:

        features = extract_features(url)

        X = pd.DataFrame(
            [features],
            columns=FEATURES
        )

    except Exception as e:

        return {

            "result": "ERROR",

            "message": f"Feature extraction failed: {str(e)}"

        }


    # ========================================================
    # 4. MACHINE LEARNING PREDICTION
    # ========================================================

    prediction = model.predict(X)[0]

    probabilities = model.predict_proba(X)[0]


    # Dataset:
    # 0 = phishing
    # 1 = legitimate

    phishing_probability = float(probabilities[0])

    legitimate_probability = float(probabilities[1])


    ml_risk = phishing_probability * 100


    # ========================================================
    # 5. XAI SECURITY RULES
    # ========================================================

    reasons = []

    rule_risk = 0


    # HTTPS

    if not url.startswith("https://"):

        rule_risk += 15

        reasons.append(
            "Connection is not using HTTPS"
        )


    # @ symbol

    if "@" in url:

        rule_risk += 20

        reasons.append(
            "URL contains @ symbol which can hide the actual destination"
        )


    # Long URL

    if len(url) > 75:

        rule_risk += 15

        reasons.append(
            "Unusually long URL detected"
        )


    # Many dots

    if url.count(".") > 3:

        rule_risk += 15

        reasons.append(
            "Multiple subdomains detected"
        )


    # Digits

    digit_count = sum(
        c.isdigit()
        for c in url
    )


    if digit_count > 4:

        rule_risk += 10

        reasons.append(
            "High number of digits in URL"
        )


    # Suspicious keywords

    suspicious_words = [

        "login",
        "verify",
        "verification",
        "account",
        "password",
        "signin",
        "confirm",
        "secure",
        "update",
        "bank",
        "payment",
        "wallet",
        "credential"

    ]


    found_words = [

        word
        for word in suspicious_words
        if word in normalized_url

    ]


    if found_words:

        rule_risk += min(
            len(found_words) * 10,
            30
        )

        reasons.append(

            "Suspicious keyword(s): "
            + ", ".join(found_words)

        )


    # ========================================================
    # 6. FINAL RISK SCORE
    # ========================================================

    risk_score = (

        (ml_risk * 0.6)
        +
        (rule_risk * 0.4)

    )


    risk_score = round(

        min(
            max(risk_score, 0),
            100
        ),

        2

    )


    # ========================================================
    # 7. FINAL RESULT
    # ========================================================

    if risk_score >= 60:

        result = "SUSPICIOUS"

        action = (

            "Do not open this link. "
            "Avoid entering passwords, OTPs, "
            "banking or personal information."

        )


        if not reasons:

            reasons.append(

                "Machine learning model detected "
                "phishing-like URL characteristics"

            )


    else:

        result = "SAFE"

        action = (

            "URL appears low risk. "
            "Verify the domain before entering "
            "sensitive information."

        )


        if not reasons:

            reasons.append(

                "No major suspicious URL characteristics detected"

            )


    # ========================================================
    # 8. RESPONSE
    # ========================================================

    return {

        "url": url,

        "result": result,

        "risk_score": risk_score,

        "phishing_probability":
            round(
                phishing_probability * 100,
                2
            ),

        "legitimate_probability":
            round(
                legitimate_probability * 100,
                2
            ),

        "reasons": reasons,

        "recommended_action": action,

        "source": "ML + XAI Security Analysis"

    }