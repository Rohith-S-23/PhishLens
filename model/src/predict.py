import joblib
import pandas as pd

from feature_extraction import extract_features, FEATURES


MODEL_PATH = "model/phishing_model.pkl"


# Load trained model
model = joblib.load(MODEL_PATH)


def predict_url(url):

    # Extract features
    feature_values = extract_features(url)

    # Create DataFrame with exact feature names
    input_data = pd.DataFrame(
        [feature_values],
        columns=FEATURES
    )

    # Prediction
    prediction = model.predict(input_data)[0]

    # Probability
    probabilities = model.predict_proba(input_data)[0]

    # Probability of phishing
    phishing_probability = probabilities[1]

    # Convert to risk score
    risk_score = round(phishing_probability * 100, 2)

    if prediction == 1:
        result = "SUSPICIOUS"
    else:
        result = "SAFE"

    return result, risk_score


# ==========================================
# USER INPUT
# ==========================================

if __name__ == "__main__":

    print("=" * 50)
    print("             PHISHLENS")
    print("      Suspicious Link Analyzer")
    print("=" * 50)

    url = input("\nEnter URL: ").strip()

    if not url:
        print("Please enter a URL.")
    else:

        result, risk_score = predict_url(url)

        print("\n" + "=" * 50)
        print("              ANALYSIS RESULT")
        print("=" * 50)

        print("\nURL:", url)

        print("\nResult:", result)

        print("Risk Score:", risk_score, "/ 100")

        print("=" * 50)