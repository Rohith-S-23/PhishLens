import os
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix


# ==========================================
# 1. FIND DATASET
# ==========================================

dataset_folder = "dataset"

csv_files = [
    file for file in os.listdir(dataset_folder)
    if file.endswith(".csv")
]

if not csv_files:
    raise FileNotFoundError("No CSV file found inside dataset folder.")

dataset_path = os.path.join(dataset_folder, csv_files[0])

print("Dataset:", dataset_path)


# ==========================================
# 2. LOAD DATASET
# ==========================================

df = pd.read_csv(dataset_path)

print("\nDataset Shape:", df.shape)


# ==========================================
# 3. SELECT FEATURES
# ==========================================

features = [
    "URLLength",
    "DomainLength",
    "IsDomainIP",
    "URLSimilarityIndex",
    "CharContinuationRate",
    "TLDLegitimateProb",
    "URLCharProb",
    "TLDLength",
    "NoOfSubDomain",
    "HasObfuscation",
    "NoOfObfuscatedChar",
    "ObfuscationRatio",
    "NoOfLettersInURL",
    "LetterRatioInURL",
    "NoOfDegitsInURL",
    "DegitRatioInURL",
    "NoOfEqualsInURL",
    "NoOfQMarkInURL",
    "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL",
    "SpacialCharRatioInURL",
    "IsHTTPS"
]

target = "label"


# ==========================================
# 4. CHECK REQUIRED COLUMNS
# ==========================================

missing_columns = [
    column for column in features + [target]
    if column not in df.columns
]

if missing_columns:
    print("\nMissing columns:")
    print(missing_columns)
    raise ValueError("Required columns are missing from dataset.")


print("\nNumber of Features:", len(features))

print("\nSelected Features:")
for feature in features:
    print("-", feature)


# ==========================================
# 5. CREATE X AND Y
# ==========================================

X = df[features]
y = df[target]

print("\nX Shape:", X.shape)
print("y Shape:", y.shape)


# ==========================================
# 6. CHECK MISSING VALUES
# ==========================================

print("\nMissing Values:")

print(X.isnull().sum())


# ==========================================
# 7. HANDLE MISSING VALUES
# ==========================================

X = X.fillna(0)


# ==========================================
# 8. TRAIN TEST SPLIT
# ==========================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("\nTraining samples:", len(X_train))
print("Testing samples:", len(X_test))


# ==========================================
# 9. TRAINING LABEL DISTRIBUTION
# ==========================================

print("\nTraining label distribution:")
print(y_train.value_counts())


print("\nTesting label distribution:")
print(y_test.value_counts())


# ==========================================
# 10. RANDOM FOREST MODEL
# ==========================================

print("\nTraining Random Forest model...")

model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced"
)

model.fit(X_train, y_train)

print("Model training completed!")


# ==========================================
# 11. MODEL EVALUATION
# ==========================================

print("\nEvaluating model...")

y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)

print("\nAccuracy:", accuracy)

print("\nClassification Report:")

print(
    classification_report(
        y_test,
        y_pred,
        target_names=["Legitimate", "Phishing"]
    )
)

print("\nConfusion Matrix:")

print(confusion_matrix(y_test, y_pred))


# ==========================================
# 12. FEATURE IMPORTANCE
# ==========================================

importance = pd.DataFrame({
    "Feature": features,
    "Importance": model.feature_importances_
})

importance = importance.sort_values(
    by="Importance",
    ascending=False
)

print("\nTop 10 Important Features:")

print(
    importance.head(10).to_string(index=False)
)


# ==========================================
# 13. SAVE MODEL
# ==========================================

model_folder = "model"

os.makedirs(model_folder, exist_ok=True)

model_path = os.path.join(
    model_folder,
    "phishing_model.pkl"
)

joblib.dump(model, model_path)

print("\nModel saved successfully!")
print("Model path:", model_path)