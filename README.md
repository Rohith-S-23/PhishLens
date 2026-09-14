## 🛡️ PhishLens – AI-Powered Phishing URL Detection

PhishLens is an AI-powered web security system that analyzes URLs and detects potentially phishing or suspicious links.

The system combines **Machine Learning, URL Feature Extraction, Rule-Based Security Analysis, Risk Scoring, and Explainable AI (XAI)** to help users understand whether a URL is safe or suspicious.

## 🚨 Problem Statement

Malicious URLs can closely resemble legitimate websites, making it difficult for users to identify phishing attacks.

Attackers may use:

- Look-alike domains
- Suspicious keywords
- Long URLs
- Multiple subdomains
- Excessive special characters
- IP-based domains
- Obfuscated URLs
- Fake login and verification pages

PhishLens provides an intelligent way to analyze a URL before the user visits it.

## 💡 Proposed Solution

PhishLens allows a user to paste a URL into a web dashboard.

The system then:

1. Extracts important URL features
2. Analyzes the URL using a Machine Learning model
3. Applies additional security rules
4. Generates a risk score from **0–100**
5. Classifies the URL as **SAFE** or **SUSPICIOUS**
6. Provides explainable reasons for suspicious URLs
7. Gives a recommended security action

## 🔄 System Workflow

```text
👤 USER
   │
   ▼
🔗 ENTER URL
   │
   ▼
┌──────────────────────┐
│    URL ANALYZER      │
└──────────────────────┘
   │
   ▼
┌──────────────────────┐
│ FEATURE EXTRACTION   │
│                      │
│ • URL Structure      │
│ • Domain Features    │
│ • URL Patterns       │
│ • Character Features │
└──────────────────────┘
   │
   ▼
┌──────────────────────┐
│   ML + SECURITY      │
│       RULES          │
└──────────────────────┘
   │
   ▼
┌──────────────────────┐
│    RISK ENGINE       │
└──────────────────────┘
   │
   ▼
┌──────────────────────┐
│   RISK SCORE 0–100   │
└──────────────────────┘
   │
   ├───────────────┐
   ▼               ▼
🟢 SAFE       🔴 SUSPICIOUS
                   │
                   ▼
            🧠 XAI EXPLANATION
                   │
                   ▼
            🛡️ RECOMMENDED ACTION
