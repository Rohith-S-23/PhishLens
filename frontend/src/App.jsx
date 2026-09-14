import { useState } from "react";
import "./App.css";

function App() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const analyzeURL = async () => {
    if (!url.trim()) {
      setError("Please enter a URL");
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);

    try {
      const response = await fetch("http://127.0.0.1:8000/analyze", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          url: url.trim(),
        }),
      });

      if (!response.ok) {
        throw new Error("API request failed");
      }

      const data = await response.json();

      setResult(data);
    } catch (err) {
      console.error(err);
      setError(
        "Unable to connect to PhishLens API. Make sure FastAPI is running on port 8000."
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="app">

      <h1>
        Detect <span>Phishing</span>
        <br />
        Before You Click
      </h1>

      <p className="subtitle">
        Analyze suspicious links using machine learning,
        URL intelligence and explainable AI.
      </p>

      <div className="search-box">

        <input
          type="text"
          placeholder="Enter URL to analyze..."
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              analyzeURL();
            }
          }}
        />

        <button onClick={analyzeURL} disabled={loading}>
          {loading ? "Analyzing..." : "Analyze URL →"}
        </button>

      </div>

      {error && (
        <div className="error">
          ⚠️ {error}
        </div>
      )}

      {result && (
        <div className="result-card">

          <h2>
            {result.result === "SAFE" ? "🟢 SAFE" : "🔴 SUSPICIOUS"}
          </h2>

          <div className="risk">
            Risk Score
            <strong>{result.risk_score}/100</strong>
          </div>

          <p>
            <b>URL:</b> {result.url}
          </p>

          <hr />

          <h3>🧠 Why?</h3>

          <ul>
            {result.reasons?.map((reason, index) => (
              <li key={index}>{reason}</li>
            ))}
          </ul>

          <h3>🛡 Recommended Action</h3>

          <p>{result.recommended_action}</p>

          <div className="probabilities">

            <div>
              <b>Phishing Probability</b>
              <span>{result.phishing_probability}%</span>
            </div>

            <div>
              <b>Legitimate Probability</b>
              <span>{result.legitimate_probability}%</span>
            </div>

          </div>

        </div>
      )}

    </div>
  );
}

export default App;