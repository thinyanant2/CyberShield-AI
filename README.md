# CyberShield-AI
# ⚡ CyberShield-AI: Intelligent Phishing Detection

CyberShield-AI is a machine learning-based security tool designed to detect phishing URLs in real-time. It uses the **XGBoost** algorithm to analyze URL structures and identify malicious patterns with high precision.

## 🚀 Features
- **Real-time Analysis:** Inspects URLs for suspicious features instantly.
- **High Accuracy:** Achieved **98.64%** accuracy during training/testing.
- **Cyberpunk UI:** Built with Streamlit for a futuristic, security-focused user experience.
- **Hybrid Detection:** Combines ML models with heuristic rules (e.g., '@' symbol detection).

## 📊 Model Performance
The model was evaluated using a Confusion Matrix, showing excellent performance in both Phishing and Legitimate classifications.

| Metric | Value |
| :--- | :--- |
| **Accuracy** | 98.64% |
| **Algorithm** | XGBoost Classifier |
Precision (Phishing) = 0.98
F1-score = 0.97

## 🛠️ Tech Stack
- **Python** (Core Logic)
- **Scikit-learn & XGBoost** (Machine Learning)
- **Streamlit** (Web Dashboard)
- **Joblib** (Model Serialization)
