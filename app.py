import csv
import os
import random
from datetime import datetime

from flask import Flask, render_template, request
import joblib

from feature_extractor import extract_features

app = Flask(__name__)

# Load ML Model
model = joblib.load("model.pkl")
vectorizer = joblib.load("vectorizer.pkl")


# ---------------- HOME ----------------

@app.route("/")
def home():
    return render_template("home.html")


# ---------------- SCAN PAGE ----------------

@app.route("/scan")
def scan():
    return render_template("scan.html")


# ---------------- PREDICT ----------------

@app.route("/predict", methods=["POST"])
def predict():

    url = request.form["url"].strip()

    # Validate URL
    if not (url.startswith("http://") or url.startswith("https://")):

        return render_template(
            "scan.html",
            prediction="❌ Invalid URL",
            confidence=0,
            reasons=[
                "Please enter a complete URL.",
                "Example: https://google.com"
            ],
            result_class="suspicious",
            risk_level="Unknown",
            risk_color="gray",
            cyber_tip="💡 Always enter the full website address."
        )

    # ---------------- ML Prediction ----------------

    url_vector = vectorizer.transform([url])

    ml_prediction = model.predict(url_vector)[0]

    confidence = round(
        max(model.predict_proba(url_vector)[0]) * 100,
        2
    )

    # ---------------- Feature Extraction ----------------

    features = extract_features(url)

    reasons = []

    if features["https"] == 0:
        reasons.append("❌ Website is not using HTTPS.")

    else:
        reasons.append("✅ HTTPS detected.")

    if features["has_at"] == 1:
        reasons.append("⚠️ URL contains '@' symbol.")

    else:
        reasons.append("✅ No '@' symbol found.")

    if features["has_hyphen"] == 1:
        reasons.append("⚠️ URL contains '-' which may be suspicious.")

    if features["length"] > 75:
        reasons.append("⚠️ URL is unusually long.")

    else:
        reasons.append("✅ URL length is normal.")

    if features["dots"] > 3:
        reasons.append("⚠️ Too many subdomains detected.")

    if features["ip"] == 1:
        reasons.append("❌ URL uses an IP address.")

    else:
        reasons.append("✅ Domain name detected.")

    if features["suspicious_words"] > 0:
        reasons.append("⚠️ Suspicious keywords detected.")

    else:
        reasons.append("✅ No suspicious keywords found.")

    # ---------------- Risk Score ----------------

    risk_score = 0

    if features["https"] == 0:
        risk_score += 1

    if features["has_at"]:
        risk_score += 2

    if features["has_hyphen"]:
        risk_score += 1

    if features["length"] > 75:
        risk_score += 1

    if features["dots"] > 3:
        risk_score += 1

    if features["ip"]:
        risk_score += 3

    risk_score += features["suspicious_words"]

    # ---------------- Friendly Prediction ----------------

    if ml_prediction == "benign":
        prediction = "🟢 Safe Website"
        result_class = "safe"

    elif ml_prediction == "phishing":
        prediction = "🔴 Phishing Website"
        result_class = "phishing"

    elif ml_prediction == "malware":
        prediction = "🟣 Malware Website"
        result_class = "malware"

    elif ml_prediction == "defacement":
        prediction = "🟠 Defacement Website"
        result_class = "defacement"

    else:
        prediction = "🟡 Suspicious Website"
        result_class = "suspicious"

    # ---------------- Risk Level ----------------

    if risk_score <= 1:
        risk_level = "🟢 LOW"

    elif risk_score <= 3:
        risk_level = "🟡 MEDIUM"

    else:
        risk_level = "🔴 HIGH"

    # ---------------- Cyber Tips ----------------

    tips = [

        "💡 Always verify the website URL before entering passwords.",

        "💡 Never click suspicious email links.",

        "💡 Enable Two-Factor Authentication whenever possible.",

        "💡 Check HTTPS before logging into any website.",

        "💡 Keep your browser updated for better security."

    ]

    cyber_tip = random.choice(tips)

    # ---------------- Save History ----------------

    history_file = "history.csv"

    if not os.path.exists(history_file):

        with open(history_file, "w", newline="", encoding="utf-8") as file:

            writer = csv.writer(file)

            writer.writerow([
                "Date",
                "URL",
                "Result",
                "Confidence"
            ])

    with open(history_file, "a", newline="", encoding="utf-8") as file:

        writer = csv.writer(file)

        writer.writerow([

            datetime.now().strftime("%d-%m-%Y %H:%M:%S"),

            url,

            prediction,

            confidence

        ])

    return render_template(

        "scan.html",

        prediction=prediction,

        confidence=confidence,

        reasons=reasons,

        result_class=result_class,

        risk_level=risk_level,

        cyber_tip=cyber_tip
    )

# ---------------- DASHBOARD ----------------

@app.route("/dashboard")
def dashboard():

    total = 0
    safe = 0
    phishing = 0
    malware = 0
    defacement = 0
    suspicious = 0

    recent = []

    if os.path.exists("history.csv"):

        with open("history.csv", newline="", encoding="utf-8") as file:

            reader = csv.DictReader(file)

            for row in reader:

                total += 1

                result = row["Result"]

                if "Safe" in result:
                    safe += 1

                elif "Phishing" in result:
                    phishing += 1

                elif "Malware" in result:
                    malware += 1

                elif "Defacement" in result:
                    defacement += 1

                else:
                    suspicious += 1

                recent.append(row)

    recent = recent[-5:]

    return render_template(
        "dashboard.html",
        total=total,
        safe=safe,
        phishing=phishing,
        malware=malware,
        defacement=defacement,
        suspicious=suspicious,
        recent=recent
    )


# ---------------- HISTORY ----------------

@app.route("/history")
def history():

    history = []

    if os.path.exists("history.csv"):

        with open("history.csv", newline="", encoding="utf-8") as file:

            reader = csv.DictReader(file)
            history = list(reader)

    history.reverse()

    return render_template(
        "history.html",
        history=history
    )


# ---------------- CLEAR HISTORY ----------------

@app.route("/clear_history")
def clear_history():

    with open("history.csv", "w", newline="", encoding="utf-8") as file:

        writer = csv.writer(file)

        writer.writerow([
            "Date",
            "URL",
            "Result",
            "Confidence"
        ])

    return dashboard()


# ---------------- ABOUT ----------------

@app.route("/about")
def about():
    return render_template("about.html")


# ---------------- CONTACT ----------------

@app.route("/contact")
def contact():
    return render_template("contact.html")


# ---------------- RUN APP ----------------

if __name__ == "__main__":
    app.run(debug=True)