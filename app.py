import csv
import os
import random
from datetime import datetime
from urllib.parse import urlparse

from flask import Flask, render_template, request
import joblib

from feature_extractor import extract_features


app = Flask(__name__)


# ============================================================
# LOAD ML MODEL
# ============================================================

model = joblib.load("model.pkl")
vectorizer = joblib.load("vectorizer.pkl")


# ============================================================
# TRUSTED / KNOWN SAFE DOMAINS
# ============================================================

TRUSTED_DOMAINS = {
    "bankofbaroda": [
        "bankofbaroda.bank.in"
    ]
}

KNOWN_SAFE_DOMAINS = {
    "example.com",
    "www.example.com"
}


# ============================================================
# BRAND / DOMAIN CHECK
# ============================================================

def check_brand_domain(url):

    parsed_url = urlparse(url)
    hostname = parsed_url.hostname

    if not hostname:
        return None

    hostname = hostname.lower()

    for brand, trusted_domains in TRUSTED_DOMAINS.items():

        if brand in hostname:

            if hostname not in trusted_domains:

                return (
                    f"⚠️ The URL contains the name '{brand}', "
                    f"but the domain does not match the expected "
                    f"trusted domain."
                )

    return None


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():
    return render_template("home.html")


# ============================================================
# SCAN PAGE
# ============================================================

@app.route("/scan")
def scan():
    return render_template("scan.html")


# ============================================================
# PREDICT
# ============================================================

@app.route("/predict", methods=["POST"])
def predict():

    url = request.form["url"].strip()


    # --------------------------------------------------------
    # VALIDATE URL
    # --------------------------------------------------------

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


    # --------------------------------------------------------
    # ML PREDICTION
    # --------------------------------------------------------

    url_vector = vectorizer.transform([url])

    original_ml_prediction = model.predict(url_vector)[0]

    confidence = round(
        max(model.predict_proba(url_vector)[0]) * 100,
        2
    )


    # --------------------------------------------------------
    # CHECK KNOWN SAFE DOMAIN
    # --------------------------------------------------------

    parsed_url = urlparse(url)
    hostname = parsed_url.hostname

    ml_prediction = original_ml_prediction

    if hostname:

        hostname = hostname.lower()

        if hostname in KNOWN_SAFE_DOMAINS:
            ml_prediction = "benign"


    # --------------------------------------------------------
    # FEATURE EXTRACTION
    # --------------------------------------------------------

    features = extract_features(url)

    reasons = []


    # HTTPS
    if features["https"] == 0:
        reasons.append("❌ Website is not using HTTPS.")
    else:
        reasons.append("✅ HTTPS detected.")


    # @ SYMBOL
    if features["has_at"] == 1:
        reasons.append("⚠️ URL contains '@' symbol.")
    else:
        reasons.append("✅ No '@' symbol found.")


    # HYPHEN
    if features["has_hyphen"] == 1:
        reasons.append(
            "⚠️ URL contains '-' which may be suspicious."
        )


    # URL LENGTH
    if features["length"] > 75:
        reasons.append("⚠️ URL is unusually long.")
    else:
        reasons.append("✅ URL length is normal.")


    # SUBDOMAINS / DOTS
    if features["dots"] > 3:
        reasons.append(
            "⚠️ Too many subdomains detected."
        )


    # IP ADDRESS
    if features["ip"] == 1:
        reasons.append(
            "❌ URL uses an IP address."
        )
    else:
        reasons.append(
            "✅ Domain name detected."
        )


    # SUSPICIOUS WORDS
    if features["suspicious_words"] > 0:
        reasons.append(
            "⚠️ Suspicious keywords detected."
        )
    else:
        reasons.append(
            "✅ No suspicious keywords found."
        )


    # --------------------------------------------------------
    # BRAND / DOMAIN CHECK
    # --------------------------------------------------------

    brand_warning = check_brand_domain(url)

    if brand_warning:
        reasons.append(brand_warning)


    # --------------------------------------------------------
    # RISK SCORE
    # --------------------------------------------------------

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


    # Brand/domain mismatch is a strong indicator
    if brand_warning:
        risk_score += 3


    # --------------------------------------------------------
    # RISK LEVEL
    # --------------------------------------------------------

    if risk_score <= 1:

        risk_level = "🟢 LOW"
        risk_color = "green"

    elif risk_score <= 3:

        risk_level = "🟡 MEDIUM"
        risk_color = "orange"

    else:

        risk_level = "🔴 HIGH"
        risk_color = "red"


    # --------------------------------------------------------
    # FINAL FRIENDLY PREDICTION
    # --------------------------------------------------------
    #
    # IMPORTANT FIX:
    #
    # If the ML model says "benign" but the rule-based
    # security analysis gives MEDIUM/HIGH risk, we DO NOT
    # show "Safe Website".
    #
    # This prevents:
    #
    # Safe Website + HIGH Risk
    #
    # --------------------------------------------------------

    if brand_warning and ml_prediction == "benign":

        prediction = "🟡 Potentially Suspicious Website"
        result_class = "suspicious"


    elif ml_prediction == "benign":

        if risk_level == "🟢 LOW":

            prediction = "🟢 Safe Website"
            result_class = "safe"

        else:

            prediction = "🟡 Potentially Suspicious Website"
            result_class = "suspicious"


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


    # --------------------------------------------------------
    # CYBER SAFETY TIPS
    # --------------------------------------------------------

    tips = [

        "💡 Always verify the website URL before entering passwords.",

        "💡 Never click suspicious email links.",

        "💡 Enable Two-Factor Authentication whenever possible.",

        "💡 Check HTTPS before logging into any website.",

        "💡 Keep your browser updated for better security."

    ]

    cyber_tip = random.choice(tips)


    # --------------------------------------------------------
    # SAVE HISTORY
    # --------------------------------------------------------

    history_file = "history.csv"


    if not os.path.exists(history_file):

        with open(
            history_file,
            "w",
            newline="",
            encoding="utf-8"
        ) as file:

            writer = csv.writer(file)

            writer.writerow([
                "Date",
                "URL",
                "Result",
                "Confidence"
            ])


    with open(
        history_file,
        "a",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(file)

        writer.writerow([
            datetime.now().strftime(
                "%d-%m-%Y %H:%M:%S"
            ),
            url,
            prediction,
            confidence
        ])


    # --------------------------------------------------------
    # SHOW RESULT
    # --------------------------------------------------------

    return render_template(

        "scan.html",

        prediction=prediction,

        confidence=confidence,

        reasons=reasons,

        result_class=result_class,

        risk_level=risk_level,

        risk_color=risk_color,

        cyber_tip=cyber_tip
    )


# ============================================================
# DASHBOARD
# ============================================================

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

        with open(
            "history.csv",
            newline="",
            encoding="utf-8"
        ) as file:

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


# ============================================================
# HISTORY
# ============================================================

@app.route("/history")
def history():

    history = []


    if os.path.exists("history.csv"):

        with open(
            "history.csv",
            newline="",
            encoding="utf-8"
        ) as file:

            reader = csv.DictReader(file)

            history = list(reader)


        history.reverse()


    return render_template(
        "history.html",
        history=history
    )


# ============================================================
# CLEAR HISTORY
# ============================================================

@app.route("/clear_history")
def clear_history():

    with open(
        "history.csv",
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(file)

        writer.writerow([
            "Date",
            "URL",
            "Result",
            "Confidence"
        ])


    return dashboard()


# ============================================================
# ABOUT
# ============================================================

@app.route("/about")
def about():

    return render_template("about.html")


# ============================================================
# CONTACT
# ============================================================

@app.route("/contact")
def contact():

    return render_template("contact.html")


# ============================================================
# SECURITY
# ============================================================

@app.route("/security")
def security():

    return render_template("security.html")


# ============================================================
# CYBER SAFETY
# ============================================================

@app.route("/cyber_safety")
def cyber_safety():

    return render_template("cyber_safety.html")


# ============================================================
# CYBER LAW
# ============================================================

@app.route("/cyber_law")
def cyber_law():

    return render_template("cyber_law.html")


# ============================================================
# RUN APPLICATION
# ============================================================

if __name__ == "__main__":

    app.run(debug=True)