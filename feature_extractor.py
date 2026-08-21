import re

def extract_features(url):

    features = {}

    # HTTPS
    features["https"] = 1 if url.startswith("https://") else 0

    # @ Symbol
    features["has_at"] = 1 if "@" in url else 0

    # Hyphen
    features["has_hyphen"] = 1 if "-" in url else 0

    # URL Length
    features["length"] = len(url)

    # Number of Dots
    features["dots"] = url.count(".")

    # IP Address
    ip_pattern = r"(\d{1,3}\.){3}\d{1,3}"
    features["ip"] = 1 if re.search(ip_pattern, url) else 0

    # Suspicious Words
    suspicious = [
        "login",
        "verify",
        "update",
        "secure",
        "account",
        "bank",
        "paypal",
        "signin",
        "confirm"
    ]

    count = 0

    for word in suspicious:
        if word in url.lower():
            count += 1

    features["suspicious_words"] = count

    return features