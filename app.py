import csv
import html
import ipaddress
import pickle
import warnings
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, jsonify, render_template, request

from convert import shortlink

warnings.filterwarnings("ignore")

DATAFILES_DIR = Path("DataFiles")
URL_TEXT_MODEL_PATH = Path("url_text_model.pkl")
SAFE_CONFIDENCE_THRESHOLD = 0.85
PHISHING_CONFIDENCE_THRESHOLD = 0.65
HIGH_RISK_SCORE = 4
MEDIUM_RISK_SCORE = 2
SUSPICIOUS_KEYWORDS = (
    "login",
    "signin",
    "verify",
    "secure",
    "account",
    "password",
    "wallet",
    "bank",
    "billing",
    "update",
)

with URL_TEXT_MODEL_PATH.open("rb") as model_file:
    url_text_model = pickle.load(model_file)


app = Flask(__name__, template_folder="frontend", static_folder="frontend/static")


def canonicalize_host(raw_value):
    value = html.unescape((raw_value or "").strip()).lower()
    if not value:
        return ""

    if "://" not in value:
        value = f"https://{value}"

    parsed = urlparse(value)
    host = (parsed.netloc or parsed.path).split("/")[0]
    host = host.split("@")[-1].split(":")[0].strip(".")

    if host.startswith("www."):
        host = host[4:]

    return host


def canonicalize_url(raw_value):
    value = html.unescape((raw_value or "").strip())
    if not value:
        return ""

    if "://" not in value:
        value = f"https://{value}"

    parsed = urlparse(value)
    if not parsed.netloc:
        return ""

    host = parsed.netloc.lower().split("@")[-1].split(":")[0]
    normalized = parsed._replace(
        scheme=parsed.scheme.lower(),
        netloc=host,
        fragment="",
    ).geturl()

    return normalized


def build_url_lookup_keys(raw_value):
    normalized = canonicalize_url(raw_value)
    if not normalized:
        return set()

    keys = {normalized}
    if normalized.endswith("/"):
        keys.add(normalized[:-1])
    else:
        keys.add(f"{normalized}/")

    return {key for key in keys if key}


def load_csv_first_column(csv_path):
    values = set()
    with csv_path.open("r", newline="", encoding="utf-8") as file:
        reader = csv.reader(file)
        for row in reader:
            if not row:
                continue

            value = (row[0] or "").strip()
            if not value or value.lower() in {"url", "domain"}:
                continue

            values.add(value)

    return values


PHISHING_URLS = {
    key
    for value in load_csv_first_column(DATAFILES_DIR / "phishurls.csv")
    for key in build_url_lookup_keys(value)
}

LEGITIMATE_HOSTS = {
    canonicalize_host(value)
    for value in load_csv_first_column(DATAFILES_DIR / "legitimateurls.csv")
    if canonicalize_host(value)
}


def build_result(url, status, action_label, is_safe, message, result=None, source=None, confidence=None):
    return {
        "url": url,
        "status": status,
        "action_label": action_label,
        "is_safe": is_safe,
        "result": result or ("safe" if is_safe else "phish"),
        "message": message,
        "source": source,
        "confidence": confidence,
    }


def normalize_url(raw_url):
    if not raw_url:
        raise ValueError("URL is required.")

    normalized_url = raw_url.strip()
    if not normalized_url:
        raise ValueError("URL is required.")

    if "://" not in normalized_url:
        normalized_url = f"https://{normalized_url}"

    parsed_url = urlparse(normalized_url)
    if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
        raise ValueError("Enter a valid website URL.")

    return normalized_url


def dataset_lookup_result(normalized_url, risk=None):
    for key in build_url_lookup_keys(normalized_url):
        if key in PHISHING_URLS:
            return build_result(
                normalized_url,
                "Not Safe",
                "Still want to Continue",
                False,
                "Website was found in the phishing dataset.",
                source="dataset-phishing",
            )

    host = canonicalize_host(normalized_url)
    if host in LEGITIMATE_HOSTS:
        if risk is not None and risk["score"] >= MEDIUM_RISK_SCORE:
            return build_result(
                normalized_url,
                "Suspicious",
                "Proceed carefully",
                False,
                "Domain exists in the legitimate dataset, but this specific URL pattern still looks suspicious."
                + format_reason_text(risk["reasons"]),
                result="suspicious",
                source="dataset-legitimate-risk",
            )
        return build_result(
            normalized_url,
            "Safe",
            "Continue",
            True,
            "Website was found in the legitimate dataset.",
            source="dataset-legitimate",
        )

    return None


def evaluate_url_risk(normalized_url):
    parsed = urlparse(normalized_url)
    host = canonicalize_host(normalized_url)
    score = 0
    reasons = []

    try:
        ipaddress.ip_address(host)
        score += 4
        reasons.append("Uses an IP address instead of a domain.")
    except Exception:
        pass

    if "@" in normalized_url:
        score += 4
        reasons.append("Contains @ in the URL.")

    if shortlink(normalized_url) == -1:
        score += 2
        reasons.append("Uses a URL shortener.")

    if "xn--" in host:
        score += 2
        reasons.append("Contains punycode in the hostname.")

    if parsed.scheme != "https":
        score += 1
        reasons.append("Does not use HTTPS.")

    if len(normalized_url) > 160:
        score += 3
        reasons.append("URL is extremely long.")
    elif len(normalized_url) > 100:
        score += 2
        reasons.append("URL is unusually long.")
    elif len(normalized_url) > 75:
        score += 1
        reasons.append("URL is long.")

    if host.count(".") >= 3:
        score += 1
        reasons.append("Has many subdomains.")

    if "-" in host:
        score += 1
        reasons.append("Hostname contains hyphens.")

    path_and_query = f"{parsed.path}?{parsed.query}".lower()
    keyword_hits = [keyword for keyword in SUSPICIOUS_KEYWORDS if keyword in path_and_query]
    if keyword_hits:
        score += min(2, len(keyword_hits))
        reasons.append(
            "Contains sensitive keywords in the path: " + ", ".join(sorted(set(keyword_hits))) + "."
        )

    return {"score": score, "reasons": reasons}


def extract_prediction_confidence(url_value, prediction):
    if not hasattr(url_text_model, "predict_proba"):
        return None

    probabilities = url_text_model.predict_proba([url_value])[0]
    classes = list(url_text_model.classes_)
    if prediction not in classes:
        return None

    confidence = float(probabilities[classes.index(prediction)])
    return round(confidence, 4)


def format_reason_text(reasons):
    if not reasons:
        return ""
    return " Reasons: " + " ".join(reasons[:3])


def analyze_url(raw_url):
    normalized_url = normalize_url(raw_url)
    risk = evaluate_url_risk(normalized_url)
    dataset_result = dataset_lookup_result(normalized_url, risk=risk)
    if dataset_result is not None:
        return dataset_result

    if risk["score"] >= HIGH_RISK_SCORE:
        return build_result(
            normalized_url,
            "Suspicious",
            "Proceed carefully",
            False,
            "URL pattern looks suspicious before model analysis." + format_reason_text(risk["reasons"]),
            result="suspicious",
            source="heuristics",
        )

    prediction = int(url_text_model.predict([normalized_url])[0])
    confidence = extract_prediction_confidence(normalized_url, prediction)

    if prediction == -1 and (confidence is None or confidence >= PHISHING_CONFIDENCE_THRESHOLD):
        return build_result(
            normalized_url,
            "Not Safe",
            "Still want to Continue",
            False,
            "The trained URL model marked this link as phishing."
            + (f" Confidence: {confidence:.0%}." if confidence is not None else "")
            + format_reason_text(risk["reasons"]),
            source="model",
            confidence=confidence,
        )

    if prediction == 1 and confidence is not None and confidence >= SAFE_CONFIDENCE_THRESHOLD and risk["score"] < MEDIUM_RISK_SCORE:
        return build_result(
            normalized_url,
            "Safe",
            "Continue",
            True,
            f"The trained URL model marked this link as safe with {confidence:.0%} confidence.",
            source="model",
            confidence=confidence,
        )

    return build_result(
        normalized_url,
        "Suspicious",
        "Proceed carefully",
        False,
        "The result is not strong enough to mark this URL as safe."
        + (f" Model confidence: {confidence:.0%}." if confidence is not None else "")
        + format_reason_text(risk["reasons"]),
        result="suspicious",
        source="hybrid",
        confidence=confidence,
    )


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/result", methods=["GET", "POST"])
def predict():
    if request.method == "GET":
        return render_template("index.html")

    raw_url = request.form.get("name", "")
    try:
        scan_result = analyze_url(raw_url)
        return render_template(
            "index.html",
            initial_result=scan_result,
            scan_input=scan_result["url"],
        )
    except ValueError as error:
        return (
            render_template("index.html", scan_error=str(error), scan_input=raw_url),
            400,
        )
    except Exception:
        return (
            render_template(
                "index.html",
                scan_error="Unable to scan this URL right now.",
                scan_input=raw_url,
            ),
            500,
        )


@app.route("/api/scan", methods=["POST"])
def scan_api():
    payload = request.get_json(silent=True) or {}

    try:
        return jsonify(analyze_url(payload.get("url", "")))
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    except Exception:
        return jsonify({"error": "Unable to scan this URL right now."}), 500


@app.route("/usecases", methods=["GET"])
def usecases():
    return render_template("usecases.html")


if __name__ == "__main__":
    app.run(debug=True)
