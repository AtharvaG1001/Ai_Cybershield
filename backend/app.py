from flask import Flask, request, jsonify
from flask_cors import CORS

from ai_engine import AIEngine
from email_engine.email_engine import EmailEngine


app = Flask(__name__)
CORS(app)

url_engine = AIEngine()
email_engine = EmailEngine()


@app.route("/")
def home():
    return jsonify({
        "application": "AI Shield — Phishing & Email Threat Detection",
        "status": "Running",
        "services": {
            "url_detector": True,
            "email_detector": True
        }
    })


# Health check for Render
@app.route("/healthz")
def health():
    return jsonify({"status": "ok"}), 200


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    if not data:
        return jsonify({"status": "FAILED", "message": "No JSON data received."}), 400

    url = data.get("url")
    if not url:
        return jsonify({"status": "FAILED", "message": "URL is required."}), 400

    try:
        result = url_engine.analyze(url)
        return jsonify(result)
    except Exception as e:
        return jsonify({"status": "FAILED", "message": str(e)}), 500


@app.route("/analyze-email", methods=["POST"])
def analyze_email():
    data = request.get_json()
    if not data:
        return jsonify({"status": "FAILED", "message": "No JSON data received."}), 400

    raw_email = data.get("raw_email", "").strip()
    if not raw_email:
        return jsonify({"status": "FAILED", "message": "Raw email is required."}), 400

    try:
        result = email_engine.analyze(raw_email)
        return jsonify(result)
    except Exception as e:
        return jsonify({"status": "FAILED", "message": str(e)}), 500


@app.route("/analyze-all", methods=["POST"])
def analyze_all():
    data = request.get_json() or {}
    response = {"status": "SUCCESS", "analysis": {}}

    if data.get("url"):
        try:
            response["analysis"]["url"] = url_engine.analyze(data["url"])
        except Exception as e:
            response["analysis"]["url"] = {"status": "FAILED", "message": str(e)}

    if data.get("email"):
        email_data = data["email"]
        subject = email_data.get("subject", "").strip()
        body = email_data.get("body", "").strip()
        sender = email_data.get("sender", "").strip()

        if subject or body:
            try:
                # EmailEngine.analyze() only accepts a single raw_email string,
                # so build one here instead of passing sender/subject/body directly
                raw_email = f"From: {sender}\nSubject: {subject}\n\n{body}"
                response["analysis"]["email"] = email_engine.analyze(raw_email)
            except Exception as e:
                response["analysis"]["email"] = {"status": "FAILED", "message": str(e)}

    return jsonify(response)


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)