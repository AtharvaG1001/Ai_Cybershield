"""
Model Predictor — Loads the trained RF model and generates predictions.

FIX (ISSUE-004): The label mapping was inverted.
In the PhiUSIIL dataset, label=0 means PHISHING and label=1 means LEGITIMATE.
The old code used "PHISHING if prediction == 1" which incorrectly flagged
legitimate sites. The correct mapping is "PHISHING if prediction == 0".

FIX (ISSUE-003): Feature names are now loaded from feature_names.json (if
available) and validated against the extracted feature dict before prediction.
"""

import os
import json
import logging
import joblib
import pandas as pd

from website_engine.url_analyzer import analyze_url

logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(BASE_DIR, "models")

MODEL_PATH = os.path.join(MODEL_DIR, "phishing_model_custom.pkl")
FEATURE_NAMES_PATH = os.path.join(MODEL_DIR, "feature_names.json")
MODEL_META_PATH = os.path.join(MODEL_DIR, "model_metadata.json")


# Well-known domains. The training set (PhiUSIIL) contains almost only bare
# homepages as legitimate samples, so the lexical model over-flags legitimate
# deep links (e.g. github.com/login). Matching is on the exact host or a true
# subdomain, so "paypal.com.evil.tk" is NOT trusted.
TRUSTED_DOMAINS = {
    "google.com", "youtube.com", "gmail.com", "microsoft.com", "live.com",
    "office.com", "outlook.com", "apple.com", "icloud.com", "amazon.com",
    "github.com", "wikipedia.org", "facebook.com", "instagram.com",
    "linkedin.com", "twitter.com", "x.com", "paypal.com", "netflix.com",
    "stackoverflow.com", "mozilla.org", "cloudflare.com", "adobe.com",
    "dropbox.com", "zoom.us", "whatsapp.com", "yahoo.com", "reddit.com",
    "python.org", "anthropic.com", "claude.ai", "vercel.com",
}


def is_trusted_domain(url: str) -> bool:
    from urllib.parse import urlparse
    u = url.strip()
    if "://" not in u:
        u = "http://" + u
    try:
        host = (urlparse(u).hostname or "").lower()
    except ValueError:
        return False
    return any(host == d or host.endswith("." + d) for d in TRUSTED_DOMAINS)


class ModelPredictor:

    def __init__(self):
        # Load model
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(f"Model not found: {MODEL_PATH}")

        self.model = joblib.load(MODEL_PATH)
        logger.info("Model loaded: %s", type(self.model).__name__)

        # Load feature names (if available)
        if os.path.exists(FEATURE_NAMES_PATH):
            with open(FEATURE_NAMES_PATH) as f:
                self.feature_names = json.load(f)
        else:
            # Fall back: use model's feature names if recorded during training
            if hasattr(self.model, "feature_names_in_"):
                self.feature_names = list(self.model.feature_names_in_)
            else:
                self.feature_names = None
            logger.warning(
                "feature_names.json not found. Feature order will be determined "
                "by analyze_url() insertion order."
            )

        # Load metadata
        if os.path.exists(MODEL_META_PATH):
            with open(MODEL_META_PATH) as f:
                self.metadata = json.load(f)
        else:
            self.metadata = {
                "model_version": "1.0.0",
                "model_type": type(self.model).__name__,
                "n_features": getattr(self.model, "n_features_in_", "unknown"),
            }

    @property
    def model_version(self) -> str:
        return self.metadata.get("model_version", "1.0.0")

    @property
    def n_features(self) -> int:
        return getattr(self.model, "n_features_in_", 0)

    def predict(self, url: str) -> dict:
        """
        Extract URL features, run model, and return structured prediction.

        Label semantics (PhiUSIIL dataset):
          0 = PHISHING
          1 = LEGITIMATE

        FIX: Old code used `"PHISHING" if prediction == 1` — this was
        inverted and would classify legitimate sites as phishing.
        """
        features = analyze_url(url)

        # Validate / reorder features if names are available
        if self.feature_names is not None:
            missing = set(self.feature_names) - set(features.keys())
            extra = set(features.keys()) - set(self.feature_names)
            if missing:
                raise ValueError(
                    f"Feature mismatch: missing features {missing}. "
                    "Re-train the model or fix url_analyzer.py."
                )
            # Build DataFrame in the exact order the model was trained on
            feature_df = pd.DataFrame([[features[k] for k in self.feature_names]],
                                       columns=self.feature_names)
        else:
            feature_df = pd.DataFrame([features])

        # Predict
        prediction = self.model.predict(feature_df)[0]
        probabilities = self.model.predict_proba(feature_df)[0]

        # Classes: model.classes_ = [0, 1] where 0=phishing, 1=legitimate
        classes = list(self.model.classes_)
        phishing_idx = classes.index(0)   # index of class 0 (phishing)
        legit_idx = classes.index(1)      # index of class 1 (legitimate)

        phishing_prob = round(float(probabilities[phishing_idx]) * 100, 2)
        legit_prob = round(float(probabilities[legit_idx]) * 100, 2)
        confidence = round(float(max(probabilities)) * 100, 2)

        # FIX: correct label mapping
        predicted_label = "PHISHING" if prediction == 0 else "LEGITIMATE"

        if predicted_label == "PHISHING" and is_trusted_domain(url):
            predicted_label = "LEGITIMATE"
            phishing_prob = min(phishing_prob, 10.0)
            legit_prob = round(100.0 - phishing_prob, 2)
            confidence = legit_prob

        return {
            "prediction": predicted_label,
            "confidence": confidence,
            "phishing_probability": phishing_prob,
            "legitimate_probability": legit_prob,
            "features": features,
            "model_version": self.model_version,
        }


if __name__ == "__main__":
    predictor = ModelPredictor()
    for url in [
        "https://google.com",
        "http://secure-paypal-login.xyz/verify?user=123",
    ]:
        r = predictor.predict(url)
        print(f"\n== {url} ==")
        print(f"  Prediction  : {r['prediction']}")
        print(f"  Confidence  : {r['confidence']}%")
        print(f"  Phishing P  : {r['phishing_probability']}%")
        print(f"  Legit P     : {r['legitimate_probability']}%")