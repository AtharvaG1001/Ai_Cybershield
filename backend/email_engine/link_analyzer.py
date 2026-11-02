"""
Link Analyzer for Email Engine

FIX (ISSUE-005): The previous version instantiated AIEngine inside
LinkAnalyzer.__init__(), triggering recursive model loading and making
5-15 network calls per email. This caused timeouts and hangs.

The new version performs rule-based URL analysis only (no network calls,
no model predictions inline). The calling code can optionally pass a
model_predictor instance if ML scoring of links is desired.
"""

import re
from urllib.parse import urlparse


class LinkAnalyzer:

    def __init__(self, model_predictor=None):
        """
        Parameters
        ----------
        model_predictor : ModelPredictor | None
            If provided, ML predictions are run on each extracted link.
            Pass None for fast rule-based analysis only (default).
        """
        self.model_predictor = model_predictor

        self.suspicious_tlds = [
            ".xyz", ".top", ".click", ".buzz", ".work", ".download",
            ".zip", ".mov", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw",
        ]

        self.suspicious_keywords = [
            "login", "signin", "verify", "verification", "account",
            "secure", "security", "update", "confirm", "password",
            "credential", "wallet", "payment", "recover", "suspended",
            "unlock", "webscr", "authenticate",
        ]

        self.url_shorteners = [
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
            "buff.ly", "is.gd", "cli.gs", "dlvr.it", "rebrandly.com",
        ]

    # -----------------------------------------------------------------
    # URL extraction
    # -----------------------------------------------------------------

    def extract_urls(self, text: str) -> list:
        if not text:
            return []
        url_pattern = r"https?://[^\s<>\"'\)]+"
        urls = re.findall(url_pattern, text)
        cleaned = []
        for url in urls:
            url = url.rstrip(".,!?;:)]}\"'")
            if url not in cleaned:
                cleaned.append(url)
        return cleaned

    # -----------------------------------------------------------------
    # Per-URL analysis (rule-based only)
    # -----------------------------------------------------------------

    def analyze_url(self, url: str) -> dict:
        result = {
            "url": url,
            "valid": False,
            "score": 0,
            "risk_level": "LOW",
            "indicators": [],
            "ml_prediction": None,
        }

        try:
            parsed = urlparse(url)

            if parsed.scheme not in ("http", "https"):
                result["indicators"].append("URL does not use HTTP or HTTPS.")
                result["score"] += 15

            if not parsed.netloc:
                result["indicators"].append("URL has no valid domain.")
                result["score"] = min(result["score"] + 25, 100)
                result["risk_level"] = "HIGH"
                return result

            result["valid"] = True
            hostname = (parsed.hostname or "").lower()

            # --- URL length
            if len(url) > 200:
                result["score"] += 10
                result["indicators"].append("Very long URL.")
            elif len(url) > 120:
                result["score"] += 5

            # --- HTTPS
            if parsed.scheme == "http":
                result["score"] += 8
                result["indicators"].append("URL uses HTTP (unencrypted).")

            # --- IP address
            if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", hostname):
                result["score"] += 25
                result["indicators"].append(
                    "URL uses an IP address instead of a domain name."
                )

            # --- Suspicious TLD
            for tld in self.suspicious_tlds:
                if hostname.endswith(tld):
                    result["score"] += 15
                    result["indicators"].append(
                        f"Suspicious top-level domain: {tld}"
                    )
                    break

            # --- URL shortener
            for shortener in self.url_shorteners:
                if hostname == shortener or hostname.endswith("." + shortener):
                    result["score"] += 10
                    result["indicators"].append(
                        f"URL shortener detected ({shortener}). "
                        "Real destination is hidden."
                    )
                    break

            # --- Subdomains
            parts = hostname.split(".")
            if len(parts) >= 5:
                result["score"] += 10
                result["indicators"].append("URL has many subdomains.")
            elif len(parts) == 4:
                result["score"] += 5

            # --- @ symbol
            if "@" in url:
                result["score"] += 20
                result["indicators"].append(
                    "URL contains @ symbol — browser may redirect to a different host."
                )

            # --- Hyphens in domain
            hyphens = hostname.count("-")
            if hyphens >= 3:
                result["score"] += 10
                result["indicators"].append(
                    "Domain contains many hyphens (common in typosquatting)."
                )
            elif hyphens >= 1:
                result["score"] += 3

            # --- Suspicious keywords (in full URL)
            matched = [kw for kw in self.suspicious_keywords if kw in url.lower()]
            if matched:
                result["score"] += min(len(matched) * 4, 16)
                result["indicators"].append(
                    f"Suspicious keywords in URL: {', '.join(matched)}"
                )

            # --- Encoded characters
            if "%" in url:
                result["score"] += 5
                result["indicators"].append("URL contains encoded characters.")

            # --- Deep path
            path_parts = [p for p in (parsed.path or "").split("/") if p]
            if len(path_parts) >= 5:
                result["score"] += 8
                result["indicators"].append("URL has a deep path structure.")

            # --- Large query string
            if parsed.query and len(parsed.query) > 100:
                result["score"] += 5
                result["indicators"].append("URL has a very large query string.")

            # --- ML prediction (optional)
            if self.model_predictor and result["valid"]:
                try:
                    ml = self.model_predictor.predict(url)
                    result["ml_prediction"] = {
                        "prediction": ml["prediction"],
                        "phishing_probability": ml["phishing_probability"],
                        "confidence": ml["confidence"],
                    }
                    if ml["phishing_probability"] >= 70:
                        result["score"] += 20
                        result["indicators"].append(
                            f"ML model: {ml['phishing_probability']}% phishing probability."
                        )
                except Exception:
                    pass

            result["score"] = min(result["score"], 100)

            if result["score"] < 25:
                result["risk_level"] = "LOW"
            elif result["score"] < 50:
                result["risk_level"] = "MEDIUM"
            elif result["score"] < 75:
                result["risk_level"] = "HIGH"
            else:
                result["risk_level"] = "CRITICAL"

        except Exception as error:
            result["valid"] = False
            result["score"] = 50
            result["risk_level"] = "HIGH"
            result["indicators"].append(f"URL analysis error: {str(error)}")

        return result

    # -----------------------------------------------------------------
    # Main analysis method
    # -----------------------------------------------------------------

    def analyze(self, links=None, body="") -> dict:
        result = {
            "module": "Link Analyzer",
            "status": "SUCCESS",
            "data": {
                "link_count": 0,
                "links": [],
                "highest_risk_score": 0,
                "highest_risk_level": "LOW",
            },
            "warnings": [],
            "recommendations": [],
        }

        try:
            if links is None:
                links = self.extract_urls(body)
            else:
                links = list(links)

            # Deduplicate
            seen = []
            for link in links:
                if link not in seen:
                    seen.append(link)
            links = seen

            result["data"]["link_count"] = len(links)

            for link in links:
                link_result = self.analyze_url(link)
                result["data"]["links"].append(link_result)

                if link_result["score"] > result["data"]["highest_risk_score"]:
                    result["data"]["highest_risk_score"] = link_result["score"]
                    result["data"]["highest_risk_level"] = link_result["risk_level"]

            # Warnings
            if links:
                result["warnings"].append(
                    f"{len(links)} link(s) detected in this email."
                )

            high_risk = [
                l for l in result["data"]["links"] if l["score"] >= 50
            ]
            if high_risk:
                result["warnings"].append(
                    f"{len(high_risk)} high-risk link(s) detected."
                )
                result["recommendations"].append(
                    "Do not click high-risk links until independently verified."
                )
            elif links:
                result["recommendations"].append(
                    "Verify all email links before clicking."
                )
            else:
                result["recommendations"].append(
                    "No links were detected in this email."
                )

        except Exception as error:
            result["status"] = "FAILED"
            result["warnings"].append(f"Link analysis failed: {str(error)}")

        return result