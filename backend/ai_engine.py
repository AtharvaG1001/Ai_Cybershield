"""
AI Engine — Master URL Analysis Coordinator

FIX (ISSUE-012): Each sub-module now runs in its own try/except, so a
single module failure (e.g., WHOIS timeout) no longer causes the entire
scan to fail. Partial results are returned with warnings.

FIX (ISSUE-002): SSL false positives fixed in ssl_checker.py
FIX (ISSUE-001/010): WHOIS now returns standardized risk module dict
"""

import logging
from utils.validator import is_valid_url
from model_predictor import ModelPredictor
from website_engine.ssl_checker import SSLChecker
from website_engine.dns_checker import DNSChecker
from website_engine.whois_checker import WhoisChecker
from website_engine.keyword_checker import KeywordChecker
from website_engine.threat_score import ThreatScoreEngine

logger = logging.getLogger(__name__)


class AIEngine:
    """
    Master URL Analysis Engine

    Coordinates:
    - Machine Learning prediction
    - SSL/TLS analysis
    - DNS analysis
    - WHOIS / domain-age analysis
    - Keyword pattern analysis
    - Multi-layer threat scoring
    """

    def __init__(self):
        self.model = ModelPredictor()
        self.ssl_checker = SSLChecker()
        self.dns_checker = DNSChecker()
        self.whois_checker = WhoisChecker()
        self.keyword_checker = KeywordChecker()
        self.threat_engine = ThreatScoreEngine()

    @property
    def model_version(self) -> str:
        return self.model.model_version

    def analyze(self, url: str) -> dict:
        """
        Run the full multi-layer analysis pipeline on a URL.

        Returns a structured result dict. Individual module failures are
        captured as warnings rather than aborting the entire analysis.
        """

        if not is_valid_url(url):
            return {
                "status": "FAILED",
                "message": "Invalid URL. Please enter a URL starting with http:// or https://",
            }

        result = {
            "status": "SUCCESS",
            "url": url,
            "machine_learning": None,
            "ssl": None,
            "dns": None,
            "whois": None,
            "keywords": None,
            "threat_analysis": None,
            "module_errors": [],
        }

        # ---------------------------------------------------------------
        # Layer A: Machine Learning
        # ---------------------------------------------------------------
        try:
            logger.debug("Running ML prediction for: %s", url)
            result["machine_learning"] = self.model.predict(url)
        except Exception as e:
            logger.warning("ML prediction failed: %s", e)
            result["machine_learning"] = {
                "prediction": "UNAVAILABLE",
                "confidence": None,
                "phishing_probability": None,
                "legitimate_probability": None,
                "features": {},
                "error": str(e),
            }
            result["module_errors"].append(f"ML: {str(e)}")

        # ---------------------------------------------------------------
        # Layer B: SSL / TLS
        # ---------------------------------------------------------------
        try:
            logger.debug("Checking SSL for: %s", url)
            result["ssl"] = self.ssl_checker.analyze(url)
        except Exception as e:
            logger.warning("SSL check failed: %s", e)
            result["ssl"] = {
                "module": "SSL Checker",
                "status": "FAILED",
                "risk_score": 0,
                "security_level": "LOW",
                "data": {},
                "warnings": [f"SSL check error: {str(e)}"],
                "recommendations": [],
            }
            result["module_errors"].append(f"SSL: {str(e)}")

        # ---------------------------------------------------------------
        # Layer C: DNS
        # ---------------------------------------------------------------
        try:
            logger.debug("Checking DNS for: %s", url)
            result["dns"] = self.dns_checker.analyze(url)
        except Exception as e:
            logger.warning("DNS check failed: %s", e)
            result["dns"] = {
                "module": "DNS Checker",
                "status": "FAILED",
                "risk_score": 0,
                "security_level": "LOW",
                "data": {},
                "warnings": [f"DNS check error: {str(e)}"],
                "recommendations": [],
            }
            result["module_errors"].append(f"DNS: {str(e)}")

        # ---------------------------------------------------------------
        # Layer C: WHOIS / Domain Age
        # ---------------------------------------------------------------
        try:
            logger.debug("Checking WHOIS for: %s", url)
            result["whois"] = self.whois_checker.analyze(url)
        except Exception as e:
            logger.warning("WHOIS check failed: %s", e)
            result["whois"] = {
                "module": "WHOIS Checker",
                "status": "FAILED",
                "risk_score": 0,
                "security_level": "LOW",
                "data": {},
                "warnings": [f"WHOIS check error: {str(e)}"],
                "recommendations": [],
            }
            result["module_errors"].append(f"WHOIS: {str(e)}")

        # ---------------------------------------------------------------
        # Layer B: Keyword patterns
        # ---------------------------------------------------------------
        try:
            logger.debug("Checking keywords for: %s", url)
            result["keywords"] = self.keyword_checker.analyze(url)
        except Exception as e:
            logger.warning("Keyword check failed: %s", e)
            result["keywords"] = {
                "module": "Keyword Checker",
                "status": "FAILED",
                "risk_score": 0,
                "security_level": "LOW",
                "data": {},
                "warnings": [f"Keyword check error: {str(e)}"],
                "recommendations": [],
            }
            result["module_errors"].append(f"Keywords: {str(e)}")

        # ---------------------------------------------------------------
        # Layer E: Evidence aggregation
        # ---------------------------------------------------------------
        try:
            reports = [
                r for r in [
                    result["ssl"],
                    result["dns"],
                    result["whois"],
                    result["keywords"],
                ] if r is not None
            ]
            result["threat_analysis"] = self.threat_engine.calculate(
                reports=reports,
                ml_result=result["machine_learning"],
            )
        except Exception as e:
            logger.error("Threat score calculation failed: %s", e)
            result["threat_analysis"] = {
                "overall_score": 0,
                "security_level": "INCONCLUSIVE",
                "verdict": "INCONCLUSIVE",
                "score_breakdown": {},
                "warnings": [f"Threat score error: {str(e)}"],
                "recommendations": [],
            }
            result["module_errors"].append(f"ThreatScore: {str(e)}")

        return result