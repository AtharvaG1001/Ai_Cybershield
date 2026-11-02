"""
WHOIS Checker Module
--------------------
Extracts WHOIS information for a domain and returns a standardized
risk module dict compatible with ThreatScoreEngine.calculate().

FIX: Previous version returned a plain dict missing `module` and
`risk_score` keys, causing the domain-age signal to be silently
discarded from the overall threat score.
"""

import whois
from urllib.parse import urlparse
from datetime import datetime, timezone


class WhoisChecker:

    def __init__(self):
        self.cache = {}

    def extract_domain(self, url):
        """Extract bare hostname from URL."""
        parsed = urlparse(url)
        netloc = parsed.netloc or url
        # Strip port number
        return netloc.split(":")[0].lower()

    def get_whois(self, domain):
        """Fetch WHOIS data with simple cache."""
        if domain in self.cache:
            return self.cache[domain]
        try:
            data = whois.whois(domain)
            self.cache[domain] = data
            return data
        except Exception as e:
            return None

    def _get_first_date(self, value):
        """WHOIS may return a list or a single datetime."""
        if value is None:
            return None
        if isinstance(value, list):
            return value[0]
        return value

    def get_domain_age_days(self, domain):
        """Returns domain age in days, or None if unavailable."""
        data = self.get_whois(domain)
        if data is None:
            return None
        creation = self._get_first_date(getattr(data, "creation_date", None))
        if creation is None:
            return None
        try:
            if hasattr(creation, "tzinfo") and creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)
            elif not hasattr(creation, "tzinfo"):
                return None
            today = datetime.now(timezone.utc)
            return max(0, (today - creation).days)
        except Exception:
            return None

    def get_days_until_expiry(self, domain):
        """Returns days until expiry, or None if unavailable."""
        data = self.get_whois(domain)
        if data is None:
            return None
        expiry = self._get_first_date(getattr(data, "expiration_date", None))
        if expiry is None:
            return None
        try:
            if hasattr(expiry, "tzinfo") and expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            today = datetime.now(timezone.utc)
            return (expiry - today).days
        except Exception:
            return None

    def analyze(self, url):
        """
        Returns standardized module dict with module, status, risk_score,
        security_level, data, warnings, and recommendations keys.

        FIX (ISSUE-001, ISSUE-010): Old version returned a plain dict
        without these keys, causing ThreatScoreEngine to discard the
        domain-age risk signal entirely.
        """
        domain = self.extract_domain(url)

        report = {
            "module": "WHOIS Checker",
            "status": "SUCCESS",
            "risk_score": 0,
            "security_level": "LOW",
            "data": {
                "domain": domain,
                "domain_age_days": None,
                "days_until_expiry": None,
                "registrar": "Unknown",
                "country": "Unknown",
                "name_servers": [],
            },
            "warnings": [],
            "recommendations": [],
        }

        try:
            data = self.get_whois(domain)

            if data is None:
                report["status"] = "UNAVAILABLE"
                report["data"]["note"] = "WHOIS data could not be retrieved."
                return report

            report["data"]["domain_age_days"] = self.get_domain_age_days(domain)
            report["data"]["days_until_expiry"] = self.get_days_until_expiry(domain)
            report["data"]["registrar"] = getattr(data, "registrar", "Unknown") or "Unknown"
            report["data"]["country"] = getattr(data, "country", "Unknown") or "Unknown"

            ns = getattr(data, "name_servers", []) or []
            if isinstance(ns, str):
                ns = [ns]
            report["data"]["name_servers"] = list(ns)

            # -----------------------------------------------------------
            # Risk scoring based on domain age
            # -----------------------------------------------------------
            age = report["data"]["domain_age_days"]

            if age is not None:
                if age < 30:
                    report["risk_score"] = 40
                    report["security_level"] = "HIGH"
                    report["warnings"].append(
                        f"Domain was registered very recently ({age} days ago). "
                        "Very new domains are disproportionately associated with phishing."
                    )
                    report["recommendations"].append(
                        "Exercise extreme caution with domains registered less than 30 days ago."
                    )
                elif age < 180:
                    report["risk_score"] = 20
                    report["security_level"] = "MEDIUM"
                    report["warnings"].append(
                        f"Domain was registered recently ({age} days ago / ~{age // 30} months)."
                    )
                elif age < 365:
                    report["risk_score"] = 5
                    report["security_level"] = "LOW"
                else:
                    report["risk_score"] = 0
                    report["security_level"] = "LOW"
                    report["recommendations"].append(
                        f"Domain has been registered for {age // 365} year(s) — established domain."
                    )

            # Expiry risk
            expiry = report["data"]["days_until_expiry"]
            if expiry is not None and expiry < 30:
                report["risk_score"] = min(report["risk_score"] + 10, 100)
                report["warnings"].append(
                    f"Domain registration expires in {expiry} days."
                )

        except Exception as e:
            report["status"] = "UNAVAILABLE"
            report["data"]["note"] = f"WHOIS lookup failed: {str(e)}"

        return report


if __name__ == "__main__":
    checker = WhoisChecker()
    for url in ["https://google.com", "https://this-domain-does-not-exist-xyz123.com"]:
        result = checker.analyze(url)
        print(f"\n== WHOIS: {url} ==")
        print(f"  Module      : {result['module']}")
        print(f"  Status      : {result['status']}")
        print(f"  Risk Score  : {result['risk_score']}")
        print(f"  Domain Age  : {result['data'].get('domain_age_days')} days")
        for w in result["warnings"]:
            print(f"  WARNING: {w}")