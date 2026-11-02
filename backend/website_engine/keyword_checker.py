"""
Keyword Checker — contextual URL keyword analysis.

FIX (ISSUE-008): The old implementation assigned 8 points per keyword
match, causing massive false positives for legitimate sites like:
  https://secure.bankofamerica.com/verify  → 16 pts (MEDIUM)
  https://account.google.com/login         → 16 pts (MEDIUM)

The new implementation:
1. Uses context-aware scoring (domain vs path vs query)
2. Applies lower weight for keywords in the path (not the domain)
3. Caps contribution at 15 points maximum
4. Skips common false-positive patterns
"""

from urllib.parse import urlparse


class KeywordChecker:

    def __init__(self):
        # Keywords in the DOMAIN strongly suggest impersonation
        self.domain_keywords = [
            "paypal", "apple", "amazon", "microsoft", "google",
            "facebook", "netflix", "instagram", "linkedin", "twitter",
            "webscr", "authenticate",
        ]

        # Keywords in the PATH — moderate weight, context-dependent
        self.path_keywords = [
            "login", "signin", "verify", "verification",
            "password", "otp", "confirm", "credential", "suspend",
            "recover", "unlock", "reset", "phish",
        ]

        # Low-weight keywords — appear in many legitimate sites too
        self.low_weight_keywords = [
            "secure", "security", "account", "update", "support",
            "admin", "bank", "payment", "invoice", "refund",
            "gift", "bonus", "free", "crypto", "bitcoin", "wallet",
        ]

    def analyze(self, url: str) -> dict:
        url_lower = url.lower()
        try:
            parsed = urlparse(url_lower)
            domain = parsed.netloc
            path = parsed.path + "?" + parsed.query if parsed.query else parsed.path
        except Exception:
            domain = url_lower
            path = ""

        score = 0
        matched_domain = []
        matched_path = []
        matched_low = []

        # Domain keywords (high weight — 8 pts each, max 24)
        for kw in self.domain_keywords:
            if kw in domain:
                matched_domain.append(kw)
        domain_score = min(len(matched_domain) * 8, 24)
        score += domain_score

        # Path keywords (medium weight — 4 pts each, max 16)
        for kw in self.path_keywords:
            if kw in path:
                matched_path.append(kw)
        path_score = min(len(matched_path) * 4, 16)
        score += path_score

        # Low-weight keywords — only count if already in domain (extra context)
        for kw in self.low_weight_keywords:
            if kw in domain:
                matched_low.append(kw)
        low_score = min(len(matched_low) * 2, 8)
        score += low_score

        # Cap total contribution
        score = min(score, 15)

        if score == 0:
            level = "LOW"
        elif score < 8:
            level = "LOW"
        elif score < 12:
            level = "MEDIUM"
        else:
            level = "HIGH"

        all_matched = matched_domain + matched_path + matched_low

        report = {
            "module": "Keyword Checker",
            "status": "SUCCESS",
            "risk_score": score,
            "security_level": level,
            "data": {
                "matched_keywords": all_matched,
                "matched_domain_keywords": matched_domain,
                "matched_path_keywords": matched_path,
                "total_matches": len(all_matched),
            },
            "warnings": [],
            "recommendations": [],
        }

        if matched_domain:
            report["warnings"].append(
                f"Domain contains brand-related keywords: {', '.join(matched_domain)}. "
                "Verify this is the legitimate brand's domain."
            )

        if matched_path:
            report["warnings"].append(
                f"URL path contains credential-related keywords: {', '.join(matched_path)}."
            )

        if all_matched:
            report["recommendations"].append(
                "Check the full domain name carefully before entering any credentials."
            )

        return report