import re
from email.utils import parseaddr


class SenderAnalyzer:

    def __init__(self):

        # Common free email providers
        self.free_email_providers = [
            "gmail.com",
            "yahoo.com",
            "outlook.com",
            "hotmail.com",
            "live.com",
            "icloud.com",
            "protonmail.com",
            "proton.me"
        ]

        # Suspicious/high-risk TLDs
        self.suspicious_tlds = [
            ".xyz",
            ".top",
            ".click",
            ".buzz",
            ".work",
            ".download",
            ".zip",
            ".mov",
            ".tk",
            ".ml",
            ".ga",
            ".cf",
            ".gq"
        ]

        # Common impersonation targets
        self.common_brands = [
            "paypal",
            "microsoft",
            "google",
            "apple",
            "amazon",
            "facebook",
            "instagram",
            "netflix",
            "linkedin",
            "bank",
            "sbi",
            "hdfc",
            "icici",
            "axis"
        ]

    # ==========================================
    # EXTRACT EMAIL
    # ==========================================

    def extract_email(self, sender):

        name, email_address = parseaddr(sender)

        return name.strip(), email_address.strip().lower()

    # ==========================================
    # EXTRACT DOMAIN
    # ==========================================

    def extract_domain(self, email_address):

        if "@" not in email_address:
            return ""

        return email_address.split("@")[-1].lower()

    # ==========================================
    # ANALYZE SENDER
    # ==========================================

    def analyze(self, sender=""):

        result = {

            "module": "Sender Analyzer",

            "status": "SUCCESS",

            "data": {

                "display_name": "",
                "email": "",
                "domain": "",

                "sender_score": 0,

                "risk_level": "LOW",

                "indicators": [],

                "free_email_provider": False,

                "suspicious_tld": False,

                "ip_address_sender": False,

                "brand_impersonation": False
            },

            "warnings": [],

            "recommendations": []
        }

        try:

            if not sender:

                result["status"] = "FAILED"

                result["warnings"].append(
                    "Sender information is missing."
                )

                return result

            # ==========================================
            # EXTRACT NAME + EMAIL
            # ==========================================

            display_name, email_address = self.extract_email(
                sender
            )

            domain = self.extract_domain(
                email_address
            )

            result["data"]["display_name"] = display_name
            result["data"]["email"] = email_address
            result["data"]["domain"] = domain

            score = 0

            # ==========================================
            # INVALID EMAIL FORMAT
            # ==========================================

            email_pattern = (
                r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
            )

            if not re.match(
                email_pattern,
                email_address
            ):

                score += 20

                result["data"]["indicators"].append(
                    "Invalid sender email format."
                )

                result["warnings"].append(
                    "Sender email address has an unusual format."
                )

            # ==========================================
            # FREE EMAIL PROVIDER
            # ==========================================

            if domain in self.free_email_providers:

                result["data"]["free_email_provider"] = True

                result["data"]["indicators"].append(
                    "Sender uses a free email provider."
                )

                # Not automatically malicious
                score += 2

            # ==========================================
            # SUSPICIOUS TLD
            # ==========================================

            for tld in self.suspicious_tlds:

                if domain.endswith(tld):

                    result["data"]["suspicious_tld"] = True

                    result["data"]["indicators"].append(
                        f"Suspicious top-level domain detected: {tld}"
                    )

                    score += 15

                    break

            # ==========================================
            # IP ADDRESS AS DOMAIN
            # ==========================================

            ip_pattern = (
                r"^(?:\d{1,3}\.){3}\d{1,3}$"
            )

            if re.match(
                ip_pattern,
                domain
            ):

                result["data"]["ip_address_sender"] = True

                result["data"]["indicators"].append(
                    "Sender uses an IP address instead of a domain."
                )

                score += 25

                result["warnings"].append(
                    "Sender address uses an IP address."
                )

            # ==========================================
            # BRAND IMPERSONATION
            # ==========================================

            sender_text = (
                f"{display_name} {email_address}"
            ).lower()

            for brand in self.common_brands:

                if brand in sender_text:

                    # If the brand appears in a domain,
                    # it may be legitimate OR impersonation.
                    # We flag it for further verification.

                    result["data"]["brand_impersonation"] = True

                    result["data"]["indicators"].append(
                        f"Brand-related sender name detected: {brand}"
                    )

                    score += 8

                    break

            # ==========================================
            # SUSPICIOUS EMAIL PATTERNS
            # ==========================================

            suspicious_patterns = [

                "security-alert",
                "account-security",
                "verify-account",
                "account-verify",
                "support-team",
                "admin-team",
                "official-support",
                "customer-service"
            ]

            for pattern in suspicious_patterns:

                if pattern in email_address:

                    score += 10

                    result["data"]["indicators"].append(
                        f"Suspicious sender pattern detected: {pattern}"
                    )

                    break

            # ==========================================
            # EXCESSIVE SUBDOMAINS
            # ==========================================

            if domain:

                domain_parts = domain.split(".")

                if len(domain_parts) >= 4:

                    score += 10

                    result["data"]["indicators"].append(
                        "Sender domain contains many subdomains."
                    )

            # ==========================================
            # LIMIT SCORE
            # ==========================================

            score = min(score, 100)

            result["data"]["sender_score"] = score

            # ==========================================
            # RISK LEVEL
            # ==========================================

            if score < 25:

                risk_level = "LOW"

            elif score < 50:

                risk_level = "MEDIUM"

            elif score < 75:

                risk_level = "HIGH"

            else:

                risk_level = "CRITICAL"

            result["data"]["risk_level"] = risk_level

            # ==========================================
            # RECOMMENDATIONS
            # ==========================================

            if score >= 50:

                result["recommendations"].append(
                    "Verify the sender through an independent "
                    "trusted channel before interacting."
                )

            elif score >= 25:

                result["recommendations"].append(
                    "Exercise caution and verify the sender "
                    "before responding."
                )

            else:

                result["recommendations"].append(
                    "No major sender-level risk indicators detected."
                )

            if result["data"]["suspicious_tld"]:

                result["recommendations"].append(
                    "Check whether the sender domain belongs "
                    "to the claimed organization."
                )

            if result["data"]["brand_impersonation"]:

                result["recommendations"].append(
                    "Compare the sender domain with the "
                    "organization's official domain."
                )

        except Exception as error:

            result["status"] = "FAILED"

            result["warnings"].append(
                f"Sender analysis failed: {str(error)}"
            )

        return result


# ==========================================
# TEST
# ==========================================

if __name__ == "__main__":

    analyzer = SenderAnalyzer()

    examples = [

        "Google Security <security@google.com>",

        "PayPal Security <security-alert@paypal-secure.xyz>",

        "Microsoft Support <support-team@microsoft-login.top>",

        "John Smith <john.smith@gmail.com>",

        "Security Team <security@192.168.1.50>"
    ]

    for sender in examples:

        result = analyzer.analyze(sender)

        print("\n======================================")
        print("          SENDER ANALYZER")
        print("======================================")

        print("\nSender :", sender)

        print(
            "Display Name :",
            result["data"]["display_name"]
        )

        print(
            "Email :",
            result["data"]["email"]
        )

        print(
            "Domain :",
            result["data"]["domain"]
        )

        print(
            "Sender Score :",
            result["data"]["sender_score"],
            "/100"
        )

        print(
            "Risk Level :",
            result["data"]["risk_level"]
        )

        print(
            "Free Email Provider :",
            result["data"]["free_email_provider"]
        )

        print(
            "Suspicious TLD :",
            result["data"]["suspicious_tld"]
        )

        print(
            "IP Address Sender :",
            result["data"]["ip_address_sender"]
        )

        print(
            "Brand Impersonation :",
            result["data"]["brand_impersonation"]
        )

        print("\nIndicators:")

        for indicator in result["data"]["indicators"]:

            print("⚠", indicator)

        print("\nRecommendations:")

        for recommendation in result["recommendations"]:

            print("✔", recommendation) 