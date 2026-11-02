import re


class EmailKeywordAnalyzer:

    def __init__(self):

        self.phishing_keywords = [
            "verify your account",
            "verify account",
            "account verification",
            "confirm your account",
            "confirm account",
            "account suspended",
            "account blocked",
            "account locked",
            "urgent action",
            "immediate action",
            "login",
            "log in",
            "password",
            "reset password",
            "update password",
            "security alert",
            "unusual activity",
            "suspicious activity",
            "click here",
            "verify now",
            "confirm now",
            "limited time",
            "your account",
            "payment failed",
            "payment declined",
            "refund",
            "claim your",
            "winner",
            "congratulations"
        ]

        self.spam_keywords = [
            "free",
            "winner",
            "congratulations",
            "you have won",
            "cash prize",
            "earn money",
            "make money",
            "work from home",
            "act now",
            "buy now",
            "click here",
            "limited time",
            "guaranteed",
            "risk free",
            "no investment",
            "cheap",
            "exclusive offer"
        ]

        self.advertisement_keywords = [
            "sale",
            "discount",
            "offer",
            "special offer",
            "promo",
            "promotion",
            "coupon",
            "deal",
            "deals",
            "buy now",
            "shop now",
            "limited time",
            "save",
            "off",
            "free shipping",
            "exclusive"
        ]

        self.business_keywords = [
            "meeting",
            "project",
            "invoice",
            "contract",
            "proposal",
            "company",
            "business",
            "client",
            "customer",
            "employee",
            "manager",
            "department",
            "quotation",
            "purchase order",
            "agreement",
            "deadline",
            "schedule"
        ]

        self.transactional_keywords = [
            "payment",
            "transaction",
            "receipt",
            "order",
            "order confirmation",
            "shipping",
            "delivery",
            "subscription",
            "billing",
            "invoice",
            "refund",
            "purchase",
            "booking",
            "reservation"
        ]

    def _find_keywords(self, text, keywords):

        text = text.lower()

        matched = []

        for keyword in keywords:

            if keyword.lower() in text:
                matched.append(keyword)

        return list(dict.fromkeys(matched))

    def analyze(self, subject="", body=""):

        result = {
            "module": "Email Keyword Analyzer",
            "status": "SUCCESS",
            "data": {
                "phishing_keywords": [],
                "spam_keywords": [],
                "advertisement_keywords": [],
                "business_keywords": [],
                "transactional_keywords": [],
                "phishing_count": 0,
                "spam_count": 0,
                "advertisement_count": 0,
                "business_count": 0,
                "transactional_count": 0
            },
            "warnings": [],
            "recommendations": []
        }

        try:

            text = f"{subject} {body}".strip()

            if not text:

                result["status"] = "FAILED"
                result["warnings"].append(
                    "Email content is empty."
                )

                return result

            phishing = self._find_keywords(
                text,
                self.phishing_keywords
            )

            spam = self._find_keywords(
                text,
                self.spam_keywords
            )

            advertisement = self._find_keywords(
                text,
                self.advertisement_keywords
            )

            business = self._find_keywords(
                text,
                self.business_keywords
            )

            transactional = self._find_keywords(
                text,
                self.transactional_keywords
            )

            result["data"]["phishing_keywords"] = phishing
            result["data"]["spam_keywords"] = spam
            result["data"]["advertisement_keywords"] = advertisement
            result["data"]["business_keywords"] = business
            result["data"]["transactional_keywords"] = transactional

            result["data"]["phishing_count"] = len(phishing)
            result["data"]["spam_count"] = len(spam)
            result["data"]["advertisement_count"] = len(advertisement)
            result["data"]["business_count"] = len(business)
            result["data"]["transactional_count"] = len(transactional)

            if phishing:

                result["warnings"].append(
                    f"Potential phishing language detected: "
                    f"{len(phishing)} indicator(s)."
                )

                result["recommendations"].append(
                    "Do not click links or provide sensitive information "
                    "until the email is verified."
                )

            if spam:

                result["warnings"].append(
                    f"Spam indicators detected: {len(spam)}."
                )

            if advertisement:

                result["recommendations"].append(
                    "This email contains promotional or advertisement "
                    "language."
                )

            if business:

                result["recommendations"].append(
                    "Business-related language detected."
                )

            if transactional:

                result["recommendations"].append(
                    "Transactional activity detected."
                )

        except Exception as error:

            result["status"] = "FAILED"

            result["warnings"].append(
                f"Keyword analysis failed: {str(error)}"
            )

        return result


if __name__ == "__main__":

    subject = "URGENT: Verify Your Account"

    body = """
    Your account has been suspended due to unusual activity.

    Please login and verify your account immediately:

    https://example.com/login

    """

    analyzer = EmailKeywordAnalyzer()

    result = analyzer.analyze(
        subject,
        body
    )

    print("\n======================================")
    print("       EMAIL KEYWORD ANALYZER")
    print("======================================")

    print("\nStatus :", result["status"])

    print("\nPhishing Keywords :")
    print(result["data"]["phishing_keywords"])

    print("\nSpam Keywords :")
    print(result["data"]["spam_keywords"])

    print("\nAdvertisement Keywords :")
    print(result["data"]["advertisement_keywords"])

    print("\nBusiness Keywords :")
    print(result["data"]["business_keywords"])

    print("\nTransactional Keywords :")
    print(result["data"]["transactional_keywords"])

    print("\nCounts:")
    print("Phishing       :", result["data"]["phishing_count"])
    print("Spam           :", result["data"]["spam_count"])
    print("Advertisement  :", result["data"]["advertisement_count"])
    print("Business       :", result["data"]["business_count"])
    print("Transactional  :", result["data"]["transactional_count"])

    print("\nWarnings:")

    for warning in result["warnings"]:
        print("⚠", warning)

    print("\nRecommendations:")

    for recommendation in result["recommendations"]:
        print("✔", recommendation)