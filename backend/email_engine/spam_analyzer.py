import re


class SpamAnalyzer:

    def __init__(self):

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
            "exclusive offer",
            "claim now",
            "urgent",
            "hurry",
            "special offer",
            "get rich",
            "double your money",
            "investment opportunity",
        ]

        self.promotional_keywords = [
            "discount",
            "sale",
            "offer",
            "promo",
            "promotion",
            "coupon",
            "deal",
            "clearance",
            "flash sale",
            "% off",
            "save big",
            "shop now",
            "free shipping",
        ]

    # ==========================================
    # KEYWORD DETECTION
    # ==========================================

    def find_keywords(self, text, keywords):

        text = text.lower()

        matched = []

        for keyword in keywords:

            if keyword.lower() in text:
                matched.append(keyword)

        return list(dict.fromkeys(matched))

    # ==========================================
    # SPAM ANALYSIS
    # ==========================================

    def analyze(self, subject="", body="", links=None):

        result = {
            "module": "Spam Analyzer",
            "status": "SUCCESS",

            "data": {
                "spam_score": 0,
                "spam_level": "LOW",
                "verdict": "NOT SPAM",

                "spam_keywords": [],
                "promotional_keywords": [],

                "indicators": {
                    "excessive_caps": False,
                    "excessive_exclamation": False,
                    "excessive_special_characters": False,
                    "urgency": False,
                    "too_many_links": False,
                    "money_related": False
                }
            },

            "warnings": [],
            "recommendations": []
        }

        try:

            if links is None:
                links = []

            combined_text = f"{subject} {body}".strip()

            if not combined_text:

                result["status"] = "FAILED"

                result["warnings"].append(
                    "Email content is empty."
                )

                return result

            score = 0

            # ==========================================
            # 1. SPAM KEYWORDS
            # ==========================================

            spam_keywords = self.find_keywords(
                combined_text,
                self.spam_keywords
            )

            promotional_keywords = self.find_keywords(
                combined_text,
                self.promotional_keywords
            )

            result["data"]["spam_keywords"] = spam_keywords

            result["data"]["promotional_keywords"] = promotional_keywords

            # Each spam keyword = 5 points
            score += min(len(spam_keywords) * 5, 30)

            # Promotional keywords
            score += min(len(promotional_keywords) * 3, 15)

            # ==========================================
            # 2. EXCESSIVE CAPITALIZATION
            # ==========================================

            letters = re.findall(r"[A-Za-z]", combined_text)

            if len(letters) >= 20:

                uppercase_letters = re.findall(
                    r"[A-Z]",
                    combined_text
                )

                uppercase_ratio = (
                    len(uppercase_letters) / len(letters)
                )

                if uppercase_ratio > 0.40:

                    result["data"]["indicators"][
                        "excessive_caps"
                    ] = True

                    score += 10

                    result["warnings"].append(
                        "Excessive capitalization detected."
                    )

            # ==========================================
            # 3. EXCESSIVE EXCLAMATION MARKS
            # ==========================================

            exclamation_count = combined_text.count("!")

            if exclamation_count >= 3:

                result["data"]["indicators"][
                    "excessive_exclamation"
                ] = True

                score += 10

                result["warnings"].append(
                    "Excessive exclamation marks detected."
                )

            # ==========================================
            # 4. SPECIAL CHARACTERS
            # ==========================================

            special_characters = re.findall(
                r"[$%*#@!?]",
                combined_text
            )

            if len(special_characters) >= 8:

                result["data"]["indicators"][
                    "excessive_special_characters"
                ] = True

                score += 8

                result["warnings"].append(
                    "Excessive use of special characters detected."
                )

            # ==========================================
            # 5. URGENCY
            # ==========================================

            urgency_words = [
                "urgent",
                "immediately",
                "act now",
                "hurry",
                "right now",
                "last chance",
                "expires today",
                "final warning",
                "don't wait"
            ]

            urgency_matches = self.find_keywords(
                combined_text,
                urgency_words
            )

            if urgency_matches:

                result["data"]["indicators"][
                    "urgency"
                ] = True

                score += min(len(urgency_matches) * 5, 15)

                result["warnings"].append(
                    "Urgency-based language detected."
                )

            # ==========================================
            # 6. TOO MANY LINKS
            # ==========================================

            if len(links) >= 4:

                result["data"]["indicators"][
                    "too_many_links"
                ] = True

                score += 10

                result["warnings"].append(
                    "Multiple links detected in the email."
                )

            # ==========================================
            # 7. MONEY RELATED CONTENT
            # ==========================================

            money_patterns = [
                r"\$[\d,]+",
                r"₹[\d,]+",
                r"\b\d+\s*(?:usd|inr|dollars|rupees)\b",
                r"\bmoney\b",
                r"\bcash\b",
                r"\bprize\b",
                r"\bpayment\b"
            ]

            money_detected = False

            for pattern in money_patterns:

                if re.search(
                    pattern,
                    combined_text,
                    re.IGNORECASE
                ):

                    money_detected = True
                    break

            if money_detected:

                result["data"]["indicators"][
                    "money_related"
                ] = True

                score += 8

                result["warnings"].append(
                    "Money or financial language detected."
                )

            # ==========================================
            # LIMIT SCORE
            # ==========================================

            score = min(score, 100)

            result["data"]["spam_score"] = score

            # ==========================================
            # SPAM LEVEL
            # ==========================================

            if score < 25:

                result["data"]["spam_level"] = "LOW"
                result["data"]["verdict"] = "NOT SPAM"

            elif score < 50:

                result["data"]["spam_level"] = "MEDIUM"
                result["data"]["verdict"] = "POSSIBLE SPAM"

            elif score < 75:

                result["data"]["spam_level"] = "HIGH"
                result["data"]["verdict"] = "LIKELY SPAM"

            else:

                result["data"]["spam_level"] = "CRITICAL"
                result["data"]["verdict"] = "SPAM"

            # ==========================================
            # RECOMMENDATIONS
            # ==========================================

            if score >= 50:

                result["recommendations"].append(
                    "Avoid responding to this email "
                    "until the sender is verified."
                )

            if len(links) > 0 and score >= 25:

                result["recommendations"].append(
                    "Verify links before clicking them."
                )

            if result["data"]["indicators"]["money_related"]:

                result["recommendations"].append(
                    "Do not provide financial information "
                    "based solely on this email."
                )

        except Exception as error:

            result["status"] = "FAILED"

            result["warnings"].append(
                f"Spam analysis failed: {str(error)}"
            )

        return result


# ==========================================
# TEST
# ==========================================

if __name__ == "__main__":

    analyzer = SpamAnalyzer()

    examples = [

        {
            "subject": "CONGRATULATIONS!!! YOU WON $5000!!!",
            "body": """
            You are the lucky winner!
            Claim your cash prize NOW!!!
            Limited time offer.
            Click here immediately!!!
            """,
            "links": [
                "https://example.com/winner",
                "https://example.com/claim"
            ]
        },

        {
            "subject": "50% OFF - Flash Sale",
            "body": """
            Huge discount this weekend.
            Shop now and save big!
            Free shipping available.
            """,
            "links": [
                "https://example.com/shop"
            ]
        },

        {
            "subject": "Project Meeting Tomorrow",
            "body": """
            Hi team,

            Our project meeting is scheduled for tomorrow
            at 10 AM.

            Regards,
            Manager
            """,
            "links": []
        }
    ]

    for email in examples:

        result = analyzer.analyze(
            subject=email["subject"],
            body=email["body"],
            links=email["links"]
        )

        print("\n======================================")
        print("          SPAM ANALYZER TEST")
        print("======================================")

        print("\nSubject :", email["subject"])

        print(
            "Spam Score :",
            result["data"]["spam_score"]
        )

        print(
            "Spam Level :",
            result["data"]["spam_level"]
        )

        print(
            "Verdict :",
            result["data"]["verdict"]
        )

        print(
            "\nSpam Keywords :",
            result["data"]["spam_keywords"]
        )

        print(
            "Promotional Keywords :",
            result["data"]["promotional_keywords"]
        )

        print("\nIndicators :")

        for key, value in result["data"]["indicators"].items():

            print(f"  {key} : {value}")

        print("\nWarnings:")

        for warning in result["warnings"]:
            print("⚠", warning)

        print("\nRecommendations:")

        for recommendation in result["recommendations"]:
            print("✔", recommendation)