class IntentClassifier:

    def __init__(self):

        self.category_keywords = {

            "BUSINESS": [
                "meeting",
                "invoice",
                "contract",
                "proposal",
                "project",
                "deadline",
                "client",
                "agenda",
                "report",
                "schedule a call",
                "attached is",
                "please find attached",
                "regards",
                "team",
                "quarterly",
                "budget",
                "colleague"
            ],

            "ADVERTISEMENT": [
                "% off",
                "discount",
                "sale",
                "buy now",
                "shop now",
                "limited time",
                "deal",
                "promo code",
                "coupon",
                "clearance",
                "flash sale",
                "save big"
            ],

            "PROMOTIONAL": [
                "newsletter",
                "new arrivals",
                "loyalty",
                "rewards program",
                "subscribe",
                "you're invited",
                "webinar",
                "join us",
                "our latest",
                "check out our",
                "membership"
            ],

            "PERSONAL": [
                "hey",
                "hi there",
                "how are you",
                "long time no see",
                "miss you",
                "catch up",
                "birthday",
                "dinner",
                "weekend plans",
                "love,",
                "family"
            ],

            "NOTIFICATION": [
                "password reset",
                "login attempt",
                "verify your account",
                "your otp",
                "one-time code",
                "account alert",
                "security alert",
                "sign-in",
                "two-factor",
                "confirm your email"
            ],

            "TRANSACTIONAL": [
                "order confirmation",
                "receipt",
                "invoice number",
                "your order has shipped",
                "tracking number",
                "payment received",
                "purchase confirmation",
                "delivery",
                "billing statement",
                "amount due",
                "total:"
            ]
        }

    # ==========================================
    # FIND MATCHING KEYWORDS
    # ==========================================

    def find_keywords(self, text, keywords):

        text = text.lower()

        matched = []

        for keyword in keywords:

            if keyword.lower() in text:
                matched.append(keyword)

        return list(dict.fromkeys(matched))

    # ==========================================
    # CLASSIFY EMAIL
    # ==========================================

    def classify(self, subject="", body=""):

        result = {

            "module": "Intent Classifier",

            "status": "SUCCESS",

            "data": {
                "category": "UNKNOWN",
                "confidence": 0.0,
                "scores": {},
                "matched_keywords": {}
            },

            "warnings": [],
            "recommendations": []
        }

        try:

            combined_text = f"{subject} {body}".strip().lower()

            if not combined_text:

                result["status"] = "FAILED"

                result["warnings"].append(
                    "Email content is empty."
                )

                return result

            scores = {}
            matched_keywords = {}

            # ==========================================
            # CHECK EVERY CATEGORY
            # ==========================================

            for category, keywords in self.category_keywords.items():

                hits = self.find_keywords(
                    combined_text,
                    keywords
                )

                if hits:

                    scores[category] = len(hits)

                    matched_keywords[category] = hits

            result["data"]["scores"] = scores

            result["data"]["matched_keywords"] = matched_keywords

            # ==========================================
            # NOTHING FOUND
            # ==========================================

            if not scores:

                result["data"]["category"] = "UNKNOWN"

                result["data"]["confidence"] = 0.0

                result["warnings"].append(
                    "No clear intent indicators detected."
                )

                return result

            # ==========================================
            # SORT CATEGORIES
            # ==========================================

            sorted_categories = sorted(
                scores.items(),
                key=lambda item: item[1],
                reverse=True
            )

            top_category = sorted_categories[0][0]
            top_score = sorted_categories[0][1]

            total_hits = sum(scores.values())

            confidence = round(
                (top_score / total_hits) * 100,
                1
            )

            # ==========================================
            # CHECK TIE
            # ==========================================

            if len(sorted_categories) > 1:

                second_score = sorted_categories[1][1]

                if top_score == second_score:

                    result["warnings"].append(
                        "Multiple email intents have equal scores."
                    )

            # ==========================================
            # SET RESULT
            # ==========================================

            result["data"]["category"] = top_category

            result["data"]["confidence"] = confidence

            # ==========================================
            # LOW CONFIDENCE
            # ==========================================

            if confidence < 40:

                result["warnings"].append(
                    "Low confidence classification. "
                    "Email may contain multiple intents."
                )

            # ==========================================
            # RECOMMENDATIONS
            # ==========================================

            if top_category == "ADVERTISEMENT":

                result["recommendations"].append(
                    "This email appears to contain advertising content."
                )

            elif top_category == "PROMOTIONAL":

                result["recommendations"].append(
                    "This email appears to contain promotional content."
                )

            elif top_category == "BUSINESS":

                result["recommendations"].append(
                    "This email appears to be business-related."
                )

            elif top_category == "TRANSACTIONAL":

                result["recommendations"].append(
                    "This email appears to be related to a transaction."
                )

            elif top_category == "NOTIFICATION":

                result["recommendations"].append(
                    "This email appears to be an automated notification."
                )

            elif top_category == "PERSONAL":

                result["recommendations"].append(
                    "This email appears to be personal communication."
                )

        except Exception as error:

            result["status"] = "FAILED"

            result["warnings"].append(
                f"Intent classification failed: {str(error)}"
            )

        return result


# ==========================================
# TEST
# ==========================================

if __name__ == "__main__":

    classifier = IntentClassifier()

    examples = [

        (
            "Your order has shipped",
            "Your order #1234 has shipped. "
            "Tracking number: XYZ789."
        ),

        (
            "50% OFF Everything - Shop Now!!!",
            "Huge discounts this weekend only. "
            "Shop now to save big."
        ),

        (
            "Quarterly project update",
            "Hi team, please find attached the report "
            "for the quarterly review meeting."
        ),

        (
            "Password reset requested",
            "We received a login attempt. "
            "Verify your account or reset your password."
        ),

        (
            "Hey, long time no see!",
            "How are you? We should catch up this weekend, "
            "maybe dinner?"
        ),

        (
            "Weekly Newsletter",
            "Check out our latest products and new arrivals. "
            "Subscribe to our newsletter."
        )
    ]

    for subject, body in examples:

        result = classifier.classify(
            subject=subject,
            body=body
        )

        print("\n======================================")
        print("         INTENT CLASSIFIER")
        print("======================================")

        print("\nSubject :", subject)

        print(
            "Category :",
            result["data"]["category"]
        )

        print(
            "Confidence :",
            result["data"]["confidence"],
            "%"
        )

        print(
            "Scores :",
            result["data"]["scores"]
        )

        print(
            "Matched Keywords :",
            result["data"]["matched_keywords"]
        )

        if result["warnings"]:

            print("\nWarnings:")

            for warning in result["warnings"]:
                print("⚠", warning)

        if result["recommendations"]:

            print("\nRecommendations:")

            for recommendation in result["recommendations"]:
                print("✔", recommendation)