from .email_parser import EmailParser
from .keyword_analyzer import EmailKeywordAnalyzer
from .spam_analyzer import SpamAnalyzer
from .intent_classifier import IntentClassifier
from .email_threat_score import EmailThreatScoreEngine
from .sender_analyzer import SenderAnalyzer
from .link_analyzer import LinkAnalyzer

class EmailEngine:

    def __init__(self):
        self.parser = EmailParser()
        self.keyword_analyzer = EmailKeywordAnalyzer()
        self.spam_analyzer = SpamAnalyzer()
        self.intent_classifier = IntentClassifier()
        self.sender_analyzer = SenderAnalyzer()
        self.threat_engine = EmailThreatScoreEngine()
        self.link_analyzer = LinkAnalyzer()

    # ==========================================
    # ANALYZE EMAIL
    # ==========================================

    def analyze(self, raw_email):

        result = {
            "module": "Email Engine",
            "status": "SUCCESS",
            "email": {},
            "keyword_analysis": {},
            "spam_analysis": {},
            "intent_analysis": {},
            "sender_analysis": {},
            "threat_analysis": {},
            "warnings": [],
            "link_analysis": {},
            "recommendations": []
        }

        try:

            # ==========================================
            # STEP 1 — PARSE EMAIL
            # ==========================================

            parsed = self.parser.parse(raw_email)

            if parsed["status"] == "FAILED":

                result["status"] = "FAILED"

                result["warnings"].extend(
                    parsed.get("warnings", [])
                )

                result["recommendations"].extend(
                    parsed.get("recommendations", [])
                )

                return result

            email_data = parsed["data"]

            result["email"] = email_data

            # ==========================================
            # STEP 2 — KEYWORD ANALYSIS
            # ==========================================

            keyword_result = self.keyword_analyzer.analyze(
                subject=email_data.get("subject", ""),
                body=email_data.get("body", "")
            )

            result["keyword_analysis"] = keyword_result

            # ==========================================
            # STEP 3 — SPAM ANALYSIS
            # ==========================================

            spam_result = self.spam_analyzer.analyze(
                subject=email_data.get("subject", ""),
                body=email_data.get("body", ""),
                links=email_data.get("links", [])
            )

            result["spam_analysis"] = spam_result

            # ==========================================
            # STEP 4 — INTENT CLASSIFICATION
            # ==========================================

            intent_result = self.intent_classifier.classify(
                subject=email_data.get("subject", ""),
                body=email_data.get("body", "")
            )

            result["intent_analysis"] = intent_result

            # ==========================================
            # STEP 5 — SENDER ANALYSIS
            # ==========================================

            sender_result = self.sender_analyzer.analyze(
                sender=email_data.get("sender", "")
            )

            result["sender_analysis"] = sender_result

            link_result = self.link_analyzer.analyze(
                links=email_data.get("links", []),
                body=email_data.get("body", "")
            )

            result["link_analysis"] = link_result

            # ==========================================
            # STEP 6 — THREAT SCORE
            # ==========================================

            threat_result = self.threat_engine.calculate(
                keyword_result=keyword_result,
                spam_result=spam_result,
                email_data=email_data,
                sender_result=sender_result,
                link_result=link_result
            )

            result["threat_analysis"] = threat_result

            # ==========================================
            # COMBINE WARNINGS
            # ==========================================

            result["warnings"].extend(
                parsed.get("warnings", [])
            )

            result["warnings"].extend(
                keyword_result.get("warnings", [])
            )

            result["warnings"].extend(
                spam_result.get("warnings", [])
            )

            result["warnings"].extend(
                intent_result.get("warnings", [])
            )

            result["warnings"].extend(
                sender_result.get("warnings", [])
            )
            result["warnings"].extend(
                link_result.get("warnings", [])
            )

            # ==========================================
            # COMBINE RECOMMENDATIONS
            # ==========================================

            result["recommendations"].extend(
                parsed.get("recommendations", [])
            )

            result["recommendations"].extend(
                keyword_result.get("recommendations", [])
            )

            result["recommendations"].extend(
                spam_result.get("recommendations", [])
            )

            result["recommendations"].extend(
                intent_result.get("recommendations", [])
            )

            result["recommendations"].extend(
                sender_result.get("recommendations", [])
            )
            result["recommendations"].extend(
                link_result.get("recommendations", [])
            )
            # ==========================================
            # REMOVE DUPLICATE WARNINGS
            # ==========================================

            result["warnings"] = list(
                dict.fromkeys(result["warnings"])
            )

            # ==========================================
            # REMOVE DUPLICATE RECOMMENDATIONS
            # ==========================================

            result["recommendations"] = list(
                dict.fromkeys(result["recommendations"])
            )

        except Exception as error:

            result["status"] = "FAILED"

            result["warnings"].append(
                f"Email engine failed: {str(error)}"
            )

        return result


# ==========================================
# TEST
# ==========================================

if __name__ == "__main__":

    raw_email = """From: security@example.com
To: user@example.com
Subject: URGENT: Verify Your Account

Dear Customer,

Your account has been suspended due to unusual activity.

Please login and verify your account immediately.

Click here:

https://example.com/login

Thank you.
"""

    engine = EmailEngine()

    result = engine.analyze(raw_email)

    print("\n==========================================")
    print("           EMAIL ENGINE TEST")
    print("==========================================")

    print("\nStatus :", result["status"])

    # ==========================================
    # EMAIL
    # ==========================================

    print("\n========== EMAIL ==========")

    print(
        "Sender :",
        result["email"].get("sender")
    )

    print(
        "Subject :",
        result["email"].get("subject")
    )

    print(
        "Links :",
        result["email"].get("links")
    )

    # ==========================================
    # KEYWORD ANALYSIS
    # ==========================================

    print("\n========== KEYWORD ANALYSIS ==========")

    keyword_data = result["keyword_analysis"]["data"]

    print(
        "Phishing Keywords :",
        keyword_data["phishing_keywords"]
    )

    print(
        "Spam Keywords :",
        keyword_data["spam_keywords"]
    )

    print(
        "Advertisement Keywords :",
        keyword_data["advertisement_keywords"]
    )

    print(
        "Business Keywords :",
        keyword_data["business_keywords"]
    )

    print(
        "Transactional Keywords :",
        keyword_data["transactional_keywords"]
    )

    # ==========================================
    # SPAM ANALYSIS
    # ==========================================

    print("\n========== SPAM ANALYSIS ==========")

    spam_data = result["spam_analysis"]["data"]

    print(
        "Spam Score :",
        spam_data["spam_score"]
    )

    print(
        "Spam Level :",
        spam_data["spam_level"]
    )

    print(
        "Verdict :",
        spam_data["verdict"]
    )

    # ==========================================
    # INTENT ANALYSIS
    # ==========================================

    print("\n========== INTENT ANALYSIS ==========")

    intent_data = result["intent_analysis"]["data"]

    print(
        "Category :",
        intent_data["category"]
    )

    print(
        "Confidence :",
        intent_data["confidence"],
        "%"
    )

    print(
        "Scores :",
        intent_data["scores"]
    )

    # ==========================================
    # SENDER ANALYSIS
    # ==========================================

    print("\n========== SENDER ANALYSIS ==========")

    sender_data = result["sender_analysis"]["data"]

    print(
        "Display Name :",
        sender_data["display_name"]
    )

    print(
        "Email :",
        sender_data["email"]
    )

    print(
        "Domain :",
        sender_data["domain"]
    )

    print(
        "Sender Score :",
        sender_data["sender_score"],
        "/100"
    )

    print(
        "Risk Level :",
        sender_data["risk_level"]
    )

    print(
        "Free Email Provider :",
        sender_data["free_email_provider"]
    )

    print(
        "Suspicious TLD :",
        sender_data["suspicious_tld"]
    )

    print(
        "IP Address Sender :",
        sender_data["ip_address_sender"]
    )

    print(
        "Brand Impersonation :",
        sender_data["brand_impersonation"]
    )

    print("\nIndicators:")

    if sender_data["indicators"]:

        for indicator in sender_data["indicators"]:
            print("⚠", indicator)

    else:
        print("No sender indicators.")


    # ==========================================
    # LINK ANALYSIS
    # ==========================================

    print("\n========== LINK ANALYSIS ==========")

    link_data = result["link_analysis"]["data"]

    print(
        "Link Count :",
        link_data["link_count"]
    )

    print(
        "Highest Risk Score :",
        link_data["highest_risk_score"],
        "/100"
    )

    print(
        "Highest Risk Level :",
        link_data["highest_risk_level"]
    )

    print("\nLinks:")

    for link in link_data["links"]:

        print(
            "\nURL :",
            link["url"]
        )

        print(
            "Valid :",
            link["valid"]
        )

        print(
            "Score :",
            link["score"],
            "/100"
        )

        print(
            "Risk Level :",
            link["risk_level"]
        )

        if link["indicators"]:

            print("Indicators:")

            for indicator in link["indicators"]:

                print(
                    "  ⚠",
                    indicator
                )

        website = link.get("website_analysis")

        if website:

            print("\nWebsite AI Analysis:")

            if website.get("status") == "SUCCESS":

                ml = website.get(
                    "machine_learning",
                    {}
                )

                threat = website.get(
                    "threat_analysis",
                    {}
                )

                print(
                    "  ML Prediction :",
                    ml.get("prediction", "N/A")
                )

                print(
                    "  ML Confidence :",
                    ml.get("confidence", "N/A"),
                    "%"
                )

                print(
                    "  Threat Score  :",
                    threat.get("overall_score", "N/A"),
                    "/100"
                )

                print(
                    "  Security Level:",
                    threat.get("security_level", "N/A")
                )

                print(
                    "  Verdict       :",
                    threat.get("verdict", "N/A")
                )

            else:

                print(
                    "  Website analysis failed:",
                    website.get("error", "Unknown error")
                )

    # ==========================================
    # THREAT ANALYSIS
    # ==========================================

    print("\n========== THREAT ANALYSIS ==========")

    threat_data = result["threat_analysis"]["data"]

    print(
        "Overall Score :",
        threat_data["overall_score"],
        "/100"
    )

    print(
        "Security Level :",
        threat_data["security_level"]
    )

    print(
        "Verdict :",
        threat_data["verdict"]
    )

    print("\nScore Breakdown:")

    for key, value in threat_data["score_breakdown"].items():

        print(
            f"  {key} : +{value}"
        )

    # ==========================================
    # WARNINGS
    # ==========================================

    print("\n========== WARNINGS ==========")

    if result["warnings"]:

        for warning in result["warnings"]:
            print("⚠", warning)

    else:

        print("No warnings.")

    # ==========================================
    # RECOMMENDATIONS
    # ==========================================

    print("\n========== RECOMMENDATIONS ==========")

    if result["recommendations"]:

        for recommendation in result["recommendations"]:
            print("✔", recommendation)

    else:

        print("No recommendations.")