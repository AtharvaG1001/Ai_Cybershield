
class EmailThreatScoreEngine:

    def __init__(self):
        pass

    # ==========================================
    # CALCULATE THREAT SCORE
    # ==========================================

    def calculate(
        self,
        keyword_result,
        spam_result,
        email_data,
        sender_result=None,
        link_result=None
    ):

        result = {
            "module": "Email Threat Score",
            "status": "SUCCESS",
            "data": {
                "overall_score": 0,
                "security_level": "LOW",
                "verdict": "SAFE",
                "score_breakdown": {}
            },
            "warnings": [],
            "recommendations": []
        }

        try:

            total_score = 0

            # =====================================================
            # 1. PHISHING KEYWORDS
            # =====================================================

            phishing_count = keyword_result.get(
                "data", {}
            ).get(
                "phishing_count",
                0
            )

            phishing_score = min(
                phishing_count * 8,
                35
            )

            total_score += phishing_score

            result["data"]["score_breakdown"][
                "Phishing Keywords"
            ] = phishing_score


            # =====================================================
            # 2. SPAM SCORE
            # =====================================================

            spam_score = spam_result.get(
                "data",
                {}
            ).get(
                "spam_score",
                0
            )

            spam_contribution = min(
                round(spam_score * 0.25),
                20
            )

            total_score += spam_contribution

            result["data"]["score_breakdown"][
                "Spam"
            ] = spam_contribution


            # =====================================================
            # 3. EMAIL LINKS
            # =====================================================

            links = email_data.get(
                "links",
                []
            )

            link_count = len(links)

            if link_count == 0:

                link_score = 0

            elif link_count == 1:

                link_score = 5

            elif link_count <= 3:

                link_score = 10

            else:

                link_score = 15


            total_score += link_score

            result["data"]["score_breakdown"][
                "Email Links"
            ] = link_score


            # =====================================================
            # 4. ATTACHMENTS
            # =====================================================

            attachments = email_data.get(
                "attachments",
                []
            )

            attachment_count = len(
                attachments
            )

            if attachment_count == 0:

                attachment_score = 0

            elif attachment_count == 1:

                attachment_score = 5

            else:

                attachment_score = 10


            total_score += attachment_score

            result["data"]["score_breakdown"][
                "Attachments"
            ] = attachment_score


            # =====================================================
            # 5. HTML EMAIL
            # =====================================================

            if email_data.get(
                "is_html",
                False
            ):

                html_score = 3

            else:

                html_score = 0


            total_score += html_score

            result["data"]["score_breakdown"][
                "HTML"
            ] = html_score


            # =====================================================
            # 6. SENDER ANALYSIS
            # =====================================================

            sender_score = 0

            if sender_result:

                sender_score = sender_result.get(
                    "data",
                    {}
                ).get(
                    "sender_score",
                    0
                )

                sender_score = min(
                    sender_score,
                    20
                )


            total_score += sender_score

            result["data"]["score_breakdown"][
                "Sender Risk"
            ] = sender_score


            # =====================================================
            # 7. WEBSITE LINK RISK
            # =====================================================

            website_link_score = 0
            highest_website_score = 0

            if link_result:

                link_data = link_result.get(
                    "data",
                    {}
                )

                analyzed_links = link_data.get(
                    "links",
                    []
                )

                for link in analyzed_links:

                    website_analysis = link.get(
                        "website_analysis"
                    )

                    if not website_analysis:
                        continue

                    if website_analysis.get(
                        "status"
                    ) != "SUCCESS":
                        continue

                    threat_analysis = website_analysis.get(
                        "threat_analysis",
                        {}
                    )

                    website_score = threat_analysis.get(
                        "overall_score",
                        0
                    )

                    if website_score > highest_website_score:

                        highest_website_score = website_score


                # -------------------------------------------------
                # Convert highest website risk into email risk
                # -------------------------------------------------

                if highest_website_score >= 75:

                    website_link_score = 25

                elif highest_website_score >= 50:

                    website_link_score = 20

                elif highest_website_score >= 25:

                    website_link_score = 10

                else:

                    website_link_score = 0


            total_score += website_link_score

            result["data"]["score_breakdown"][
                "Website Link Risk"
            ] = website_link_score


            # =====================================================
            # FINAL SCORE
            # =====================================================

            total_score = min(
                total_score,
                100
            )

            result["data"]["overall_score"] = (
                total_score
            )


            # =====================================================
            # SECURITY LEVEL
            # =====================================================

            if total_score < 25:

                security_level = "LOW"

            elif total_score < 50:

                security_level = "MEDIUM"

            elif total_score < 75:

                security_level = "HIGH"

            else:

                security_level = "CRITICAL"


            result["data"]["security_level"] = (
                security_level
            )


            # =====================================================
            # VERDICT
            # =====================================================

            if total_score < 25:

                verdict = "SAFE"

            elif total_score < 50:

                verdict = "SUSPICIOUS"

            elif total_score < 75:

                verdict = "LIKELY PHISHING"

            else:

                verdict = "PHISHING"


            result["data"]["verdict"] = verdict


            # =====================================================
            # WARNINGS
            # =====================================================

            if highest_website_score >= 75:

                result["warnings"].append(
                    "A linked website was classified as "
                    "critical risk by the Website AI Engine."
                )

            elif highest_website_score >= 50:

                result["warnings"].append(
                    "A linked website was classified as "
                    "high risk by the Website AI Engine."
                )

            elif highest_website_score >= 25:

                result["warnings"].append(
                    "A linked website showed suspicious "
                    "risk indicators."
                )


            # =====================================================
            # RECOMMENDATIONS
            # =====================================================

            if verdict == "PHISHING":

                result["recommendations"].append(
                    "Do not click links, open attachments, "
                    "or provide sensitive information."
                )

            elif verdict == "LIKELY PHISHING":

                result["recommendations"].append(
                    "Treat this email as high risk and "
                    "verify it through an independent source."
                )

            elif verdict == "SUSPICIOUS":

                result["recommendations"].append(
                    "Exercise caution and verify the sender "
                    "and links before interacting."
                )

            else:

                result["recommendations"].append(
                    "No major email-level security concerns detected."
                )


        except Exception as error:

            result["status"] = "FAILED"

            result["warnings"].append(
                f"Threat score calculation failed: {str(error)}"
            )


        return result


# ==========================================
# TEST
# ==========================================

if __name__ == "__main__":

    engine = EmailThreatScoreEngine()

    # Simulated keyword analyzer output

    keyword_result = {

        "data": {
            "phishing_count": 4
        }
    }

    # Simulated spam analyzer output

    spam_result = {

        "data": {
            "spam_score": 30
        }
    }

    # Simulated parsed email

    email_data = {

        "links": [
            "https://example.com/login"
        ],

        "attachments": [],

        "is_html": False
    }

    result = engine.calculate(
        keyword_result,
        spam_result,
        email_data
    )

    print("\n==========================================")
    print("       EMAIL THREAT SCORE TEST")
    print("==========================================")

    print(
        "\nOverall Score :",
        result["data"]["overall_score"],
        "/100"
    )

    print(
        "Security Level :",
        result["data"]["security_level"]
    )

    print(
        "Verdict :",
        result["data"]["verdict"]
    )

    print("\nScore Breakdown:")

    for key, value in result["data"][
        "score_breakdown"
    ].items():

        print(
            f"  {key} : +{value}"
        )

    print("\nWarnings:")

    for warning in result["warnings"]:

        print("⚠", warning)

    print("\nRecommendations:")

    for recommendation in result["recommendations"]:

        print("✔", recommendation)

