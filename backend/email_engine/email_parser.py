import re
from email import policy
from email.parser import Parser
from html import unescape
from urllib.parse import urlparse


class EmailParser:

    def __init__(self):
        pass

    def parse(self, raw_email):

        result = {
            "module": "Email Parser",
            "status": "SUCCESS",
            "data": {
                "sender": "",
                "recipient": "",
                "subject": "",
                "body": "",
                "links": [],
                "link_count": 0,
                "is_html": False,
                "attachments": []
            },
            "warnings": [],
            "recommendations": []
        }

        try:

            # Parse email
            message = Parser(policy=policy.default).parsestr(raw_email)

            sender = message.get("From", "")
            recipient = message.get("To", "")
            subject = message.get("Subject", "")

            body = ""
            is_html = False

            # ==========================
            # Extract Body
            # ==========================

            if message.is_multipart():

                for part in message.walk():

                    content_type = part.get_content_type()

                    if content_type == "text/plain":

                        try:
                            body += part.get_content()
                        except Exception:
                            pass

                    elif content_type == "text/html":

                        is_html = True

                        try:
                            html_body = part.get_content()

                            # Remove HTML tags
                            clean_body = re.sub(
                                r"<[^>]+>",
                                " ",
                                html_body
                            )

                            body += unescape(clean_body)

                        except Exception:
                            pass

                    # ==========================
                    # Attachments
                    # ==========================

                    if part.get_filename():

                        result["data"]["attachments"].append(
                            part.get_filename()
                        )

            else:

                content_type = message.get_content_type()

                try:

                    body = message.get_content()

                except Exception:

                    body = ""

                if content_type == "text/html":

                    is_html = True

                    body = re.sub(
                        r"<[^>]+>",
                        " ",
                        body
                    )

                    body = unescape(body)

            # ==========================
            # Extract URLs
            # ==========================

            combined_text = (
                subject + " " + body
            )

            urls = re.findall(
                r"https?://[^\s<>\"']+",
                combined_text
            )

            # Remove duplicates
            urls = list(dict.fromkeys(urls))

            # Clean URLs
            clean_urls = []

            for url in urls:

                url = url.rstrip(".,);]")

                try:

                    parsed = urlparse(url)

                    if parsed.netloc:

                        clean_urls.append(url)

                except Exception:

                    pass

            # ==========================
            # Final Data
            # ==========================

            result["data"]["sender"] = sender

            result["data"]["recipient"] = recipient

            result["data"]["subject"] = subject

            result["data"]["body"] = body.strip()

            result["data"]["links"] = clean_urls

            result["data"]["link_count"] = len(clean_urls)

            result["data"]["is_html"] = is_html

            # ==========================
            # Basic Warnings
            # ==========================

            if not sender:

                result["warnings"].append(
                    "Sender information is missing."
                )

            if not subject:

                result["warnings"].append(
                    "Email subject is missing."
                )

            if len(clean_urls) > 0:

                result["recommendations"].append(
                    "Verify all links before clicking them."
                )

            if len(result["data"]["attachments"]) > 0:

                result["recommendations"].append(
                    "Do not open attachments unless the sender is trusted."
                )

        except Exception as error:

            result["status"] = "FAILED"

            result["warnings"].append(
                f"Email parsing failed: {str(error)}"
            )

        return result


# ==========================================
# TEST
# ==========================================

if __name__ == "__main__":

    raw_email = """From: security@example.com
To: user@example.com
Subject: Urgent Account Verification

Dear Customer,

Your account requires verification.

Please login here:

https://example.com/login

Thank you.
"""

    parser = EmailParser()

    result = parser.parse(raw_email)

    print("\n======================================")
    print("       EMAIL PARSER TEST")
    print("======================================")

    print("\nStatus :", result["status"])

    print("\nSender :", result["data"]["sender"])

    print("Recipient :", result["data"]["recipient"])

    print("Subject :", result["data"]["subject"])

    print("Links :", result["data"]["links"])

    print("Link Count :", result["data"]["link_count"])

    print("HTML :", result["data"]["is_html"])

    print("Attachments :", result["data"]["attachments"])

    print("\nWarnings:")

    for warning in result["warnings"]:

        print("⚠", warning)

    print("\nRecommendations:")

    for recommendation in result["recommendations"]:

        print("✔", recommendation)