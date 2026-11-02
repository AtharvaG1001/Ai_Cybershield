import dns.resolver
from urllib.parse import urlparse


class DNSChecker:

    def __init__(self):
        pass

    def extract_domain(self, url):
        return urlparse(url).netloc

    def get_records(self, domain, record_type):

        try:
            answers = dns.resolver.resolve(domain, record_type)

            return [str(r) for r in answers]

        except Exception:
            return []

    def analyze(self, url):

        domain = self.extract_domain(url)

        a_records = self.get_records(domain, "A")
        mx_records = self.get_records(domain, "MX")
        ns_records = self.get_records(domain, "NS")

        report = {
            "module": "DNS Checker",
            "status": "SUCCESS",
            "risk_score": 0,
            "security_level": "LOW",
            "data": {
                "A Records": a_records,
                "MX Records": mx_records,
                "NS Records": ns_records
            },
            "warnings": [],
            "recommendations": []
        }

        if len(a_records) == 0:
            report["risk_score"] += 40
            report["warnings"].append("No A Record found.")

        if len(mx_records) == 0:
            report["warnings"].append("No MX Record found.")

        if len(ns_records) == 0:
            
            report["warnings"].append("No Name Servers found.")

        if report["risk_score"] == 0:
            report["security_level"] = "LOW"

        elif report["risk_score"] < 50:
            report["security_level"] = "MEDIUM"

        else:
            report["security_level"] = "HIGH"

        if report["risk_score"] > 0:
            report["recommendations"].append(
                "Verify the website before sharing sensitive information."
            )

        return report


if __name__ == "__main__":

    checker = DNSChecker()

    url = "https://this-domain-does-not-exist-123456.com"

    result = checker.analyze(url)

    print("\n========== DNS SECURITY REPORT ==========\n")

    print(f"Module          : {result['module']}")
    print(f"Status          : {result['status']}")
    print(f"Risk Score      : {result['risk_score']}")
    print(f"Security Level  : {result['security_level']}")

    print("\nDNS Records")

    for key, value in result["data"].items():
        print(f"\n{key}")
        if value:
            for item in value:
                print(f"  • {item}")
        else:
            print("  None")

    if result["warnings"]:
        print("\nWarnings")
        for warning in result["warnings"]:
            print(f"⚠ {warning}")

    if result["recommendations"]:
        print("\nRecommendations")
        for recommendation in result["recommendations"]:
            print(f"✔ {recommendation}")
