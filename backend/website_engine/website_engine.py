from url_analyzer import analyze_url
from whois_checker import WhoisChecker
from ssl_checker import SSLChecker
from dns_checker import DNSChecker
from keyword_checker import KeywordChecker
from threat_score import ThreatScoreEngine


class WebsiteEngine:

    def __init__(self):

        self.whois = WhoisChecker()
        self.ssl = SSLChecker()
        self.dns = DNSChecker()
        self.keyword = KeywordChecker()
        self.threat = ThreatScoreEngine()

    def analyze(self, url):

        print("\nAnalyzing URL...")

        url_report = analyze_url(url)

        whois_report = self.whois.analyze(url)

        ssl_report = self.ssl.analyze(url)

        dns_report = self.dns.analyze(url)

        keyword_report = self.keyword.analyze(url)

        final_report = self.threat.calculate([

            whois_report,

            ssl_report,

            dns_report,

            keyword_report

        ])

        return {

            "url_features": url_report,

            "whois": whois_report,

            "ssl": ssl_report,

            "dns": dns_report,

            "keywords": keyword_report,

            "final": final_report

        }


if __name__ == "__main__":

    engine = WebsiteEngine()

    url = "https://google.com"

    result = engine.analyze(url)

    print("\n================ FINAL REPORT ================\n")

    print("\n================ WEBSITE SECURITY REPORT ================\n")

print("URL")
print("--------------------------------------------")
print(url)

print("\nURL Features")
print("--------------------------------------------")

for key, value in result["url_features"].items():
    print(f"{key:25}: {value}")

print("\nWHOIS")
print("--------------------------------------------")

print(result["whois"])

print("\nSSL")
print("--------------------------------------------")

print(result["ssl"])

print("\nDNS")
print("--------------------------------------------")

print(result["dns"])

print("\nKeyword Analysis")
print("--------------------------------------------")

print(result["keywords"])

print("\nFINAL RESULT")
print("--------------------------------------------")

final = result["final"]

print(f"Threat Score    : {final['overall_score']}/100")
print(f"Security Level  : {final['security_level']}")
print(f"Verdict         : {final['verdict']}")

print("\nWarnings")

for warning in final["warnings"]:
    print(f"⚠ {warning}")

print("\nRecommendations")

for recommendation in final["recommendations"]:
    print(f"✔ {recommendation}")