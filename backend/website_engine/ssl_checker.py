"""
SSL/TLS Certificate Checker

FIX (ISSUE-002): Previous version assigned risk_score=100 on ANY SSL failure,
including simple timeouts on HTTP URLs. This produced massive false positives —
any site using HTTP would score PHISHING from SSL alone.

Revised thresholds:
  - SSL unavailable/timeout : risk_score = 15 (warning, not critical)
  - Certificate expired      : risk_score = 40
  - Expiring within 30 days  : risk_score = 15
  - Valid certificate        : risk_score = 0

A missing SSL certificate is a suspicious indicator but is NOT sufficient
on its own to classify a URL as phishing.
"""

import socket
import ssl
import ipaddress
from urllib.parse import urlparse
from datetime import datetime

# Private / reserved IP ranges that should not be contacted
_BLOCKED_IP_RANGES = [
    ipaddress.ip_network("127.0.0.0/8"),       # loopback
    ipaddress.ip_network("10.0.0.0/8"),         # private
    ipaddress.ip_network("172.16.0.0/12"),      # private
    ipaddress.ip_network("192.168.0.0/16"),     # private
    ipaddress.ip_network("169.254.0.0/16"),     # link-local
    ipaddress.ip_network("::1/128"),            # IPv6 loopback
]


def _is_private_ip(hostname: str) -> bool:
    """Return True if the resolved IP is private/loopback (SSRF guard)."""
    try:
        ip_str = socket.gethostbyname(hostname)
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in _BLOCKED_IP_RANGES)
    except Exception:
        return False


class SSLChecker:

    def __init__(self):
        pass

    def extract_domain(self, url: str) -> str:
        parsed = urlparse(url)
        netloc = parsed.netloc or url
        return netloc.split(":")[0].lower()

    def analyze(self, url: str) -> dict:
        domain = self.extract_domain(url)
        is_https = url.lower().startswith("https://")

        report = {
            "module": "SSL Checker",
            "status": "SUCCESS",
            "risk_score": 0,
            "security_level": "LOW",
            "data": {
                "ssl_checked": False,
                "ssl_available": False,
                "is_https": is_https,
                "issuer": None,
                "expiry_date": None,
                "days_remaining": None,
                "note": None,
            },
            "warnings": [],
            "recommendations": [],
        }

        # Non-HTTPS URLs: note it, assign small base score but don't fail
        if not is_https:
            report["risk_score"] = 10
            report["security_level"] = "LOW"
            report["data"]["note"] = "URL uses HTTP. SSL check skipped."
            report["warnings"].append(
                "URL does not use HTTPS. Data transmitted may not be encrypted."
            )
            return report

        # SSRF guard: don't connect to private IPs
        if _is_private_ip(domain):
            report["status"] = "BLOCKED"
            report["data"]["note"] = "SSL check blocked for private/internal IP."
            return report

        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()

                    issuer_dict = dict(x[0] for x in cert.get("issuer", []))
                    issuer = issuer_dict.get("organizationName", "Unknown")

                    not_after = cert.get("notAfter", "")
                    try:
                        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        days_left = (expiry - datetime.utcnow()).days
                    except Exception:
                        expiry = None
                        days_left = None

                    report["data"].update({
                        "ssl_checked": True,
                        "ssl_available": True,
                        "issuer": issuer,
                        "expiry_date": expiry.strftime("%Y-%m-%d") if expiry else None,
                        "days_remaining": days_left,
                    })

                    if days_left is not None and days_left < 0:
                        report["risk_score"] = 40
                        report["security_level"] = "HIGH"
                        report["warnings"].append("SSL certificate has expired.")
                        report["recommendations"].append(
                            "An expired certificate is a significant security risk."
                        )
                    elif days_left is not None and days_left < 30:
                        report["risk_score"] = 15
                        report["security_level"] = "LOW"
                        report["warnings"].append(
                            f"SSL certificate expires in {days_left} days."
                        )
                    else:
                        report["risk_score"] = 0
                        report["recommendations"].append(
                            "SSL certificate is valid. Note: a valid certificate does "
                            "not prove the site is legitimate."
                        )

        except ssl.SSLCertVerificationError:
            # Cert doesn't match hostname — moderately suspicious
            report["status"] = "FAILED"
            report["risk_score"] = 25
            report["security_level"] = "MEDIUM"
            report["data"].update({"ssl_checked": True, "ssl_available": False,
                                   "note": "SSL certificate validation failed."})
            report["warnings"].append(
                "SSL certificate could not be validated for this hostname."
            )

        except (socket.timeout, ConnectionRefusedError, OSError):
            # Cannot connect — not necessarily malicious (HTTP site, offline, etc.)
            report["status"] = "UNAVAILABLE"
            report["risk_score"] = 15
            report["security_level"] = "LOW"
            report["data"].update({"ssl_checked": True, "ssl_available": False,
                                   "note": "Could not connect to port 443."})
            report["warnings"].append(
                "SSL certificate could not be retrieved. The site may not support HTTPS."
            )

        except Exception as e:
            report["status"] = "UNAVAILABLE"
            report["risk_score"] = 10
            report["data"].update({"ssl_checked": True, "ssl_available": False,
                                   "note": f"SSL check error: {str(e)}"})

        return report


if __name__ == "__main__":
    checker = SSLChecker()
    for url in ["https://google.com", "http://example.com"]:
        r = checker.analyze(url)
        print(f"\n== SSL: {url} ==")
        print(f"  Score: {r['risk_score']}  Level: {r['security_level']}")
        for w in r["warnings"]:
            print(f"  WARNING: {w}")
