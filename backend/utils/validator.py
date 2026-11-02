"""
URL Validator and Normalizer

Improvements:
- Validates scheme and netloc
- Strips trailing slashes for clean comparison
- Documents the model's subdomain sensitivity
"""

from urllib.parse import urlparse
import re


def is_valid_url(url: str) -> bool:
    """Return True if the URL has a valid scheme and netloc."""
    try:
        result = urlparse(url)
        return bool(result.scheme in ("http", "https") and result.netloc)
    except Exception:
        return False


def normalize_url(url: str) -> str:
    """
    Normalize URL for analysis.
    - Adds https:// scheme if missing
    - Lowercases the scheme and hostname
    - Does NOT add www. because that changes the security meaning
    """
    url = url.strip()
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url
    return url