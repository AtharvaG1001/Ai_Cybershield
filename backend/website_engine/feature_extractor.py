from urllib.parse import urlparse
import math
import re
from collections import Counter

def get_url_length(url):
    return len(url)

def get_domain_length(url):
    domain = urlparse(url).netloc
    return len(domain)

def count_dots(url):
    return url.count(".")

def count_hyphens(url):
    return url.count("-")

def count_digits(url):
    return sum(char.isdigit() for char in url)

def has_https(url):
    return url.startswith("https://")

def has_ip_address(url):
    pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    return bool(re.search(pattern, url))

def count_at_symbol(url):
    return url.count("@")

def count_subdomains(url):
    domain = urlparse(url).netloc
    return max(0, domain.count(".") - 1)

def calculate_entropy(text):

    if not text:
        return 0

    counter = Counter(text)

    length = len(text)

    entropy = 0

    for count in counter.values():

        probability = count / length

        entropy -= probability * math.log2(probability)

    return round(entropy, 3)

def url_depth(url):

    path = urlparse(url).path

    return path.count("/")

def path_length(url):

    return len(urlparse(url).path)

def query_length(url):

    return len(urlparse(url).query)

def count_letters(url):

    return sum(c.isalpha() for c in url)

def count_special(url):

    return len(re.findall(r"[^a-zA-Z0-9]", url))

def count_tilde(url):
    return url.count("~")

def count_comma(url):
    return url.count(",")

def count_colon(url):
    return url.count(":")

def count_semicolon(url):
    return url.count(";")

def has_port(url):
    return int(urlparse(url).port is not None)
def suspicious_tld(url):

    suspicious = [

        ".xyz",
        ".top",
        ".club",
        ".click",
        ".gq",
        ".tk",
        ".cf",
        ".ml",
        ".ga",
        ".work"

    ]

    domain = urlparse(url).netloc.lower()

    return int(any(domain.endswith(tld) for tld in suspicious))

def path_segments(url):
    path = urlparse(url).path
    return len([x for x in path.split("/") if x])

def count_parentheses(url):
    return url.count("(") + url.count(")")

def count_star(url):
    return url.count("*")

def count_plus(url):
    return url.count("+")

def count_exclamation(url):
    return url.count("!")

def count_dollar(url):
    return url.count("$")

import re

def average_word_length(url):

    words = re.findall(r"[A-Za-z]+", url)

    if not words:
        return 0

    return round(sum(len(w) for w in words) / len(words), 2)

def longest_word(url):

    words = re.findall(r"[A-Za-z]+", url)

    if not words:
        return 0

    return max(len(w) for w in words)

