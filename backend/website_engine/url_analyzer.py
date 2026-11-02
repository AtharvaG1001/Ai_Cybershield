from .feature_extractor import *

def analyze_url(url):

    features = {

        # Basic Features
        "url_length": get_url_length(url),
        "domain_length": get_domain_length(url),
        "path_length": path_length(url),
        "query_length": query_length(url),

        # Character Counts
        "dots": count_dots(url),
        "hyphens": count_hyphens(url),
        "underscores": url.count("_"),
        "slashes": url.count("/"),
        "digits": count_digits(url),
        "letters": count_letters(url),
        "special_characters": count_special(url),

        # URL Symbols
        "at_symbols": count_at_symbol(url),
        "question_marks": url.count("?"),
        "equal_symbols": url.count("="),
        "ampersands": url.count("&"),
        "percent_symbols": url.count("%"),

        # URL Properties
        "subdomains": count_subdomains(url),
        "https": int(has_https(url)),
        "ip_address": int(has_ip_address(url)),

        # Advanced Features
        "url_depth": url_depth(url),
        "entropy": calculate_entropy(url),

        "tilde": count_tilde(url),
"comma": count_comma(url),
"colon": count_colon(url),
"semicolon": count_semicolon(url),
"dollar": count_dollar(url),
"exclamation": count_exclamation(url),
"plus": count_plus(url),
"star": count_star(url),
"parentheses": count_parentheses(url),

"has_port": has_port(url),
"path_segments": path_segments(url),
"average_word_length": average_word_length(url),
"longest_word": longest_word(url),
"suspicious_tld": suspicious_tld(url),

    }

    return features

    


if __name__ == "__main__":
    url = input("Enter URL: ")

    result = analyze_url(url)

    print("\nExtracted Features:\n")

    for key, value in result.items():
        print(f"{key:25}: {value}")