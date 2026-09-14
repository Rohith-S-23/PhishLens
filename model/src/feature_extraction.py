import re
import tldextract
from urllib.parse import urlparse


FEATURES = [
    "URLLength",
    "DomainLength",
    "IsDomainIP",
    "URLSimilarityIndex",
    "CharContinuationRate",
    "TLDLegitimateProb",
    "URLCharProb",
    "TLDLength",
    "NoOfSubDomain",
    "HasObfuscation",
    "NoOfObfuscatedChar",
    "ObfuscationRatio",
    "NoOfLettersInURL",
    "LetterRatioInURL",
    "NoOfDegitsInURL",
    "DegitRatioInURL",
    "NoOfEqualsInURL",
    "NoOfQMarkInURL",
    "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL",
    "SpacialCharRatioInURL",
    "IsHTTPS"
]


def extract_features(url):

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)

    domain = parsed.netloc
    path_query = parsed.path + "?" + parsed.query

    # Remove port number
    hostname = parsed.hostname or ""

    # TLD information
    extracted = tldextract.extract(url)

    tld = extracted.suffix
    subdomain = extracted.subdomain

    # Basic URL statistics
    url_length = len(url)
    domain_length = len(hostname)

    # IP address detection
    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"
    is_domain_ip = int(bool(re.match(ip_pattern, hostname)))

    # URL similarity
    # Dataset-specific feature; use a neutral baseline for live URLs.
    url_similarity = 50.0

    # Character continuation rate
    letters_digits = sum(c.isalnum() for c in url)

    if len(url) > 0:
        char_continuation_rate = letters_digits / len(url)
    else:
        char_continuation_rate = 0

    # TLD probability
    # Dataset-specific feature; baseline value.
    tld_legitimate_prob = 0.5

    # Character probability
    # Dataset-specific feature; baseline value.
    url_char_prob = 0.5

    # TLD length
    tld_length = len(tld)

    # Number of subdomains
    if subdomain:
        no_of_subdomain = len(subdomain.split("."))
    else:
        no_of_subdomain = 0

    # Obfuscation detection
    obfuscation_chars = "@%$^*|\\"

    obfuscated_chars = sum(
        1 for c in url if c in obfuscation_chars
    )

    has_obfuscation = int(obfuscated_chars > 0)

    if len(url) > 0:
        obfuscation_ratio = obfuscated_chars / len(url)
    else:
        obfuscation_ratio = 0

    # Letters
    no_of_letters = sum(c.isalpha() for c in url)

    if len(url) > 0:
        letter_ratio = no_of_letters / len(url)
    else:
        letter_ratio = 0

    # Digits
    no_of_digits = sum(c.isdigit() for c in url)

    if len(url) > 0:
        digit_ratio = no_of_digits / len(url)
    else:
        digit_ratio = 0

    # Special URL characters
    no_of_equals = url.count("=")
    no_of_qmark = url.count("?")
    no_of_ampersand = url.count("&")

    # Other special characters
    special_chars = [
        "!", '"', "#", "$", "%",
        "'", "(", ")", "*",
        "+", ",", "-", ".", "/",
        ":", ";", "<", ">",
        "@", "[", "]", "^",
        "_", "`", "{", "|", "}",
        "~"
    ]

    no_of_other_special = sum(
        1 for c in url
        if c in special_chars
        and c not in ["=", "?", "&"]
    )

    # Special character ratio
    if len(url) > 0:
        special_char_ratio = (
            no_of_other_special
            + no_of_equals
            + no_of_qmark
            + no_of_ampersand
        ) / len(url)
    else:
        special_char_ratio = 0

    # HTTPS
    is_https = int(parsed.scheme == "https")

    # Return features in EXACT training order
    feature_values = [
        url_length,
        domain_length,
        is_domain_ip,
        url_similarity,
        char_continuation_rate,
        tld_legitimate_prob,
        url_char_prob,
        tld_length,
        no_of_subdomain,
        has_obfuscation,
        obfuscated_chars,
        obfuscation_ratio,
        no_of_letters,
        letter_ratio,
        no_of_digits,
        digit_ratio,
        no_of_equals,
        no_of_qmark,
        no_of_ampersand,
        no_of_other_special,
        special_char_ratio,
        is_https
    ]

    return feature_values