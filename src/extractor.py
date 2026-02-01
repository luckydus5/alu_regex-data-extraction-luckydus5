"""
Regex patterns and functions to extract data from text.
Handles emails, URLs, phone numbers, credit cards, times, HTML tags, hashtags, and currency.
"""

import re
from typing import Dict, List, Tuple

# =============================================================================
# REGEX PATTERNS WITH EXPLANATIONS
# =============================================================================

# EMAIL PATTERN
# -------------
# Matches standard email formats: user@domain.tld, first.last@company.co.uk
# Security: Rejects extremely long local parts, disallows script injection characters
# Pattern breakdown:
#   - [a-zA-Z0-9._%+-]{1,64} : Local part (max 64 chars per RFC 5321)
#   - @ : Literal @ symbol
#   - [a-zA-Z0-9.-]+ : Domain name (letters, numbers, dots, hyphens)
#   - \.[a-zA-Z]{2,} : TLD must be at least 2 letters
EMAIL_PATTERN = re.compile(
    r'\b[a-zA-Z0-9._%+-]{1,64}@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
)

# URL PATTERN
# -----------
# Matches HTTP/HTTPS URLs with optional paths, query strings, and fragments
# Security: Only allows http/https protocols to prevent javascript: or data: injection
# Pattern breakdown:
#   - https?:// : Protocol (http or https only)
#   - [a-zA-Z0-9.-]+ : Domain name
#   - (?:\.[a-zA-Z]{2,}) : TLD
#   - (?:/[^\s<>\"']*)? : Optional path (excludes dangerous characters)
URL_PATTERN = re.compile(
    r'\bhttps?://[a-zA-Z0-9.-]+(?:\.[a-zA-Z]{2,})(?:/[^\s<>\"\']*)?'
)

# PHONE NUMBER PATTERN
# --------------------
# Matches Rwandan and international phone formats:
#   Rwandan: +250 788 123 456, 0788 456 789, +250-788-123-456
#   US: (123) 456-7890, 123-456-7890, +1 555 234 5678
#   UK: +44 20 7946 0958
# Security: Limits length to prevent buffer overflow attempts
# Pattern breakdown:
#   - Rwandan: +250 or 0 followed by 7[2389]X XXX XXX (9 digits after prefix)
#   - US: Optional +1, then 10 digits in various formats
#   - UK: +44 followed by area code and number
PHONE_PATTERN = re.compile(
    r'(?:'
    r'\+250[-.\s]?[0]?7[2389]\d[-.\s]?\d{3}[-.\s]?\d{3,4}'  # Rwandan: +250 78X XXX XXX
    r'|07[2389]\d[-.\s]?\d{3}[-.\s]?\d{3}'  # Rwandan local: 078X XXX XXX
    r'|\+1[-.\s]?\d{3}[-.\s]?\d{3}[-.\s]?\d{4}'  # US: +1 XXX XXX XXXX
    r'|\+44[-.\s]?\d{2}[-.\s]?\d{4}[-.\s]?\d{4}'  # UK: +44 XX XXXX XXXX
    r'|\(\d{3}\)[-.\s]?\d{3}[-.\s]?\d{4}'  # US: (XXX) XXX-XXXX
    r'|\d{3}[-.\s]\d{3}[-.\s]\d{4}'  # US: XXX-XXX-XXXX
    r')'
)

# CREDIT CARD PATTERN
# -------------------
# Matches credit card formats: 1234 5678 9012 3456, 1234-5678-9012-3456
# Security: Only extracts format, does NOT validate via Luhn algorithm here
#           (validation done separately to avoid logging raw numbers)
# Pattern breakdown:
#   - \d{4} : First group of 4 digits
#   - [\s-]? : Optional separator (space or hyphen)
#   - Repeated 3 more times for 16 total digits
CREDIT_CARD_PATTERN = re.compile(
    r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'
)

# TIME PATTERN (12-hour and 24-hour)
# ----------------------------------
# Matches: 14:30, 2:30 PM, 12:00 AM, 09:45, 23:59
# Security: Validates hour (0-23 or 1-12) and minute (0-59) ranges
# Pattern breakdown:
#   - 24-hour: ([01]?[0-9]|2[0-3]):[0-5][0-9] - Hours 0-23, minutes 0-59
#   - 12-hour: (1[0-2]|0?[1-9]):[0-5][0-9]\s*[AaPp][Mm] - Hours 1-12 with AM/PM
TIME_PATTERN = re.compile(
    r'\b(?:(?:[01]?[0-9]|2[0-3]):[0-5][0-9]|(?:1[0-2]|0?[1-9]):[0-5][0-9]\s*[AaPp][Mm])\b'
)

# HTML TAG PATTERN
# ----------------
# Matches HTML tags: <p>, <div class="example">, <img src="image.jpg" alt="text"/>
# Security: Captures tags for analysis but flags potentially dangerous ones
#           (script, iframe, onclick handlers) in validation phase
# Pattern breakdown:
#   - < : Opening bracket
#   - /?[a-zA-Z][a-zA-Z0-9]* : Tag name (optional closing slash)
#   - (?:\s+[^>]*)? : Optional attributes
#   - /?> : Closing bracket (optional self-closing slash)
HTML_TAG_PATTERN = re.compile(
    r'</?[a-zA-Z][a-zA-Z0-9]*(?:\s+[^>]*)?\s*/?>'
)

# HASHTAG PATTERN
# ---------------
# Matches hashtags: #example, #ThisIsAHashtag, #Python3
# Security: Limits length and disallows special characters to prevent injection
# Pattern breakdown:
#   - # : Literal hash symbol
#   - [a-zA-Z][a-zA-Z0-9_]{0,139} : Must start with letter, max 140 chars (Twitter limit)
HASHTAG_PATTERN = re.compile(
    r'#[a-zA-Z][a-zA-Z0-9_]{0,139}\b'
)

# CURRENCY PATTERN
# ----------------
# Matches US dollar amounts: $19.99, $1,234.56, $1,000,000.00
# Security: Validates proper comma placement for thousands separators
# Pattern breakdown:
#   - \$ : Dollar sign
#   - (?:\d{1,3}(?:,\d{3})*|\d+) : Integer part with optional comma separators
#   - (?:\.\d{2})? : Optional cents (exactly 2 digits)
CURRENCY_PATTERN = re.compile(
    r'\$(?:\d{1,3}(?:,\d{3})*|\d+)(?:\.\d{2})?'
)


# =============================================================================
# EXTRACTION FUNCTIONS
# =============================================================================

def extract_emails(text: str) -> List[str]:
    """
    Extract valid email addresses from text.
    
    Args:
        text: Raw input text to search
        
    Returns:
        List of extracted email addresses
    """
    emails = EMAIL_PATTERN.findall(text)
    # Filter out emails that look like injection attempts
    valid_emails = []
    for email in emails:
        # Security: Reject emails with suspicious patterns
        if not _contains_injection_pattern(email):
            valid_emails.append(email)
    return valid_emails


def extract_urls(text: str) -> List[str]:
    """
    Extract valid URLs from text.
    
    Args:
        text: Raw input text to search
        
    Returns:
        List of extracted URLs
    """
    urls = URL_PATTERN.findall(text)
    valid_urls = []
    for url in urls:
        # Security: Reject URLs with encoded script injections
        if not _contains_injection_pattern(url):
            valid_urls.append(url)
    return valid_urls


def extract_phone_numbers(text: str) -> List[str]:
    """
    Extract valid phone numbers from text.
    
    Args:
        text: Raw input text to search
        
    Returns:
        List of extracted phone numbers
    """
    return PHONE_PATTERN.findall(text)


def extract_credit_cards(text: str) -> List[str]:
    """
    Extract credit card numbers from text.
    Note: Returns raw numbers for processing but should be masked for display.
    
    Args:
        text: Raw input text to search
        
    Returns:
        List of extracted credit card numbers
    """
    cards = CREDIT_CARD_PATTERN.findall(text)
    # Validate using Luhn algorithm
    valid_cards = []
    for card in cards:
        digits_only = re.sub(r'[\s-]', '', card)
        if _luhn_validate(digits_only):
            valid_cards.append(card)
    return valid_cards


def extract_times(text: str) -> List[str]:
    """
    Extract time values (12-hour and 24-hour formats) from text.
    
    Args:
        text: Raw input text to search
        
    Returns:
        List of extracted time strings
    """
    return TIME_PATTERN.findall(text)


def extract_html_tags(text: str) -> Tuple[List[str], List[str]]:
    """
    Extract HTML tags from text, separating safe and potentially dangerous tags.
    
    Args:
        text: Raw input text to search
        
    Returns:
        Tuple of (safe_tags, dangerous_tags)
    """
    all_tags = HTML_TAG_PATTERN.findall(text)
    safe_tags = []
    dangerous_tags = []
    
    # Dangerous tag patterns (XSS vectors)
    dangerous_patterns = [
        r'<script',
        r'<iframe',
        r'<object',
        r'<embed',
        r'<form',
        r'onerror\s*=',
        r'onclick\s*=',
        r'onload\s*=',
        r'onmouseover\s*=',
        r'onfocus\s*=',
        r'javascript:',
        r'data:text/html',
    ]
    
    for tag in all_tags:
        is_dangerous = False
        tag_lower = tag.lower()
        for pattern in dangerous_patterns:
            if re.search(pattern, tag_lower):
                is_dangerous = True
                dangerous_tags.append(tag)
                break
        if not is_dangerous:
            safe_tags.append(tag)
    
    return safe_tags, dangerous_tags


def extract_hashtags(text: str) -> List[str]:
    """
    Extract hashtags from text.
    
    Args:
        text: Raw input text to search
        
    Returns:
        List of extracted hashtags
    """
    hashtags = HASHTAG_PATTERN.findall(text)
    # Filter out suspiciously long hashtags that might be obfuscation attempts
    return [h for h in hashtags if len(h) <= 50]


def extract_currency(text: str) -> List[str]:
    """
    Extract currency amounts from text.
    
    Args:
        text: Raw input text to search
        
    Returns:
        List of extracted currency amounts
    """
    return CURRENCY_PATTERN.findall(text)


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def _contains_injection_pattern(text: str) -> bool:
    """
    Check if text contains common injection patterns.
    
    Security: Detects SQL injection, XSS, and command injection attempts.
    
    Args:
        text: String to check
        
    Returns:
        True if suspicious pattern detected, False otherwise
    """
    injection_patterns = [
        r'<script',
        r'javascript:',
        r'onclick\s*=',
        r'onerror\s*=',
        r'onload\s*=',
        r'SELECT\s+.*\s+FROM',
        r'UNION\s+SELECT',
        r'DROP\s+TABLE',
        r'INSERT\s+INTO',
        r'DELETE\s+FROM',
        r'--\s*$',
        r';\s*--',
        r'\|\|',
        r'&&',
        r'\$\{',
        r'`.*`',
    ]
    
    text_lower = text.lower()
    for pattern in injection_patterns:
        if re.search(pattern, text_lower, re.IGNORECASE):
            return True
    return False


def _luhn_validate(card_number: str) -> bool:
    """
    Validate credit card number using the Luhn algorithm.
    
    This is a standard checksum algorithm used by credit card companies.
    
    Args:
        card_number: String of digits (no spaces or dashes)
        
    Returns:
        True if valid, False otherwise
    """
    if not card_number.isdigit() or len(card_number) != 16:
        return False
    
    digits = [int(d) for d in card_number]
    # Double every second digit from right
    for i in range(len(digits) - 2, -1, -2):
        digits[i] *= 2
        if digits[i] > 9:
            digits[i] -= 9
    
    return sum(digits) % 10 == 0


def mask_sensitive_data(data: str, data_type: str) -> str:
    """
    Mask sensitive data for safe display/logging.
    
    Args:
        data: The sensitive data string
        data_type: Type of data ('email', 'credit_card')
        
    Returns:
        Masked version of the data
    """
    if data_type == 'credit_card':
        # Show only last 4 digits
        digits = re.sub(r'[\s-]', '', data)
        return f"****-****-****-{digits[-4:]}"
    elif data_type == 'email':
        # Mask part of local portion
        parts = data.split('@')
        if len(parts) == 2:
            local = parts[0]
            domain = parts[1]
            if len(local) > 2:
                masked_local = local[0] + '*' * (len(local) - 2) + local[-1]
            else:
                masked_local = '*' * len(local)
            return f"{masked_local}@{domain}"
    return data


def extract_all(text: str) -> Dict:
    """
    Extract all data types from text and return structured results.
    
    Args:
        text: Raw input text to process
        
    Returns:
        Dictionary containing all extracted data by type
    """
    safe_html, dangerous_html = extract_html_tags(text)
    
    return {
        'emails': extract_emails(text),
        'urls': extract_urls(text),
        'phone_numbers': extract_phone_numbers(text),
        'credit_cards': extract_credit_cards(text),
        'times': extract_times(text),
        'html_tags': {
            'safe': safe_html,
            'dangerous': dangerous_html
        },
        'hashtags': extract_hashtags(text),
        'currency': extract_currency(text)
    }
