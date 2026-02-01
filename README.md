# Data Extraction & Secure Validation System

[![Python](https://img.shields.io/badge/Python-3.6+-blue.svg)](https://www.python.org/)
[![Security](https://img.shields.io/badge/Security-Aware-green.svg)](#security-features)
[![License](https://img.shields.io/badge/License-Educational-yellow.svg)](#license)

A regex-based Python application for extracting structured data from raw text with comprehensive security validation. Built for the ALU Regex Onboarding Hackathon.

---

## 📸 System Screenshots

### Main System Output
![System Running](screenshots/system_running.png)

*The system processes input and extracts multiple data types with security validation.*

### Extraction Results
![Extraction Results](screenshots/extraction_results.png)

*Emails, URLs, phone numbers (Rwandan format), credit cards, and more are extracted.*

### Security Analysis
![Security Analysis](screenshots/security_analysis.png)

*Dangerous inputs like XSS and SQL injection attempts are detected and blocked.*

---

## 🎯 Overview

This system processes large volumes of raw text data and extracts specific types of structured information using regular expressions. It implements robust security measures to handle potentially malicious or malformed input.

## ✨ Features

### Data Extraction (All 8 Types Implemented)
| Data Type | Examples | Pattern Highlights |
|-----------|----------|-------------------|
| 📧 **Email Addresses** | `user@example.com`, `j.uwimana@alustudent.com` | RFC-compliant, 64-char local part limit |
| 🔗 **URLs** | `https://www.example.com/page?id=1` | HTTP/HTTPS only, path/query support |
| 📞 **Phone Numbers** | `+250 788 123 456`, `0788 456 789` | Rwandan & international formats |
| 💳 **Credit Cards** | `1234 5678 9012 3456`, `1234-5678-9012-3456` | Luhn algorithm validation |
| 🕐 **Time Formats** | `14:30`, `2:30 PM`, `11:00 AM` | 12-hour and 24-hour formats |
| 🏷️ **HTML Tags** | `<div class="example">`, `<img src="..."/>` | Safe/dangerous classification |
| #️⃣ **Hashtags** | `#Python`, `#100DaysOfCode` | Length limits, alphanumeric validation |
| 💰 **Currency** | `$19.99`, `$1,234.56` | Proper thousands separator validation |

### Security Features
- **SQL Injection Detection** - Identifies `SELECT`, `DROP TABLE`, `UNION SELECT` patterns
- **XSS Prevention** - Flags `<script>`, event handlers (`onclick`, `onerror`), `javascript:` URLs
- **Command Injection Detection** - Catches shell metacharacters, command chaining
- **Path Traversal Prevention** - Blocks `../`, encoded variants, sensitive file paths
- **Sensitive Data Masking** - Emails and credit cards are masked in logs/output

---

## 📁 Project Structure

```
alu_regex-data-extraction-{username}/
├── main.py              # Main runner script with CLI interface
├── extractor.py         # Regex patterns and extraction functions
├── security.py          # Security validation and sanitization
├── sample_input.txt     # Realistic sample input data
├── output.json          # Generated output (after running)
├── screenshots/         # System screenshots
└── README.md            # This documentation
```

---

## 🚀 Usage

### Basic Usage
```bash
# Run with default sample input
python main.py

# Run with custom input file
python main.py your_data.txt

# Show help
python main.py --help
```

### Sample Output
```
======================================================================
   DATA EXTRACTION & SECURE VALIDATION SYSTEM
   Regex-Based Text Processing with Security Awareness
======================================================================

📂 Input File: sample_input.txt
📊 Input Size: 9,677 characters

🔒 Running security validation...
🔍 Extracting structured data...

──────────────────────────────────────────────────────────────────────
  EXTRACTION RESULTS
──────────────────────────────────────────────────────────────────────

📧 EMAIL ADDRESSES (20 found):
   • i**o@company.com
   • j*******a@alustudent.com
   • d*********a@alustudent.com
   • k******i@alustudent.com
   ...

🔗 URLs (17 found):
   • https://www.example.com
   • https://docs.example.org/getting-started
   • https://api.company.io/v2/reference
   ...

📞 PHONE NUMBERS (14 found):
   • +250 788 123 456
   • 0788 456 789
   • +250 722 345 678
   • 0799 876 543
   • +1 555 234 5678
   • +44 20 7946 0958
   ...

💳 CREDIT CARDS (3 found):
   • ****-****-****-9903
   • ****-****-****-2832
   • ****-****-****-0000

🕐 TIME VALUES (17 found):
   • 08:00  • 09:30  • 10:15  • 2:30 PM  • 11:00 AM
   ...

🏷️  HTML TAGS (42 safe, 15 dangerous):
   ✅ Safe tags:
      • <p>
      • <div class="container">
      • <img src="photo.jpg" alt="A beautiful sunset"/>
   ⚠️  Dangerous tags (BLOCKED):
      ❌ <script>alert('XSS Attack!')</script>
      ❌ <img src="x" onerror="alert('XSS')">
      ❌ <iframe src="https://malicious-site.com">
      ...

#️⃣  HASHTAGS (19 found):
   • #TechNews  • #WebDevelopment  • #Python3
   • #DataScience  • #CyberSecurity  • #Hackathon
   ...

💰 CURRENCY AMOUNTS (23 found):
   • $125.99  • $1,234.56  • $12,500.00
   • $50,000.00  • $1,000,000.00
   ...

──────────────────────────────────────────────────────────────────────
  SECURITY ANALYSIS
──────────────────────────────────────────────────────────────────────

⚠️  INPUT SECURITY STATUS: THREATS DETECTED
   Threat Level: HIGH

   Issues Found:
   ❌ [HIGH] sql_injection: Potential SQL injection detected
   ❌ [HIGH] xss: Potential XSS attack detected
   ❌ [CRITICAL] command_injection: Potential command injection detected
   ❌ [HIGH] path_traversal: Potential path traversal attack detected

   Recommendations:
   💡 Sanitize SQL-like patterns before processing
   💡 Encode HTML entities in output
   💡 Never pass user input directly to shell commands
   💡 Validate and sanitize file paths

──────────────────────────────────────────────────────────────────────
  SUMMARY
──────────────────────────────────────────────────────────────────────

   ✅ Total items extracted: 155
   ❌ Dangerous items blocked: 15
   🔒 Security status: THREATS DETECTED

======================================================================
   Processing complete!
======================================================================
```

---

## 🔧 Technical Implementation

### Regex Pattern Design Philosophy

Each regex pattern is designed with:
1. **Accuracy** - Matches real-world format variations
2. **Security** - Rejects malformed/malicious input
3. **Performance** - Efficient patterns avoiding catastrophic backtracking

### Example Pattern Explanation

```python
# Email Pattern
EMAIL_PATTERN = re.compile(
    r'\b[a-zA-Z0-9._%+-]{1,64}@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
)
# Breakdown:
# - \b                        : Word boundary (prevents partial matches)
# - [a-zA-Z0-9._%+-]{1,64}   : Local part, max 64 chars (RFC 5321)
# - @                         : Literal @ symbol
# - [a-zA-Z0-9.-]+           : Domain name
# - \.[a-zA-Z]{2,}           : TLD with at least 2 letters
# - \b                        : Ending word boundary
```

### Phone Number Pattern (Rwandan & International)

```python
# Supports multiple formats:
# Rwandan: +250 788 123 456, 0788 456 789, +250-788-123-456
# US: +1 555 234 5678, (555) 123-4567
# UK: +44 20 7946 0958

PHONE_PATTERN = re.compile(
    r'(?:'
    r'\+250[-.\s]?[0]?7[2389]\d[-.\s]?\d{3}[-.\s]?\d{3,4}'  # Rwandan: +250 78X
    r'|07[2389]\d[-.\s]?\d{3}[-.\s]?\d{3}'  # Rwandan local: 078X XXX XXX
    r'|\+1[-.\s]?\d{3}[-.\s]?\d{3}[-.\s]?\d{4}'  # US: +1 XXX XXX XXXX
    r'|\+44[-.\s]?\d{2}[-.\s]?\d{4}[-.\s]?\d{4}'  # UK: +44 XX XXXX XXXX
    r')'
)
# Rwandan prefixes: 072X, 073X, 078X, 079X (MTN, Airtel)
```

### Credit Card Validation (Luhn Algorithm)

```python
def _luhn_validate(card_number: str) -> bool:
    """
    Validate credit card using checksum algorithm.
    Prevents accepting random 16-digit numbers.
    """
    digits = [int(d) for d in card_number]
    for i in range(len(digits) - 2, -1, -2):
        digits[i] *= 2
        if digits[i] > 9:
            digits[i] -= 9
    return sum(digits) % 10 == 0
```

## 🛡️ Security Considerations

### Threat Detection
The system identifies and flags:
- SQL injection attempts (`'; DROP TABLE users; --`)
- XSS payloads (`<script>alert('xss')</script>`)
- Command injection (`; rm -rf /`)
- Path traversal (`../../../etc/passwd`)

### Data Protection
- Credit card numbers displayed as `****-****-****-1234`
- Email addresses masked as `u**r@domain.com`
- Phone numbers can be partially masked
- JSON output maintains masking for sensitive fields

### Defensive Programming
- Maximum input length limits (1MB)
- Pattern-specific length constraints
- Compiled regex patterns for performance
- No dynamic regex construction from user input

## 📊 Sample Input Design

The `sample_input.txt` file contains realistic data including:
- Standard format examples for each data type
- Edge cases (international formats, unusual but valid patterns)
- Intentionally malicious inputs to test security
- Mixed real-world scenarios (email threads, invoices)

## 📋 Output Format

Results are output in two formats:

### 1. Console Output
Human-readable formatted display with:
- Emoji indicators for data types
- Count summaries
- Masked sensitive data
- Security threat warnings

### 2. JSON File (`output.json`)
Structured data including:
```json
{
  "metadata": {
    "timestamp": "2024-01-15T10:30:00",
    "version": "1.0.0"
  },
  "security": {
    "is_safe": false,
    "threat_level": "high",
    "issues_count": 5
  },
  "extracted_data": {
    "emails": { "count": 12, "values": [...] },
    "urls": { "count": 8, "values": [...] }
  },
  "summary": {
    "total_items_extracted": 87,
    "dangerous_items_blocked": 9
  }
}
```

## 🧪 Testing

Run the system with the provided sample input to verify:
1. All 8 data types are correctly extracted
2. Malicious inputs are flagged and blocked
3. Sensitive data is properly masked
4. JSON output is valid and complete

```bash
python main.py sample_input.txt
```

### Expected Results
| Data Type | Count | Notes |
|-----------|-------|-------|
| 📧 Emails | 20 | Including 6 ALU student emails |
| 🔗 URLs | 17 | HTTP/HTTPS validated |
| 📞 Phone Numbers | 14 | 12 Rwandan + 2 international |
| 💳 Credit Cards | 3 | Luhn algorithm validated |
| 🕐 Time Values | 17 | 12-hour and 24-hour formats |
| 🏷️ Safe HTML Tags | 42 | Standard HTML elements |
| ❌ Dangerous HTML | 15 | Blocked (XSS vectors) |
| #️⃣ Hashtags | 19 | Social media tags |
| 💰 Currency | 23 | USD amounts |

**Total: 155 items extracted, 15 dangerous items blocked**

---

## 📝 Requirements

- Python 3.6+
- No external dependencies (uses only standard library)

---

## 👤 Author

Created for the **ALU Regex Onboarding Hackathon** - Data Extraction & Secure Validation Assignment.

**Program**: ALU Software Engineering

---

## 📄 License

This project is submitted as coursework for educational purposes.
