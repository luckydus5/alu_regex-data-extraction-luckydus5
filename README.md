# Regex Data Extraction

A Python program that extracts structured data from text using regular expressions. This project was built for the ALU Regex Hackathon assignment.

## What it does

The program reads text input and extracts:
- Email addresses
- URLs  
- Phone numbers (Rwandan and international formats)
- Credit card numbers (with Luhn validation)
- Time values (12-hour and 24-hour)
- HTML tags (identifies dangerous ones)
- Hashtags
- Currency amounts

It also checks for security issues like SQL injection and XSS attempts.

## How to run

```bash
python main.py
```

Or with your own file:
```bash
python main.py yourfile.txt
```

## Files

- `main.py` - runs the program
- `extractor.py` - contains all the regex patterns
- `security.py` - checks for malicious input
- `sample_input.txt` - test data
- `output.json` - results after running

## Regex Patterns

### Email
```python
r'\b[a-zA-Z0-9._%+-]{1,64}@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
```
Matches emails like `user@domain.com` or `name@alustudent.com`

### Rwandan Phone Numbers
```python
r'\+250[-.\s]?[0]?7[2389]\d[-.\s]?\d{3}[-.\s]?\d{3,4}'
r'|07[2389]\d[-.\s]?\d{3}[-.\s]?\d{3}'
```
Matches formats like `+250 788 123 456` or `0788 456 789`

### Credit Card
```python
r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'
```
Matches 16-digit cards, then validates with Luhn algorithm

### URL
```python
r'\bhttps?://[a-zA-Z0-9.-]+(?:\.[a-zA-Z]{2,})(?:/[^\s<>\"\']*)?'
```
Only matches http/https URLs to avoid javascript: injection

## Security

The program detects:
- SQL injection (`DROP TABLE`, `UNION SELECT`, etc)
- XSS attacks (`<script>`, `onclick=`, etc)
- Command injection (`;`, `|`, `&&`, etc)
- Path traversal (`../`)

Sensitive data like credit cards and emails are masked in the output:
- Cards show as `****-****-****-1234`
- Emails show as `u**r@domain.com`

## Sample Output

```
======================================================================
   DATA EXTRACTION & SECURE VALIDATION SYSTEM
======================================================================

📂 Input File: sample_input.txt
📊 Input Size: 9,677 characters

──────────────────────────────────────────────────────────────────────
  EXTRACTION RESULTS
──────────────────────────────────────────────────────────────────────

📧 EMAIL ADDRESSES (20 found):
   • i**o@company.com
   • j*******a@alustudent.com
   • d*********a@alustudent.com
   • k******i@alustudent.com
   • p********a@alustudent.com
   • m*********a@alustudent.com
   • u*****3@gmail.com

🔗 URLs (17 found):
   • https://www.example.com
   • https://docs.example.org/getting-started
   • https://api.company.io/v2/reference
   • https://blog.techsite.com/2024/01/new-features

📞 PHONE NUMBERS (14 found):
   • +250 788 123 456
   • 0788 456 789
   • +250 722 345 678
   • 0799 876 543
   • +250 738 555 000
   • 0723 111 222
   • +250 782 000 111
   • +1 555 234 5678
   • +44 20 7946 0958

💳 CREDIT CARDS (3 found):
   • ****-****-****-9903
   • ****-****-****-2832
   • ****-****-****-0000

🕐 TIME VALUES (17 found):
   • 08:00  • 09:30  • 10:15  • 12:00  • 14:30
   • 2:30 PM  • 11:00 AM  • 7:00 PM

🏷️  HTML TAGS (42 safe, 15 dangerous):
   ✅ Safe tags:
      • <p>
      • <div class="container">
      • <img src="photo.jpg" alt="A beautiful sunset"/>
   ⚠️  Dangerous tags (BLOCKED):
      ❌ <script>alert('XSS')</script>
      ❌ <img src="x" onerror="alert('XSS')">
      ❌ <iframe src="https://malicious-site.com">

#️⃣  HASHTAGS (19 found):
   • #TechNews  • #WebDevelopment  • #Python3
   • #JavaScript  • #DataScience  • #Hackathon

💰 CURRENCY AMOUNTS (23 found):
   • $125.99
   • $1,234.56
   • $12,500.00
   • $50,000.00
   • $1,000,000.00

──────────────────────────────────────────────────────────────────────
  SECURITY ANALYSIS
──────────────────────────────────────────────────────────────────────

⚠️  INPUT SECURITY STATUS: THREATS DETECTED
   Threat Level: HIGH

   Issues Found:
   ❌ [HIGH] sql_injection: Potential SQL injection detected
   ❌ [HIGH] xss: Potential XSS attack detected
   ❌ [HIGH] command_injection: Potential command injection detected
   ❌ [HIGH] path_traversal: Potential path traversal attack detected

   Recommendations:
   💡 Sanitize SQL-like patterns before processing
   💡 Encode HTML entities in output
   💡 Never pass user input directly to shell commands

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

## JSON Output

The program also saves results to `output.json`:

```json
{
  "metadata": {
    "timestamp": "2026-02-01T08:22:44",
    "version": "1.0.0"
  },
  "extracted_data": {
    "emails": { "count": 20 },
    "urls": { "count": 17 },
    "phone_numbers": { "count": 14 },
    "credit_cards": { "count": 3 },
    "times": { "count": 17 },
    "hashtags": { "count": 19 },
    "currency": { "count": 23 }
  },
  "summary": {
    "total_items_extracted": 155,
    "dangerous_items_blocked": 15
  }
}
```

## Requirements

- Python 3.6 or higher
- No external packages needed
