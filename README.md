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

## Screenshots

### Program Output
![Output](screenshots/output.png)

### Security Check
![Security](screenshots/security.png)

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
EMAIL ADDRESSES (20 found):
   • j*******a@alustudent.com
   • d*********a@alustudent.com
   ...

PHONE NUMBERS (14 found):
   • +250 788 123 456
   • 0788 456 789
   • +250 722 345 678
   ...

CREDIT CARDS (3 found):
   • ****-****-****-9903
   ...

SECURITY STATUS: THREATS DETECTED
   - SQL injection detected
   - XSS attack detected
   
Total extracted: 155 items
Dangerous blocked: 15 items
```

## Requirements

- Python 3.6 or higher
- No external packages needed
