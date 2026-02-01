"""
Security checks for detecting malicious input like SQL injection, XSS, etc.
Also masks sensitive data before logging.
"""

import re
from typing import Dict, List, Optional, Tuple
from enum import Enum


class ThreatLevel(Enum):
    """Threat classification levels for detected security issues."""
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityValidator:
    """
    Security validator for detecting and handling malicious input.
    
    This class provides methods to:
    - Detect various injection attacks
    - Sanitize input before processing
    - Classify threats by severity
    - Generate security reports
    """
    
    # Maximum input length to prevent DoS attacks
    MAX_INPUT_LENGTH = 1_000_000  # 1MB
    
    # SQL Injection patterns
    SQL_INJECTION_PATTERNS = [
        r"(?i)(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b.*\b(FROM|INTO|TABLE|DATABASE)\b)",
        r"(?i)(\bUNION\b.*\bSELECT\b)",
        r"(?i)(\bOR\b\s+[\d]+=[\d]+)",
        r"(?i)(\bAND\b\s+[\d]+=[\d]+)",
        r"(--\s*$|;\s*--)",
        r"(?i)(\bEXEC\b|\bEXECUTE\b)",
        r"(?i)(xp_cmdshell)",
        r"(/\*.*\*/)",
        r"(?i)(\bWAITFOR\b\s+\bDELAY\b)",
        r"(?i)(\bBENCHMARK\b)",
    ]
    
    # XSS (Cross-Site Scripting) patterns
    XSS_PATTERNS = [
        r"<script[^>]*>",
        r"</script>",
        r"javascript\s*:",
        r"vbscript\s*:",
        r"on\w+\s*=",  # Event handlers: onclick, onerror, onload, etc.
        r"<iframe[^>]*>",
        r"<object[^>]*>",
        r"<embed[^>]*>",
        r"<form[^>]*action\s*=",
        r"data\s*:\s*text/html",
        r"expression\s*\(",
        r"url\s*\(\s*['\"]?\s*javascript",
    ]
    
    # Command Injection patterns
    COMMAND_INJECTION_PATTERNS = [
        r"[;&|`$]",
        r"\$\([^)]+\)",
        r"`[^`]+`",
        r"\|\|",
        r"&&",
        r">\s*/dev/",
        r"<\s*/etc/",
        r"\brm\s+-rf\b",
        r"\bchmod\b",
        r"\bchown\b",
        r"\bwget\b",
        r"\bcurl\b.*\|",
        r"\bnc\b.*-e",
    ]
    
    # Path Traversal patterns
    PATH_TRAVERSAL_PATTERNS = [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e%2f",
        r"%2e%2e/",
        r"\.\.%2f",
        r"%2e%2e%5c",
        r"/etc/passwd",
        r"/etc/shadow",
        r"\\windows\\",
        r"\\system32\\",
    ]
    
    def __init__(self):
        """Initialize the security validator with compiled regex patterns."""
        self.sql_patterns = [re.compile(p, re.IGNORECASE) for p in self.SQL_INJECTION_PATTERNS]
        self.xss_patterns = [re.compile(p, re.IGNORECASE) for p in self.XSS_PATTERNS]
        self.cmd_patterns = [re.compile(p, re.IGNORECASE) for p in self.COMMAND_INJECTION_PATTERNS]
        self.path_patterns = [re.compile(p, re.IGNORECASE) for p in self.PATH_TRAVERSAL_PATTERNS]
    
    def validate_input(self, text: str) -> Tuple[bool, Dict]:
        """
        Perform comprehensive security validation on input text.
        
        Args:
            text: Raw input text to validate
            
        Returns:
            Tuple of (is_safe, security_report)
        """
        report = {
            'is_safe': True,
            'threat_level': ThreatLevel.SAFE.value,
            'issues': [],
            'recommendations': []
        }
        
        # Check input length
        if len(text) > self.MAX_INPUT_LENGTH:
            report['is_safe'] = False
            report['threat_level'] = ThreatLevel.MEDIUM.value
            report['issues'].append({
                'type': 'input_size',
                'message': f'Input exceeds maximum allowed length ({self.MAX_INPUT_LENGTH} bytes)',
                'severity': ThreatLevel.MEDIUM.value
            })
            report['recommendations'].append('Truncate or split large inputs')
            return False, report
        
        # Check for SQL injection
        sql_threats = self._detect_sql_injection(text)
        if sql_threats:
            report['is_safe'] = False
            report['threat_level'] = ThreatLevel.HIGH.value
            report['issues'].extend(sql_threats)
            report['recommendations'].append('Sanitize SQL-like patterns before processing')
        
        # Check for XSS
        xss_threats = self._detect_xss(text)
        if xss_threats:
            report['is_safe'] = False
            report['threat_level'] = ThreatLevel.HIGH.value
            report['issues'].extend(xss_threats)
            report['recommendations'].append('Encode HTML entities in output')
        
        # Check for command injection
        cmd_threats = self._detect_command_injection(text)
        if cmd_threats:
            report['is_safe'] = False
            report['threat_level'] = ThreatLevel.CRITICAL.value
            report['issues'].extend(cmd_threats)
            report['recommendations'].append('Never pass user input directly to shell commands')
        
        # Check for path traversal
        path_threats = self._detect_path_traversal(text)
        if path_threats:
            report['is_safe'] = False
            report['threat_level'] = ThreatLevel.HIGH.value
            report['issues'].extend(path_threats)
            report['recommendations'].append('Validate and sanitize file paths')
        
        return report['is_safe'], report
    
    def _detect_sql_injection(self, text: str) -> List[Dict]:
        """Detect SQL injection patterns in text."""
        threats = []
        for pattern in self.sql_patterns:
            matches = pattern.findall(text)
            if matches:
                threats.append({
                    'type': 'sql_injection',
                    'message': 'Potential SQL injection detected',
                    'severity': ThreatLevel.HIGH.value,
                    'pattern': pattern.pattern,
                    'count': len(matches)
                })
        return threats
    
    def _detect_xss(self, text: str) -> List[Dict]:
        """Detect XSS (Cross-Site Scripting) patterns in text."""
        threats = []
        for pattern in self.xss_patterns:
            matches = pattern.findall(text)
            if matches:
                threats.append({
                    'type': 'xss',
                    'message': 'Potential XSS attack detected',
                    'severity': ThreatLevel.HIGH.value,
                    'pattern': pattern.pattern,
                    'count': len(matches)
                })
        return threats
    
    def _detect_command_injection(self, text: str) -> List[Dict]:
        """Detect command injection patterns in text."""
        threats = []
        for pattern in self.cmd_patterns:
            matches = pattern.findall(text)
            if matches:
                threats.append({
                    'type': 'command_injection',
                    'message': 'Potential command injection detected',
                    'severity': ThreatLevel.CRITICAL.value,
                    'pattern': pattern.pattern,
                    'count': len(matches)
                })
        return threats
    
    def _detect_path_traversal(self, text: str) -> List[Dict]:
        """Detect path traversal patterns in text."""
        threats = []
        for pattern in self.path_patterns:
            matches = pattern.findall(text)
            if matches:
                threats.append({
                    'type': 'path_traversal',
                    'message': 'Potential path traversal attack detected',
                    'severity': ThreatLevel.HIGH.value,
                    'pattern': pattern.pattern,
                    'count': len(matches)
                })
        return threats
    
    def sanitize_for_logging(self, data: Dict) -> Dict:
        """
        Sanitize extracted data for safe logging.
        
        Masks sensitive information to prevent exposure in logs.
        
        Args:
            data: Dictionary of extracted data
            
        Returns:
            Sanitized dictionary safe for logging
        """
        sanitized = {}
        
        for key, value in data.items():
            if key == 'emails':
                # Mask email local parts
                sanitized[key] = [self._mask_email(email) for email in value]
            elif key == 'credit_cards':
                # Show only last 4 digits
                sanitized[key] = [self._mask_credit_card(card) for card in value]
            elif key == 'phone_numbers':
                # Mask middle digits
                sanitized[key] = [self._mask_phone(phone) for phone in value]
            else:
                sanitized[key] = value
        
        return sanitized
    
    def _mask_email(self, email: str) -> str:
        """Mask email address for safe logging."""
        parts = email.split('@')
        if len(parts) == 2:
            local = parts[0]
            domain = parts[1]
            if len(local) > 2:
                masked = local[0] + '*' * (len(local) - 2) + local[-1]
            else:
                masked = '*' * len(local)
            return f"{masked}@{domain}"
        return email
    
    def _mask_credit_card(self, card: str) -> str:
        """Mask credit card number showing only last 4 digits."""
        digits = re.sub(r'[\s-]', '', card)
        if len(digits) >= 4:
            return f"****-****-****-{digits[-4:]}"
        return "****-****-****-****"
    
    def _mask_phone(self, phone: str) -> str:
        """Mask phone number showing only last 4 digits."""
        digits = re.sub(r'\D', '', phone)
        if len(digits) >= 4:
            return f"(***) ***-{digits[-4:]}"
        return "(***) ***-****"


def validate_and_report(text: str) -> Tuple[bool, Dict]:
    """
    Convenience function for quick security validation.
    
    Args:
        text: Input text to validate
        
    Returns:
        Tuple of (is_safe, security_report)
    """
    validator = SecurityValidator()
    return validator.validate_input(text)


def create_safe_output(data: Dict, mask_sensitive: bool = True) -> Dict:
    """
    Create output safe for display/storage.
    
    Args:
        data: Extracted data dictionary
        mask_sensitive: Whether to mask sensitive fields
        
    Returns:
        Safe output dictionary
    """
    if mask_sensitive:
        validator = SecurityValidator()
        return validator.sanitize_for_logging(data)
    return data
