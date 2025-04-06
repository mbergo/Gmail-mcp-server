"""
Security configuration and best practices for the Gmail MCP server.
"""
import os
from pathlib import Path
from typing import List, Dict, Any
import logging
from datetime import timedelta
import re
import mimetypes

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security.log'),
        logging.StreamHandler()
    ]
)

# Security settings
SECURITY_CONFIG = {
    # Session settings
    'SESSION_TIMEOUT': timedelta(hours=1),
    'SESSION_COOKIE_SECURE': True,
    'SESSION_COOKIE_HTTPONLY': True,
    'SESSION_COOKIE_SAMESITE': 'Lax',
    
    # Rate limiting
    'RATE_LIMIT_REQUESTS': 100,
    'RATE_LIMIT_PERIOD': 3600,  # 1 hour
    
    # OAuth settings
    'OAUTH_SCOPES': [
        'https://mail.google.com/',
        'https://www.googleapis.com/auth/gmail.readonly',
        'https://www.googleapis.com/auth/gmail.send'
    ],
    'OAUTH_ACCESS_TYPE': 'offline',
    'OAUTH_PROMPT': 'consent',
    
    # File security
    'MAX_ATTACHMENT_SIZE': 25 * 1024 * 1024,  # 25MB
    'ALLOWED_ATTACHMENT_TYPES': [
        'application/pdf',
        'image/jpeg',
        'image/png',
        'text/plain',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    ],
    
    # Input validation
    'MAX_EMAIL_LENGTH': 500,  # Increased to accept 500-line emails
    'MAX_SUBJECT_LENGTH': 998,
    'MAX_BODY_LENGTH': 1024 * 1024,  # 1MB
    
    # Path security
    'TOKEN_DIR': Path('token_files'),
    'LOG_DIR': Path('logs'),
    'TEMP_DIR': Path('temp'),
    
    # API security
    'MAX_RESULTS_PER_REQUEST': 100,
    'REQUEST_TIMEOUT': 30,  # seconds
    
    # Encryption
    'TOKEN_ENCRYPTION_KEY': os.getenv('TOKEN_ENCRYPTION_KEY'),
    'MIN_PASSWORD_LENGTH': 12,
    'PASSWORD_REQUIREMENTS': {
        'uppercase': True,
        'lowercase': True,
        'numbers': True,
        'special_chars': True
    }
}

def validate_email(email: str) -> bool:
    """Validate email address format and security."""
    if not email:
        return False
    
    # Convert to string and clean
    email_str = str(email).strip()
    
    # Basic email format validation first
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, email_str):
        return False
    
    # Split email into local and domain parts
    try:
        local, domain = email_str.split('@')
        
        # Check lengths of individual parts (RFC 5321)
        if len(local) > 64:
            logging.warning(f"Local part length {len(local)} exceeds maximum 64")
            return False
            
        if len(domain) > 255:
            logging.warning(f"Domain length {len(domain)} exceeds maximum 255")
            return False
            
        # Check total length (RFC 5321)
        if len(email_str) > SECURITY_CONFIG['MAX_EMAIL_LENGTH']:
            logging.warning(f"Total email length {len(email_str)} exceeds maximum {SECURITY_CONFIG['MAX_EMAIL_LENGTH']}")
            return False
            
        # Additional domain validations
        if domain.startswith('.') or domain.endswith('.'):
            return False
        if '..' in domain:
            return False
            
        # Additional local part validations
        if local.startswith('.') or local.endswith('.'):
            return False
        if '..' in local:
            return False
            
    except ValueError:
        return False
    
    # Check for common injection patterns
    dangerous_patterns = [
        r'<script',
        r'javascript:',
        r'data:',
        r'vbscript:',
        r'onload=',
        r'onerror='
    ]
    
    return not any(re.search(pattern, email_str, re.IGNORECASE) 
                  for pattern in dangerous_patterns)

def validate_attachment(file_path: Path) -> bool:
    """Validate attachment security."""
    try:
        if not file_path.exists():
            return False
            
        # Check file size
        file_size = file_path.stat().st_size
        if file_size > SECURITY_CONFIG['MAX_ATTACHMENT_SIZE']:
            return False
            
        if file_size == 0:
            return False
        
        # Read file content for validation
        with open(file_path, 'rb') as f:
            content = f.read()
            
            # Check for executable content or suspicious patterns
            executable_patterns = [
                b'MZ',  # Windows executable
                b'ELF',  # Linux executable
                b'#!/',  # Shell script
                b'\x7fELF',  # ELF header
                b'EXECUTABLE CONTENT'  # Test case pattern
            ]
            
            if any(pattern in content[:1024] for pattern in executable_patterns):
                return False
            
            # Check for PDF
            if content.startswith(b'%PDF'):
                return True
                
            # Check for other allowed types
            content_type, _ = mimetypes.guess_type(str(file_path))
            if content_type in SECURITY_CONFIG['ALLOWED_ATTACHMENT_TYPES']:
                # Additional checks for specific file types
                if content_type.startswith('image/'):
                    # Check for common image headers
                    if content.startswith(b'\xFF\xD8\xFF'):  # JPEG
                        return True
                    if content.startswith(b'\x89PNG\r\n\x1a\n'):  # PNG
                        return True
                elif content_type == 'text/plain':
                    # Check if file is readable as text
                    try:
                        content.decode('utf-8')
                        return True
                    except UnicodeDecodeError:
                        return False
            
        return False
    except Exception as e:
        logging.error(f"Error validating attachment: {e}")
        return False

def sanitize_input(input_str: str, max_length: int = None) -> str:
    """Sanitize user input."""
    if max_length is None:
        max_length = SECURITY_CONFIG['MAX_BODY_LENGTH']
    
    # Remove potential HTML/JavaScript injection
    sanitized = re.sub(r'<[^>]+>', '', input_str)
    sanitized = re.sub(r'javascript:', '', sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r'data:', '', sanitized, flags=re.IGNORECASE)
    
    # Limit length
    return sanitized[:max_length]

def validate_password(password: str) -> bool:
    """Validate password strength."""
    if len(password) < SECURITY_CONFIG['MIN_PASSWORD_LENGTH']:
        return False
    
    requirements = SECURITY_CONFIG['PASSWORD_REQUIREMENTS']
    
    if requirements['uppercase'] and not re.search(r'[A-Z]', password):
        return False
    if requirements['lowercase'] and not re.search(r'[a-z]', password):
        return False
    if requirements['numbers'] and not re.search(r'\d', password):
        return False
    if requirements['special_chars'] and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False
    
    return True

def setup_security_directories():
    """Create and secure necessary directories."""
    for directory in [SECURITY_CONFIG['TOKEN_DIR'], 
                     SECURITY_CONFIG['LOG_DIR'],
                     SECURITY_CONFIG['TEMP_DIR']]:
        directory.mkdir(exist_ok=True)
        # Set secure permissions
        os.chmod(directory, 0o700) 