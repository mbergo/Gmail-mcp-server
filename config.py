import os
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv
from cryptography.fernet import Fernet

# Load environment variables
load_dotenv()

# Base paths
BASE_DIR = Path(__file__).parent
TOKEN_DIR = BASE_DIR / 'token_files'
TOKEN_DIR.mkdir(exist_ok=True)

# Security settings
ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY')
if not ENCRYPTION_KEY:
    ENCRYPTION_KEY = Fernet.generate_key()
    print(f"Generated new encryption key. Please add this to your .env file: ENCRYPTION_KEY={ENCRYPTION_KEY.decode()}")

fernet = Fernet(ENCRYPTION_KEY)

# OAuth settings
CLIENT_SECRETS_FILE = os.getenv('CLIENT_SECRETS_FILE', 'client_secrets.json')
OAUTH_SCOPES = ['https://mail.google.com/']
REDIRECT_URI = os.getenv('REDIRECT_URI', 'http://localhost:8080/oauth2callback')

# Rate limiting
RATE_LIMIT_REQUESTS = int(os.getenv('RATE_LIMIT_REQUESTS', '100'))
RATE_LIMIT_PERIOD = int(os.getenv('RATE_LIMIT_PERIOD', '3600'))  # 1 hour

# Session settings
SESSION_TIMEOUT = int(os.getenv('SESSION_TIMEOUT', '3600'))  # 1 hour
SESSION_SECRET_KEY = os.getenv('SESSION_SECRET_KEY', os.urandom(24).hex())

def encrypt_data(data: str) -> bytes:
    """Encrypt sensitive data."""
    return fernet.encrypt(data.encode())

def decrypt_data(encrypted_data: bytes) -> str:
    """Decrypt sensitive data."""
    return fernet.decrypt(encrypted_data).decode()

def get_token_path(email_identifier: str) -> Path:
    """Get the path for a token file, ensuring it's within the token directory."""
    # Sanitize the email identifier to prevent directory traversal
    safe_identifier = "".join(c for c in email_identifier if c.isalnum() or c in '._-')
    return TOKEN_DIR / f'token_{safe_identifier}.json'

def save_token(email_identifier: str, token_data: str) -> None:
    """Save an encrypted token."""
    token_path = get_token_path(email_identifier)
    encrypted_data = encrypt_data(token_data)
    token_path.write_bytes(encrypted_data)

def load_token(email_identifier: str) -> Optional[str]:
    """Load and decrypt a token."""
    token_path = get_token_path(email_identifier)
    if not token_path.exists():
        return None
    try:
        encrypted_data = token_path.read_bytes()
        return decrypt_data(encrypted_data)
    except Exception as e:
        print(f"Error loading token: {e}")
        return None 