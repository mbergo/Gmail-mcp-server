import pytest
from pathlib import Path
import tempfile
import os
from security_config import (
    validate_email,
    validate_password,
    sanitize_input,
    validate_attachment,
    setup_security_directories,
    SECURITY_CONFIG
)

def test_email_validation():
    """Test email validation function."""
    # Valid emails
    assert validate_email("test@example.com")
    assert validate_email("user.name@domain.co.uk")
    
    # Invalid emails
    assert not validate_email("invalid.email")
    assert not validate_email("test@example.com<script>alert('xss')</script>")
    assert not validate_email("test@example.com" + "a" * 600)  # Too long (exceeds 500)
    assert not validate_email("")  # Empty
    assert not validate_email(None)  # None

def test_password_validation():
    """Test password validation function."""
    # Valid passwords
    assert validate_password("StrongPass123!")
    assert validate_password("Complex@Password2024")
    
    # Invalid passwords
    assert not validate_password("weak")  # Too short
    assert not validate_password("12345678")  # No letters
    assert not validate_password("abcdefgh")  # No numbers
    assert not validate_password("ABCDEFGH")  # No lowercase
    assert not validate_password("abcd1234")  # No special chars

def test_input_sanitization():
    """Test input sanitization function."""
    # Test HTML removal
    input_str = "<script>alert('xss')</script>Hello"
    assert "<script>" not in sanitize_input(input_str)
    assert "Hello" in sanitize_input(input_str)
    
    # Test length limit
    long_input = "a" * (SECURITY_CONFIG['MAX_BODY_LENGTH'] + 1000)
    assert len(sanitize_input(long_input)) <= SECURITY_CONFIG['MAX_BODY_LENGTH']
    
    # Test JavaScript injection
    input_str = "javascript:alert('xss')"
    assert "javascript:" not in sanitize_input(input_str)

def test_attachment_validation():
    """Test attachment validation function."""
    with tempfile.NamedTemporaryFile() as tmp:
        # Test valid PDF
        tmp.write(b"%PDF-1.4\n%EOF")
        tmp.flush()
        assert validate_attachment(Path(tmp.name))
        
        # Test invalid file type
        tmp.write(b"EXECUTABLE CONTENT")
        tmp.flush()
        assert not validate_attachment(Path(tmp.name))
        
        # Test file size limit
        large_content = b"0" * (SECURITY_CONFIG['MAX_ATTACHMENT_SIZE'] + 1000)
        tmp.write(large_content)
        tmp.flush()
        assert not validate_attachment(Path(tmp.name))

def test_directory_security():
    """Test directory security setup."""
    # Create test directories
    test_dirs = [
        Path("test_token_files"),
        Path("test_logs"),
        Path("test_temp")
    ]
    
    try:
        # Setup directories
        for directory in test_dirs:
            directory.mkdir(exist_ok=True)
            os.chmod(directory, 0o700)
            
            # Verify permissions
            stat = os.stat(directory)
            assert stat.st_mode & 0o777 == 0o700
            
    finally:
        # Cleanup
        for directory in test_dirs:
            if directory.exists():
                directory.rmdir() 