#!/usr/bin/env python3
"""
Test wrong password scenario
"""

from secure_stego import extract_message, setup_logging, AuthenticationError

def test_wrong_password():
    """Test extraction with wrong password"""
    setup_logging(verbose=False)
    
    print("🔐 Testing Wrong Password Authentication")
    print("=" * 40)
    
    try:
        # Try to extract with wrong password
        print("🔑 Attempting extraction with wrong password...")
        message = extract_message("test_output.png", "wrongpassword")
        print(f"❌ ERROR: Should have failed but got: {message}")
        return False
        
    except AuthenticationError as e:
        print(f"✅ SUCCESS: Correctly rejected wrong password")
        print(f"   Error: {e}")
        return True
    except Exception as e:
        print(f"❌ UNEXPECTED ERROR: {e}")
        return False

if __name__ == '__main__':
    test_wrong_password()