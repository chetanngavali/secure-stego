#!/usr/bin/env python3
"""
Simple test script for the steganography functionality
"""

import sys
import logging
from secure_stego import embed_message, extract_message, setup_logging

def test_embed_extract():
    """Test the complete embed/extract workflow"""
    # Setup logging
    setup_logging(verbose=True)
    
    # Test parameters
    input_image = "test_image.png"
    output_image = "test_output.png"
    test_message = "This is a secret test message for validation!"
    test_password = "testpassword123"
    
    print("🔐 Testing Steganography Embed/Extract Workflow")
    print("=" * 50)
    
    try:
        print(f"📤 Embedding message: '{test_message}'")
        print(f"🖼️  Input image: {input_image}")
        print(f"🖼️  Output image: {output_image}")
        print(f"🔑 Password: {test_password}")
        print()
        
        # Embed message
        embed_message(input_image, output_image, test_message, test_password)
        print("✅ Message embedded successfully!")
        print()
        
        # Extract message
        print("📥 Extracting message...")
        extracted_message = extract_message(output_image, test_password)
        print(f"✅ Message extracted: '{extracted_message}'")
        print()
        
        # Verify
        if extracted_message == test_message:
            print("🎉 SUCCESS: Messages match perfectly!")
            return True
        else:
            print(f"❌ FAILURE: Messages don't match!")
            print(f"   Original:  '{test_message}'")
            print(f"   Extracted: '{extracted_message}'")
            return False
            
    except Exception as e:
        print(f"❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == '__main__':
    success = test_embed_extract()
    sys.exit(0 if success else 1)