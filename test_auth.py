import os
from gmail_api import init_gmail_service, get_email_messages, get_email_message_details

def test_authentication():
    """Test the authentication flow and basic Gmail functionality."""
    print("Starting authentication test...")
    
    # Check if client secrets file exists
    if not os.path.exists('client_secrets.json'):
        print("Error: client_secrets.json not found!")
        print("Please ensure you have placed your OAuth client secrets file in the project root.")
        return False
    
    try:
        # Try to initialize the service
        print("Attempting to initialize Gmail service...")
        service = init_gmail_service('client_secrets.json')
        
        # Test basic Gmail functionality
        print("\nTesting Gmail API functionality...")
        
        # Test getting messages
        print("Testing get_email_messages...")
        messages, next_page_token = get_email_messages(service, max_results=1)
        if not messages:
            print("Warning: No messages found in inbox")
        else:
            print(f"Successfully retrieved {len(messages)} message(s)")
            
            # Test getting message details
            print("\nTesting get_email_message_details...")
            message_details = get_email_message_details(service, messages[0]['id'])
            if message_details:
                print("Successfully retrieved message details:")
                print(f"Subject: {message_details['subject']}")
                print(f"From: {message_details['sender']}")
            else:
                print("Warning: Could not retrieve message details")
        
        print("\nAll tests completed successfully!")
        return True
        
    except Exception as e:
        print(f"\nError during testing: {str(e)}")
        return False

if __name__ == '__main__':
    test_authentication() 