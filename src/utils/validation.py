import urllib.parse
import logging

# Safe demo mode targets
DEMO_TARGETS = [
    "http://demo.testfire.net",  # Altoro Mutual demo site
    "https://public-firing-range.appspot.com",  # Google's test site
    "https://juice-shop.herokuapp.com"  # OWASP Juice Shop demo
]

def is_demo_target(target):
    """Check if the target is in the list of approved demo targets."""
    return any(demo in target for demo in DEMO_TARGETS)

def validate_input(target):
    """
    Validate and sanitize target input.
    
    Args:
        target (str): The target URL to validate
        
    Returns:
        str: The validated and sanitized target URL
        
    Raises:
        ValueError: If the target is invalid or unauthorized
    """
    if not target:
        raise ValueError("Target website cannot be empty")
    
    if not target.startswith(("http://", "https://")):
        target = "http://" + target
    
    parsed_url = urllib.parse.urlparse(target)
    if not parsed_url.scheme or not parsed_url.netloc:
        raise ValueError("Invalid URL format")
    
    if not is_demo_target(target):
        confirmation = input(f"WARNING: {target} is not a demo target. Are you authorised to test this target? (yes/no): ")
        if confirmation.lower() != 'yes':
            raise ValueError("Unauthorised target. Please use demo targets or obtain proper authorisation.")
    
    return target
