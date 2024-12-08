"""Module for managing demo targets for penetration testing."""

DEMO_TARGETS = {
    "altoro": {
        "url": "http://demo.testfire.net",
        "description": "Altoro Mutual is a demo banking application with known vulnerabilities",
        "features": ["SQL Injection", "XSS", "CSRF"],
        "safe_paths": ["/login.jsp", "/index.jsp", "/default.aspx"]
    },
    "firing_range": {
        "url": "https://public-firing-range.appspot.com",
        "description": "Google's test bed for automated scanners",
        "features": ["XSS", "DOM XSS", "Path Traversal"],
        "safe_paths": ["/reflected/index.html", "/dom/index.html"]
    },
    "juice_shop": {
        "url": "https://juice-shop.herokuapp.com",
        "description": "OWASP Juice Shop - Modern vulnerable web application",
        "features": ["Injection", "Broken Authentication", "Security Misconfiguration"],
        "safe_paths": ["/", "/login", "/register"]
    }
}

def get_demo_target(name):
    """
    Get information about a specific demo target.
    
    Args:
        name (str): Name of the demo target
        
    Returns:
        dict: Target information or None if not found
    """
    return DEMO_TARGETS.get(name.lower())

def list_demo_targets():
    """
    List all available demo targets.
    
    Returns:
        list: List of demo target names and URLs
    """
    return [(name, info["url"]) for name, info in DEMO_TARGETS.items()]

def get_safe_paths(target_url):
    """
    Get safe paths for a demo target.
    
    Args:
        target_url (str): URL of the demo target
        
    Returns:
        list: List of safe paths or empty list if target not found
    """
    for target in DEMO_TARGETS.values():
        if target["url"] in target_url:
            return target["safe_paths"]
    return []
