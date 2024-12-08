from datetime import datetime, timedelta
import logging

class RateLimiter:
    """Rate limiter implementation using token bucket algorithm."""
    
    def __init__(self, requests_per_minute=30):
        """
        Initialize rate limiter.
        
        Args:
            requests_per_minute (int): Maximum number of requests allowed per minute
        """
        self.RATE_LIMIT = requests_per_minute
        self.request_timestamps = []
    
    def check_rate_limit(self):
        """
        Check if the current request exceeds the rate limit.
        
        Raises:
            Exception: If rate limit is exceeded
        """
        now = datetime.now()
        # Remove timestamps older than 1 minute
        self.request_timestamps = [ts for ts in self.request_timestamps 
                                 if now - ts < timedelta(minutes=1)]
        
        if len(self.request_timestamps) >= self.RATE_LIMIT:
            logging.warning("[WARNING] Rate limit exceeded")
            raise Exception("Rate limit exceeded. Please wait before making more requests.")
        
        self.request_timestamps.append(now)
        logging.debug(f"[DEBUG] Requests in last minute: {len(self.request_timestamps)}")
    
    def reset(self):
        """Reset the rate limiter by clearing all timestamps."""
        self.request_timestamps = []
        logging.debug("[DEBUG] Rate limiter reset")

# Create a global rate limiter instance
rate_limiter = RateLimiter()
