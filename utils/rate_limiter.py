# utils/rate_limiter.py
import time
from typing import Dict, Optional
import asyncio

class RateLimiter:
    """Simple in-memory rate limiter"""
    
    def __init__(self):
        self.requests: Dict[str, list] = {}
        self.lock = asyncio.Lock()
    
    async def check_rate_limit(
        self,
        identifier: str,
        max_requests: int = 100,
        window_seconds: int = 60
    ) -> bool:
        """Check if request is within rate limit"""
        async with self.lock:
            current_time = time.time()
            
            # Initialize or get request times
            if identifier not in self.requests:
                self.requests[identifier] = []
            
            # Remove old requests outside window
            self.requests[identifier] = [
                req_time for req_time in self.requests[identifier]
                if current_time - req_time < window_seconds
            ]
            
            # Check if within limit
            if len(self.requests[identifier]) >= max_requests:
                return False
            
            # Add current request
            self.requests[identifier].append(current_time)
            return True
    
    async def get_remaining_requests(
        self,
        identifier: str,
        max_requests: int = 100,
        window_seconds: int = 60
    ) -> int:
        """Get remaining requests in current window"""
        async with self.lock:
            current_time = time.time()
            
            if identifier not in self.requests:
                return max_requests
            
            # Count requests in current window
            recent_requests = [
                req_time for req_time in self.requests[identifier]
                if current_time - req_time < window_seconds
            ]
            
            return max(0, max_requests - len(recent_requests))
    
    async def cleanup_old_entries(self, older_than_seconds: int = 3600):
        """Clean up old entries to prevent memory bloat"""
        async with self.lock:
            current_time = time.time()
            
            identifiers_to_remove = []
            
            for identifier, request_times in self.requests.items():
                # Remove all old requests
                self.requests[identifier] = [
                    req_time for req_time in request_times
                    if current_time - req_time < older_than_seconds
                ]
                
                # Mark empty entries for removal
                if not self.requests[identifier]:
                    identifiers_to_remove.append(identifier)
            
            # Remove empty entries
            for identifier in identifiers_to_remove:
                del self.requests[identifier]