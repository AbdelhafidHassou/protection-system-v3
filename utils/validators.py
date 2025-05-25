# utils/validators.py
import re
from typing import Any, Dict
from datetime import datetime
import ipaddress

class InputValidator:
    """Validate and sanitize input data"""
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    @staticmethod
    def validate_ip(ip: str) -> bool:
        """Validate IP address"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_timestamp(timestamp: str) -> bool:
        """Validate timestamp format"""
        try:
            # Try to parse the timestamp
            datetime.strptime(timestamp, "%a %b %d %H:%M:%S %Z %Y")
            return True
        except ValueError:
            return False
    
    @staticmethod
    def sanitize_string(value: str, max_length: int = 1000) -> str:
        """Sanitize string input"""
        if not isinstance(value, str):
            return ""
        
        # Remove control characters
        value = ''.join(char for char in value if ord(char) >= 32)
        
        # Truncate to max length
        return value[:max_length]
    
    @staticmethod
    def validate_request(data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and sanitize request data"""
        errors = []
        
        # Required fields
        required_fields = [
            'email', 'timestamp', 'action', 'status', 
            'duration', 'ip', 'userAgent', 'browser', 
            'os', 'deviceType', 'policyKey', 'service'
        ]
        
        for field in required_fields:
            if field not in data:
                errors.append(f"Missing required field: {field}")
        
        if errors:
            return {"valid": False, "errors": errors}
        
        # Validate specific fields
        if not InputValidator.validate_email(data['email']):
            errors.append("Invalid email format")
        
        if not InputValidator.validate_ip(data['ip']):
            errors.append("Invalid IP address")
        
        if not InputValidator.validate_timestamp(data['timestamp']):
            errors.append("Invalid timestamp format")
        
        if data['duration'] < 0:
            errors.append("Duration must be positive")
        
        if errors:
            return {"valid": False, "errors": errors}
        
        # Sanitize strings
        string_fields = [
            'action', 'status', 'userAgent', 'browser', 
            'os', 'deviceType', 'policyKey', 'service'
        ]
        
        for field in string_fields:
            data[field] = InputValidator.sanitize_string(data[field])
        
        return {"valid": True, "data": data}