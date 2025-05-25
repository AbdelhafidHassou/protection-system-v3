# utils/security.py
import hashlib
import hmac
import secrets
from typing import Optional
from datetime import datetime, timedelta
import jwt

class SecurityUtils:
    """Security utilities for the API"""
    
    @staticmethod
    def generate_api_key() -> str:
        """Generate a secure API key"""
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def hash_api_key(api_key: str) -> str:
        """Hash an API key for storage"""
        return hashlib.sha256(api_key.encode()).hexdigest()
    
    @staticmethod
    def verify_api_key(provided_key: str, stored_hash: str) -> bool:
        """Verify an API key against stored hash"""
        provided_hash = SecurityUtils.hash_api_key(provided_key)
        return hmac.compare_digest(provided_hash, stored_hash)
    
    @staticmethod
    def generate_session_token(
        user_id: str,
        secret_key: str,
        expiry_hours: int = 24
    ) -> str:
        """Generate JWT session token"""
        payload = {
            'user_id': user_id,
            'exp': datetime.utcnow() + timedelta(hours=expiry_hours),
            'iat': datetime.utcnow()
        }
        return jwt.encode(payload, secret_key, algorithm='HS256')
    
    @staticmethod
    def verify_session_token(
        token: str,
        secret_key: str
    ) -> Optional[Dict[str, Any]]:
        """Verify and decode JWT session token"""
        try:
            payload = jwt.decode(token, secret_key, algorithms=['HS256'])
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
    
    @staticmethod
    def sanitize_log_data(data: Dict[str, Any]) -> Dict[str, Any]:
        """Remove sensitive data from logs"""
        sensitive_fields = [
            'password', 'api_key', 'token', 'secret',
            'credit_card', 'ssn', 'bank_account'
        ]
        
        sanitized = data.copy()
        
        for field in sensitive_fields:
            if field in sanitized:
                sanitized[field] = '***REDACTED***'
        
        # Sanitize nested dictionaries
        for key, value in sanitized.items():
            if isinstance(value, dict):
                sanitized[key] = SecurityUtils.sanitize_log_data(value)
        
        return sanitized