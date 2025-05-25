# database/models.py
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, EmailStr, Field

from database.mongodb import MongoDB

class UserProfile(BaseModel):
    """User profile document schema"""
    email: EmailStr
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    
    # User behavior patterns
    typical_browsers: List[str] = []
    typical_devices: List[str] = []
    typical_os: List[str] = []
    typical_ips: List[str] = []
    typical_locations: List[Dict[str, Any]] = []
    
    # Activity patterns
    typical_actions: List[str] = []
    typical_access_hours: List[int] = []  # 0-23
    typical_access_days: List[int] = []   # 0-6 (Mon-Sun)
    
    # Risk profile
    risk_profile: Dict[str, Any] = {
        "current_risk_level": "LOW",
        "fraud_attempts": 0,
        "successful_authentications": 0,
        "failed_authentications": 0,
        "last_risk_assessment": None
    }
    
    # Statistical data
    statistics: Dict[str, Any] = {
        "total_sessions": 0,
        "average_session_duration": 0,
        "average_actions_per_session": 0,
        "last_login": None
    }

class AuthEvent(BaseModel):
    """Authentication event document schema"""
    email: EmailStr
    timestamp: datetime
    ip: str
    user_agent: str
    browser: str
    os: str
    device_type: str
    
    # Auth specific
    auth_type: str  # password, oauth, biometric
    success: bool
    failure_reason: Optional[str] = None
    
    # Risk indicators
    risk_indicators: Dict[str, Any] = {
        "new_device": False,
        "new_location": False,
        "unusual_time": False,
        "multiple_failures": False
    }
    
    # Session info
    session_id: Optional[str] = None
    
    # Metadata
    created_at: datetime = Field(default_factory=datetime.utcnow)

class SessionEvent(BaseModel):
    """Session event document schema"""
    email: EmailStr
    session_id: str
    timestamp: datetime
    action: str
    status: str
    duration: int  # milliseconds
    
    # Context
    ip: str
    user_agent: str
    browser: str
    os: str
    device_type: str
    policy_key: str
    service: str
    
    # Additional data
    request_path: Optional[str] = None
    response_code: Optional[int] = None
    error_message: Optional[str] = None
    
    # Risk indicators
    anomaly_scores: Dict[str, float] = {}
    
    created_at: datetime = Field(default_factory=datetime.utcnow)

class RiskAssessment(BaseModel):
    """Risk assessment document schema"""
    request_id: str
    email: EmailStr
    
    # Request data
    request: Dict[str, Any]
    
    # Response data
    response: Dict[str, Any]
    
    # Processing metadata
    processing_metadata: Dict[str, Any] = {
        "models_used": [],
        "feature_count": 0,
        "cache_hit": False,
        "processing_time_ms": 0
    }
    
    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow)
    
class DataAggregator:
    """Helper class for aggregating user data from MongoDB"""
    
    def __init__(self, db: MongoDB):
        self.db = db
        
    async def get_user_profile(self, email: str) -> Optional[Dict[str, Any]]:
        """Get or create user profile"""
        user = await self.db.users.find_one({"email": email})
        
        if not user:
            # Create new user profile
            new_user = UserProfile(email=email)
            await self.db.users.insert_one(new_user.dict())
            return new_user.dict()
            
        return user
        
    async def get_user_auth_history(
        self, 
        email: str, 
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get user's authentication history"""
        cursor = self.db.auth_events.find(
            {"email": email}
        ).sort("timestamp", -1).limit(limit)
        
        return await cursor.to_list(length=limit)
        
    async def get_user_session_history(
        self, 
        email: str, 
        limit: int = 1000
    ) -> List[Dict[str, Any]]:
        """Get user's session history"""
        cursor = self.db.session_events.find(
            {"email": email}
        ).sort("timestamp", -1).limit(limit)
        
        return await cursor.to_list(length=limit)
        
    async def update_user_profile(
        self, 
        email: str, 
        updates: Dict[str, Any]
    ):
        """Update user profile with new patterns"""
        updates["updated_at"] = datetime.utcnow()
        
        await self.db.users.update_one(
            {"email": email},
            {"$set": updates}
        )
        
    async def get_aggregated_user_data(
        self, 
        email: str
    ) -> Dict[str, Any]:
        """Get all relevant user data for fraud detection"""
        
        # Get user profile
        profile = await self.get_user_profile(email)
        
        # Get recent auth events
        auth_history = await self.get_user_auth_history(email, limit=50)
        
        # Get recent session events
        session_history = await self.get_user_session_history(email, limit=200)
        
        # Calculate aggregated statistics
        aggregated_data = {
            "profile": profile,
            "auth_stats": self._calculate_auth_stats(auth_history),
            "session_stats": self._calculate_session_stats(session_history),
            "recent_auth_events": auth_history[:10],
            "recent_session_events": session_history[:20]
        }
        
        return aggregated_data
        
    def _calculate_auth_stats(self, auth_history: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate authentication statistics"""
        if not auth_history:
            return {
                "total_attempts": 0,
                "success_rate": 0,
                "unique_ips": 0,
                "unique_devices": 0
            }
            
        total_attempts = len(auth_history)
        successful_attempts = sum(1 for event in auth_history if event.get("success", False))
        unique_ips = len(set(event.get("ip", "") for event in auth_history))
        unique_devices = len(set(
            f"{event.get('browser', '')}-{event.get('os', '')}-{event.get('device_type', '')}"
            for event in auth_history
        ))
        
        return {
            "total_attempts": total_attempts,
            "success_rate": successful_attempts / total_attempts if total_attempts > 0 else 0,
            "unique_ips": unique_ips,
            "unique_devices": unique_devices
        }
        
    def _calculate_session_stats(self, session_history: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate session statistics"""
        if not session_history:
            return {
                "total_actions": 0,
                "unique_actions": 0,
                "avg_duration": 0,
                "error_rate": 0
            }
            
        total_actions = len(session_history)
        unique_actions = len(set(event.get("action", "") for event in session_history))
        
        durations = [event.get("duration", 0) for event in session_history if event.get("duration")]
        avg_duration = sum(durations) / len(durations) if durations else 0
        
        errors = sum(1 for event in session_history if event.get("status", "").lower() == "false")
        error_rate = errors / total_actions if total_actions > 0 else 0
        
        return {
            "total_actions": total_actions,
            "unique_actions": unique_actions,
            "avg_duration": avg_duration,
            "error_rate": error_rate
        }