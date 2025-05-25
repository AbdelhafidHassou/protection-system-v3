# database/mongodb.py
import os
from typing import Optional, Dict, Any
from datetime import datetime
import logging

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from pymongo import ASCENDING, DESCENDING, IndexModel
from pymongo.errors import ConnectionFailure

logger = logging.getLogger(__name__)

class MongoDB:
    """MongoDB connection and database operations manager"""
    
    def __init__(self):
        self.client: Optional[AsyncIOMotorClient] = None
        self.db: Optional[AsyncIOMotorDatabase] = None
        self.is_connected = False
        
        # MongoDB configuration
        self.mongo_uri = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
        self.database_name = os.getenv("MONGODB_DATABASE", "fraud_detection")
        
    async def connect(self):
        """Establish connection to MongoDB"""
        try:
            self.client = AsyncIOMotorClient(self.mongo_uri)
            self.db = self.client[self.database_name]
            
            # Test connection
            await self.client.admin.command('ping')
            self.is_connected = True
            
            # Create indexes
            await self._create_indexes()
            
            logger.info(f"Connected to MongoDB at {self.mongo_uri}")
            
        except ConnectionFailure as e:
            logger.error(f"Failed to connect to MongoDB: {str(e)}")
            raise
            
    async def close(self):
        """Close MongoDB connection"""
        if self.client:
            self.client.close()
            self.is_connected = False
            logger.info("MongoDB connection closed")
            
    async def _create_indexes(self):
        """Create necessary indexes for optimal performance"""
        try:
            # Users collection indexes
            users_indexes = [
                IndexModel([("email", ASCENDING)], unique=True),
                IndexModel([("created_at", DESCENDING)]),
                IndexModel([("risk_profile.current_risk_level", ASCENDING)])
            ]
            await self.db.users.create_indexes(users_indexes)
            
            # Auth events indexes
            auth_indexes = [
                IndexModel([("email", ASCENDING), ("timestamp", DESCENDING)]),
                IndexModel([("timestamp", DESCENDING)]),
                IndexModel([("ip", ASCENDING)]),
                IndexModel([("success", ASCENDING)])
            ]
            await self.db.auth_events.create_indexes(auth_indexes)
            
            # Session events indexes
            session_indexes = [
                IndexModel([("email", ASCENDING), ("timestamp", DESCENDING)]),
                IndexModel([("session_id", ASCENDING)]),
                IndexModel([("action", ASCENDING)]),
                IndexModel([("timestamp", DESCENDING)])
            ]
            await self.db.session_events.create_indexes(session_indexes)
            
            # Risk assessments indexes
            risk_indexes = [
                IndexModel([("request.email", ASCENDING), ("created_at", DESCENDING)]),
                IndexModel([("response.risk_level", ASCENDING)]),
                IndexModel([("created_at", DESCENDING)]),
                IndexModel([("metadata.request_id", ASCENDING)], unique=True)
            ]
            await self.db.risk_assessments.create_indexes(risk_indexes)
            
            # Feedback collection indexes
            feedback_indexes = [
                IndexModel([("email", ASCENDING), ("created_at", DESCENDING)]),
                IndexModel([("request_id", ASCENDING)]),
                IndexModel([("was_fraud", ASCENDING)])
            ]
            await self.db.feedback.create_indexes(feedback_indexes)
            
            logger.info("Database indexes created successfully")
            
        except Exception as e:
            logger.error(f"Error creating indexes: {str(e)}")
            
    @property
    def users(self):
        """Access users collection"""
        return self.db.users
        
    @property
    def auth_events(self):
        """Access authentication events collection"""
        return self.db.auth_events
        
    @property
    def session_events(self):
        """Access session events collection"""
        return self.db.session_events
        
    @property
    def risk_assessments(self):
        """Access risk assessments collection"""
        return self.db.risk_assessments
        
    @property
    def feedback(self):
        """Access feedback collection"""
        return self.db.feedback

