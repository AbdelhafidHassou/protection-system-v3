# main.py
import logging
from datetime import datetime
from typing import Dict, Any, Optional
import asyncio
import json

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from motor.motor_asyncio import AsyncIOMotorClient
import redis.asyncio as redis
import numpy as np
from contextlib import asynccontextmanager

# Import our custom modules
from models.ml_models import ModelManager
from database.mongodb import MongoDB
from core.feature_engineering import FeatureEngineering
from core.risk_engine import RiskEngine
from utils.logging_config import setup_logging

# Setup logging
logger = setup_logging()

# Global instances
db_client: Optional[MongoDB] = None
redis_client: Optional[redis.Redis] = None
model_manager: Optional[ModelManager] = None

# Pydantic models for API
class FraudDetectionRequest(BaseModel):
    email: EmailStr
    timestamp: str
    action: str
    status: str
    duration: int = Field(gt=0)
    ip: str
    userAgent: str
    browser: str
    os: str
    deviceType: str
    policyKey: str
    service: str

class RiskFactor(BaseModel):
    factor: str
    severity: str
    description: str

class ModelScore(BaseModel):
    model_name: str
    score: float
    confidence: float
    factors: list[str]

class FraudDetectionResponse(BaseModel):
    overall_risk_score: float
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    model_scores: list[ModelScore]
    risk_factors: list[RiskFactor]
    recommendations: list[str]
    metadata: Dict[str, Any]

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    global db_client, redis_client, model_manager
    
    logger.info("Starting up Fraud Detection API...")
    
    # Initialize MongoDB
    db_client = MongoDB()
    await db_client.connect()
    
    # Initialize Redis
    redis_client = redis.Redis(
        host='localhost',
        port=6379,
        decode_responses=True
    )
    
    # Initialize ML models
    model_manager = ModelManager()
    await model_manager.initialize()
    
    logger.info("All services initialized successfully")
    
    yield
    
    # Shutdown
    logger.info("Shutting down Fraud Detection API...")
    await db_client.close()
    await redis_client.close()

# Create FastAPI app
app = FastAPI(
    title="Fraud Detection API",
    description="Real-time fraud detection system with ML-powered risk assessment",
    version="1.0.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "services": {
            "database": db_client.is_connected if db_client else False,
            "cache": await redis_client.ping() if redis_client else False,
            "models": model_manager.is_ready if model_manager else False
        }
    }

@app.post("/api/v1/analyze", response_model=FraudDetectionResponse)
async def analyze_fraud_risk(
    request: FraudDetectionRequest,
    background_tasks: BackgroundTasks
):
    """
    Analyze fraud risk for a given user action
    """
    try:
        # Check cache first
        cache_key = f"fraud:{request.email}:{request.action}:{request.timestamp}"
        cached_result = await redis_client.get(cache_key)
        
        if cached_result:
            logger.info(f"Cache hit for {cache_key}")
            return json.loads(cached_result)
        
        # Convert request to dict for processing
        request_data = request.dict()
        
        # Feature engineering
        feature_eng = FeatureEngineering()
        features = await feature_eng.extract_features(request_data, db_client)
        
        # Get predictions from all models
        predictions = await model_manager.predict_all(features)
        
        # Risk assessment
        risk_engine = RiskEngine()
        risk_assessment = await risk_engine.assess_risk(
            predictions,
            request_data,
            features
        )
        
        # Prepare response
        response = FraudDetectionResponse(
            overall_risk_score=risk_assessment['overall_score'],
            risk_level=risk_assessment['risk_level'],
            model_scores=[
                ModelScore(
                    model_name=score['model_name'],
                    score=score['score'],
                    confidence=score['confidence'],
                    factors=score['factors']
                )
                for score in risk_assessment['model_scores']
            ],
            risk_factors=[
                RiskFactor(
                    factor=factor['factor'],
                    severity=factor['severity'],
                    description=factor['description']
                )
                for factor in risk_assessment['risk_factors']
            ],
            recommendations=risk_assessment['recommendations'],
            metadata={
                "request_id": risk_assessment['request_id'],
                "processing_time_ms": risk_assessment['processing_time_ms'],
                "timestamp": datetime.utcnow().isoformat()
            }
        )
        
        # Cache the result
        await redis_client.setex(
            cache_key,
            300,  # 5 minutes TTL
            json.dumps(response.dict())
        )
        
        # Store in database asynchronously
        background_tasks.add_task(
            store_risk_assessment,
            request_data,
            response.dict()
        )
        
        return response
        
    except Exception as e:
        logger.error(f"Error in fraud analysis: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")

async def store_risk_assessment(request_data: dict, response_data: dict):
    """Store risk assessment in database"""
    try:
        assessment_doc = {
            "request": request_data,
            "response": response_data,
            "created_at": datetime.utcnow()
        }
        await db_client.risk_assessments.insert_one(assessment_doc)
    except Exception as e:
        logger.error(f"Error storing risk assessment: {str(e)}")

@app.post("/api/v1/feedback")
async def submit_feedback(
    email: str,
    request_id: str,
    was_fraud: bool,
    feedback: Optional[str] = None
):
    """Submit feedback on fraud detection accuracy"""
    try:
        feedback_doc = {
            "email": email,
            "request_id": request_id,
            "was_fraud": was_fraud,
            "feedback": feedback,
            "created_at": datetime.utcnow()
        }
        
        await db_client.feedback.insert_one(feedback_doc)
        
        # Trigger model retraining if needed
        # This would be handled by a separate service in production
        
        return {"status": "success", "message": "Feedback recorded"}
        
    except Exception as e:
        logger.error(f"Error submitting feedback: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/v1/user/{email}/history")
async def get_user_history(email: str, limit: int = 100):
    """Get user's fraud detection history"""
    try:
        # Get recent assessments for user
        assessments = await db_client.risk_assessments.find(
            {"request.email": email}
        ).sort("created_at", -1).limit(limit).to_list(length=limit)
        
        # Calculate statistics
        total_assessments = len(assessments)
        high_risk_count = sum(
            1 for a in assessments 
            if a['response']['risk_level'] in ['HIGH', 'CRITICAL']
        )
        
        return {
            "email": email,
            "total_assessments": total_assessments,
            "high_risk_count": high_risk_count,
            "risk_percentage": (high_risk_count / total_assessments * 100) if total_assessments > 0 else 0,
            "recent_assessments": [
                {
                    "timestamp": a['created_at'],
                    "action": a['request']['action'],
                    "risk_level": a['response']['risk_level'],
                    "risk_score": a['response']['overall_risk_score']
                }
                for a in assessments[:10]  # Last 10 assessments
            ]
        }
        
    except Exception as e:
        logger.error(f"Error getting user history: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/api/v1/train/trigger")
async def trigger_training(
    model_name: Optional[str] = None,
    background_tasks: BackgroundTasks = BackgroundTasks()
):
    """Trigger model retraining"""
    try:
        if not model_manager:
            raise HTTPException(status_code=503, detail="Model manager not initialized")
        
        background_tasks.add_task(
            model_manager.retrain_models,
            model_name
        )
        
        return {
            "status": "success",
            "message": f"Training triggered for {'all models' if not model_name else model_name}"
        }
        
    except Exception as e:
        logger.error(f"Error triggering training: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )