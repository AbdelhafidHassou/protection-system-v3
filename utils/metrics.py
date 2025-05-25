# utils/metrics.py
from prometheus_client import Counter, Histogram, Gauge, generate_latest
import time
from functools import wraps
from typing import Callable

# Define metrics
api_requests_total = Counter(
    'fraud_detection_api_requests_total',
    'Total API requests',
    ['method', 'endpoint', 'status']
)

api_request_duration = Histogram(
    'fraud_detection_api_request_duration_seconds',
    'API request duration',
    ['method', 'endpoint']
)

risk_assessments_total = Counter(
    'fraud_detection_risk_assessments_total',
    'Total risk assessments',
    ['risk_level']
)

model_predictions = Histogram(
    'fraud_detection_model_predictions',
    'Model prediction scores',
    ['model_name']
)

cache_hits = Counter(
    'fraud_detection_cache_hits_total',
    'Cache hit count',
    ['cache_type']
)

active_sessions = Gauge(
    'fraud_detection_active_sessions',
    'Number of active sessions'
)

def track_request_metrics(method: str, endpoint: str):
    """Decorator to track API request metrics"""
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            start_time = time.time()
            status = "success"
            
            try:
                result = await func(*args, **kwargs)
                return result
            except Exception as e:
                status = "error"
                raise
            finally:
                duration = time.time() - start_time
                api_requests_total.labels(
                    method=method,
                    endpoint=endpoint,
                    status=status
                ).inc()
                api_request_duration.labels(
                    method=method,
                    endpoint=endpoint
                ).observe(duration)
        
        return wrapper
    return decorator

def track_risk_assessment(risk_level: str):
    """Track risk assessment metrics"""
    risk_assessments_total.labels(risk_level=risk_level).inc()

def track_model_prediction(model_name: str, score: float):
    """Track model prediction metrics"""
    model_predictions.labels(model_name=model_name).observe(score)

def track_cache_hit(cache_type: str):
    """Track cache hit metrics"""
    cache_hits.labels(cache_type=cache_type).inc()