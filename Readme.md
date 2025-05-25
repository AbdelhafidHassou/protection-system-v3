# Fraud Detection API System

A comprehensive real-time fraud detection system powered by machine learning, designed to analyze user behavior and identify potential security threats.

## 🚀 Features

- **Real-time Risk Assessment**: Instant fraud detection with sub-second response times
- **Multi-Model ML System**: Three specialized models for comprehensive analysis
  - Authentication Behavior Model
  - Session Anomaly Detection Model
  - Access Time Pattern Model
- **Intelligent Risk Scoring**: Weighted ensemble approach with business rule integration
- **MongoDB Integration**: Flexible document storage for evolving data structures
- **Redis Caching**: High-performance caching for improved response times
- **Production-Ready**: Complete with monitoring, logging, and scalability features

## 📋 Prerequisites

- Python 3.9+
- MongoDB 4.4+
- Redis 6.0+
- Docker & Docker Compose (optional)

## 🛠️ Installation

### Using Docker (Recommended)

1. Clone the repository:
```bash
git clone https://github.com/your-org/fraud-detection-api.git
cd fraud-detection-api
```

2. Start the services:
```bash
docker-compose up -d
```

3. The API will be available at `http://localhost:8000`

### Manual Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Set up MongoDB and Redis locally

3. Configure environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

4. Run the application:
```bash
python main.py
```

## 📊 API Usage

### Analyze Fraud Risk

```bash
curl -X POST "http://localhost:8000/api/v1/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "timestamp": "Wed May 14 16:17:30 UTC 2025",
    "action": "deleteCollaboratorById",
    "status": "true",
    "duration": 266,
    "ip": "192.168.0.69",
    "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0",
    "browser": "Firefox",
    "os": "Windows NT",
    "deviceType": "Desktop",
    "policyKey": "trust_services",
    "service": "trust-service"
  }'
```

### Response Format

```json
{
  "overall_risk_score": 0.234,
  "risk_level": "LOW",
  "model_scores": [
    {
      "model_name": "Authentication Behavior",
      "score": 0.182,
      "confidence": 0.85,
      "factors": ["Normal authentication pattern"]
    },
    {
      "model_name": "Session Anomaly",
      "score": 0.265,
      "confidence": 0.92,
      "factors": ["Normal session behavior"]
    },
    {
      "model_name": "Access Time Pattern",
      "score": 0.241,
      "confidence": 0.88,
      "factors": ["Normal access time"]
    }
  ],
  "risk_factors": [
    {
      "factor": "First time using this device",
      "severity": "MEDIUM",
      "description": "This device has not been seen before for this user. MEDIUM risk as it could indicate account compromise."
    }
  ],
  "recommendations": [
    "Continue monitoring user activity",
    "No immediate action required"
  ],
  "metadata": {
    "request_id": "550e8400-e29b-41d4-a716-446655440000",
    "processing_time_ms": 142,
    "timestamp": "2025-05-23T10:15:30.123456"
  }
}
```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MONGODB_URI` | MongoDB connection string | `mongodb://localhost:27017` |
| `MONGODB_DATABASE` | Database name | `fraud_detection` |
| `REDIS_HOST` | Redis host | `localhost` |
| `REDIS_PORT` | Redis port | `6379` |
| `LOG_LEVEL` | Logging level | `INFO` |
| `MODEL_UPDATE_INTERVAL` | Model retraining interval (seconds) | `3600` |

### Risk Thresholds

Configure risk thresholds in the environment:

- `RISK_THRESHOLD_LOW`: 0.3
- `RISK_THRESHOLD_MEDIUM`: 0.5
- `RISK_THRESHOLD_HIGH`: 0.7
- `RISK_THRESHOLD_CRITICAL`: 0.85

## 📚 API Endpoints

### Core Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/analyze` | POST | Analyze fraud risk for user action |
| `/api/v1/feedback` | POST | Submit feedback on detection accuracy |
| `/api/v1/user/{email}/history` | GET | Get user's risk assessment history |
| `/api/v1/train/trigger` | POST | Trigger model retraining |
| `/health` | GET | Health check endpoint |

### Monitoring Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/metrics` | GET | Prometheus metrics |

## 🧠 Machine Learning Models

### 1. Authentication Behavior Model
- **Purpose**: Detects anomalies in authentication patterns
- **Features**: Time patterns, device fingerprints, IP analysis
- **Algorithm**: Isolation Forest

### 2. Session Anomaly Model
- **Purpose**: Identifies unusual session behaviors
- **Features**: Action patterns, duration analysis, error rates
- **Algorithm**: Random Forest Classifier

### 3. Access Time Model
- **Purpose**: Analyzes temporal access patterns
- **Features**: Hour/day patterns, timezone analysis, velocity
- **Algorithm**: Isolation Forest with user-specific patterns

## 📊 Monitoring

### Prometheus Metrics
Access metrics at `http://localhost:9090/metrics`

### Grafana Dashboards
Access dashboards at `http://localhost:3000` (admin/admin123)

### MongoDB Express
View database at `http://localhost:8081` (admin/admin123)

## 🔒 Security Considerations

1. **API Authentication**: Implement API key authentication in production
2. **HTTPS**: Always use HTTPS in production
3. **Rate Limiting**: Built-in rate limiting per IP/user
4. **Input Validation**: All inputs are validated and sanitized
5. **Logging**: Sensitive data is redacted from logs

## 📈 Performance

- **Response Time**: < 200ms average
- **Throughput**: 1000+ requests/second
- **Caching**: 5-minute TTL for risk assessments
- **Scalability**: Horizontal scaling with Docker Swarm/Kubernetes

## 🧪 Testing

Run the test suite:
```bash
pytest tests/ -v
```

Load testing:
```bash
locust -f tests/load_test.py --host=http://localhost:8000
```

## 🚀 Deployment

### Docker Swarm
```bash
docker stack deploy -c docker-compose.yml fraud-detection
```

### Kubernetes
```bash
kubectl apply -f k8s/
```

### AWS ECS
Use the provided `ecs-task-definition.json`

## 📝 Model Training

### Initial Training
Models are automatically trained on synthetic data during startup.

### Retraining with Real Data
```bash
curl -X POST "http://localhost:8000/api/v1/train/trigger"
```

### Custom Training Script
```python
from models.ml_models import ModelManager
import asyncio

async def train_custom():
    manager = ModelManager()
    await manager.initialize()
    # Load your data
    await manager.retrain_models()

asyncio.run(train_custom())
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- FastAPI for the excellent web framework
- scikit-learn for ML capabilities
- MongoDB for flexible data storage
- Redis for high-performance caching

## 📞 Support

For support, email support@frauddetection.ai or create an issue in the repository.