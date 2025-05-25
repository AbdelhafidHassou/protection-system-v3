# .env.example
# Copy this file to .env and update with your values

# Application Settings
APP_NAME="Fraud Detection API"
APP_VERSION="1.0.0"
DEBUG=false

# Server Settings
HOST=0.0.0.0
PORT=8000
WORKERS=4

# MongoDB Settings
MONGODB_URI=mongodb://localhost:27017
# For MongoDB with auth:
# MONGODB_URI=mongodb://username:password@localhost:27017/fraud_detection?authSource=admin
MONGODB_DATABASE=fraud_detection

# Redis Settings
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=
REDIS_DB=0

# Security Settings
API_KEY_HEADER=X-API-Key
CORS_ORIGINS=["*"]
# For production, specify allowed origins:
# CORS_ORIGINS=["https://app.example.com", "https://admin.example.com"]

# ML Model Settings
MODEL_DIR=saved_models
MODEL_UPDATE_INTERVAL=3600  # 1 hour in seconds

# Feature Engineering Settings
MAX_HISTORICAL_EVENTS=1000
FEATURE_CACHE_TTL=300  # 5 minutes

# Risk Assessment Settings
RISK_CACHE_TTL=300  # 5 minutes
RISK_THRESHOLD_LOW=0.3
RISK_THRESHOLD_MEDIUM=0.5
RISK_THRESHOLD_HIGH=0.7
RISK_THRESHOLD_CRITICAL=0.85

# Model Weights (must sum to 1.0)
MODEL_WEIGHT_AUTH=0.35
MODEL_WEIGHT_SESSION=0.35
MODEL_WEIGHT_ACCESS=0.30

# Monitoring Settings
ENABLE_METRICS=true
METRICS_PORT=9090

# Logging Settings
LOG_LEVEL=INFO  # DEBUG, INFO, WARNING, ERROR, CRITICAL
LOG_FORMAT=json  # json or plain

# Rate Limiting
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=60  # seconds

# Business Rules
WHITELISTED_IPS=192.168.1.1,10.0.0.1
TRUSTED_SERVICES=trust-service,auth-service
SENSITIVE_ACTIONS=delete,remove,admin,config,permission,export

# Training Settings
TRAINING_BATCH_SIZE=1000
TRAINING_MIN_SAMPLES=10000
ANOMALY_CONTAMINATION=0.1  # Expected proportion of anomalies

# AWS Settings (if deploying to AWS)
# AWS_REGION=us-east-1
# AWS_ACCESS_KEY_ID=
# AWS_SECRET_ACCESS_KEY=

# Notification Settings (optional)
# SMTP_HOST=smtp.gmail.com
# SMTP_PORT=587
# SMTP_USERNAME=
# SMTP_PASSWORD=
# ALERT_EMAIL=security@example.com

# Sentry Settings (optional, for error tracking)
# SENTRY_DSN=https://xxx@xxx.ingest.sentry.io/xxx

# OpenTelemetry Settings (optional, for distributed tracing)
# OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
# OTEL_SERVICE_NAME=fraud-detection-api