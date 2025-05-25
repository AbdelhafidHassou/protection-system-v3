# Fraud Detection API Project

## Project Structure Created

This project has been set up with the following structure:

- `core/` - Core business logic
- `models/` - Machine learning models
- `database/` - Database layer
- `utils/` - Utility modules
- `saved_models/` - Trained model storage
- `logs/` - Application logs
- `tests/` - Test suite
- `scripts/` - Utility scripts
- `grafana-dashboards/` - Monitoring dashboards
- `k8s/` - Kubernetes configurations

## Next Steps

1. Copy all the Python files from the artifacts to their respective locations
2. Copy configuration files (Dockerfile, docker-compose.yml, etc.)
3. Set up your environment variables by copying .env.example to .env
4. Run `docker-compose up -d` to start all services

## Quick Commands

- Start services: `docker-compose up -d`
- View logs: `docker-compose logs -f api`
- Run tests: `python test_api.py`
- Stop services: `docker-compose down`

