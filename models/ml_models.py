# models/ml_models.py
import os
import pickle
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
import asyncio

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score

logger = logging.getLogger(__name__)

class AuthenticationBehaviorModel:
    """Model for detecting authentication anomalies"""
    
    def __init__(self):
        self.model = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        self.scaler = StandardScaler()
        self.label_encoders = {}
        self.is_trained = False
        self.feature_names = []
        
    def prepare_features(self, data: pd.DataFrame) -> np.ndarray:
        """Prepare features for authentication behavior analysis"""
        features = []
        
        # Time-based features
        if 'timestamp' in data.columns:
            data['hour'] = pd.to_datetime(data['timestamp']).dt.hour
            data['day_of_week'] = pd.to_datetime(data['timestamp']).dt.dayofweek
            data['is_weekend'] = data['day_of_week'].isin([5, 6]).astype(int)
            data['is_business_hours'] = data['hour'].between(9, 17).astype(int)
            features.extend(['hour', 'day_of_week', 'is_weekend', 'is_business_hours'])
        
        # Device features
        categorical_features = ['browser', 'os', 'device_type']
        for feature in categorical_features:
            if feature in data.columns:
                if feature not in self.label_encoders:
                    self.label_encoders[feature] = LabelEncoder()
                    data[f'{feature}_encoded'] = self.label_encoders[feature].fit_transform(
                        data[feature].fillna('unknown')
                    )
                else:
                    # Handle unseen categories
                    data[f'{feature}_encoded'] = data[feature].apply(
                        lambda x: self.label_encoders[feature].transform([x])[0]
                        if x in self.label_encoders[feature].classes_
                        else -1
                    )
                features.append(f'{feature}_encoded')
        
        # IP-based features (simplified for this example)
        if 'ip' in data.columns:
            data['ip_octets'] = data['ip'].apply(
                lambda x: [int(octet) for octet in x.split('.')]
                if pd.notna(x) and '.' in x else [0, 0, 0, 0]
            )
            for i in range(4):
                data[f'ip_octet_{i}'] = data['ip_octets'].apply(lambda x: x[i] if len(x) > i else 0)
                features.append(f'ip_octet_{i}')
        
        # Historical behavior features (would be enriched from user profile)
        if 'auth_failure_count' in data.columns:
            features.append('auth_failure_count')
        
        self.feature_names = features
        return data[features].values
    
    def train(self, training_data: pd.DataFrame):
        """Train the authentication behavior model"""
        try:
            logger.info("Training Authentication Behavior Model...")
            
            # Prepare features
            X = self.prepare_features(training_data)
            
            # Scale features
            X_scaled = self.scaler.fit_transform(X)
            
            # Train model
            self.model.fit(X_scaled)
            self.is_trained = True
            
            logger.info(f"Authentication model trained on {len(X)} samples")
            
        except Exception as e:
            logger.error(f"Error training authentication model: {str(e)}")
            raise
    
    def predict(self, features: Dict[str, Any]) -> Tuple[float, float, List[str]]:
        """Predict authentication risk score"""
        if not self.is_trained:
            # Return neutral score if model not trained
            return 0.5, 0.5, ["Model not trained"]
        
        try:
            # Convert to DataFrame for feature preparation
            df = pd.DataFrame([features])
            X = self.prepare_features(df)
            X_scaled = self.scaler.transform(X)
            
            # Get anomaly score (-1 for anomaly, 1 for normal)
            prediction = self.model.predict(X_scaled)[0]
            anomaly_score = self.model.score_samples(X_scaled)[0]
            
            # Convert to risk score (0-1)
            risk_score = 1 / (1 + np.exp(anomaly_score))
            confidence = 0.8 if abs(anomaly_score) > 0.5 else 0.6
            
            # Identify risk factors
            risk_factors = self._identify_auth_risk_factors(features, risk_score)
            
            return risk_score, confidence, risk_factors
            
        except Exception as e:
            logger.error(f"Error in authentication prediction: {str(e)}")
            return 0.5, 0.3, ["Prediction error"]
    
    def _identify_auth_risk_factors(self, features: Dict[str, Any], risk_score: float) -> List[str]:
        """Identify specific authentication risk factors"""
        factors = []
        
        if risk_score > 0.7:
            # Check for unusual access time
            hour = datetime.fromisoformat(features.get('timestamp', '')).hour
            if hour < 6 or hour > 22:
                factors.append("Unusual access time")
            
            # Check for new device
            if features.get('is_new_device', False):
                factors.append("New device detected")
            
            # Check for location anomaly
            if features.get('is_new_location', False):
                factors.append("New location detected")
        
        return factors if factors else ["Normal authentication pattern"]

class SessionAnomalyModel:
    """Model for detecting session-level anomalies"""
    
    def __init__(self):
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        self.feature_importance = {}
        
    def prepare_features(self, session_data: pd.DataFrame) -> np.ndarray:
        """Prepare features for session anomaly detection"""
        features = []
        
        # Action-based features
        if 'action' in session_data.columns:
            # Action frequency
            action_counts = session_data['action'].value_counts()
            session_data['action_frequency'] = session_data['action'].map(action_counts)
            features.append('action_frequency')
            
            # Action sequence patterns (simplified)
            session_data['action_length'] = session_data['action'].str.len()
            features.append('action_length')
        
        # Duration features
        if 'duration' in session_data.columns:
            session_data['duration_log'] = np.log1p(session_data['duration'])
            features.append('duration_log')
            
            # Duration anomaly
            duration_mean = session_data['duration'].mean()
            duration_std = session_data['duration'].std()
            session_data['duration_zscore'] = (
                (session_data['duration'] - duration_mean) / duration_std
            ).fillna(0)
            features.append('duration_zscore')
        
        # Status features
        if 'status' in session_data.columns:
            session_data['is_failure'] = (session_data['status'] == 'false').astype(int)
            features.append('is_failure')
        
        # Service and policy features
        if 'service' in session_data.columns:
            service_counts = session_data['service'].value_counts()
            session_data['service_frequency'] = session_data['service'].map(service_counts)
            features.append('service_frequency')
        
        # Session velocity features (actions per time)
        if len(session_data) > 1:
            session_data['actions_per_minute'] = len(session_data) / 60  # Simplified
            features.append('actions_per_minute')
        
        return session_data[features].fillna(0).values
    
    def train(self, training_data: pd.DataFrame, labels: Optional[np.ndarray] = None):
        """Train the session anomaly model"""
        try:
            logger.info("Training Session Anomaly Model...")
            
            # Prepare features
            X = self.prepare_features(training_data)
            
            # Generate synthetic labels if not provided
            if labels is None:
                # Simple heuristic for anomaly labels
                labels = self._generate_synthetic_labels(training_data)
            
            # Scale features
            X_scaled = self.scaler.fit_transform(X)
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X_scaled, labels, test_size=0.2, random_state=42
            )
            
            # Train model
            self.model.fit(X_train, y_train)
            self.is_trained = True
            
            # Evaluate
            y_pred = self.model.predict(X_test)
            logger.info(f"Session model accuracy: {self.model.score(X_test, y_test):.3f}")
            
            # Store feature importance
            self.feature_importance = dict(zip(
                range(len(self.model.feature_importances_)),
                self.model.feature_importances_
            ))
            
        except Exception as e:
            logger.error(f"Error training session model: {str(e)}")
            raise
    
    def _generate_synthetic_labels(self, data: pd.DataFrame) -> np.ndarray:
        """Generate synthetic anomaly labels based on heuristics"""
        labels = np.zeros(len(data))
        
        # Mark as anomaly if:
        # - Very high duration
        if 'duration' in data.columns:
            high_duration_threshold = data['duration'].quantile(0.95)
            labels[data['duration'] > high_duration_threshold] = 1
        
        # - Failed status
        if 'status' in data.columns:
            labels[data['status'] == 'false'] = 1
        
        # - Unusual actions
        if 'action' in data.columns:
            rare_actions = data['action'].value_counts().tail(10).index
            labels[data['action'].isin(rare_actions)] = 1
        
        return labels
    
    def predict(self, session_features: Dict[str, Any]) -> Tuple[float, float, List[str]]:
        """Predict session anomaly risk score"""
        if not self.is_trained:
            return 0.5, 0.5, ["Model not trained"]
        
        try:
            # Convert to DataFrame
            df = pd.DataFrame([session_features])
            X = self.prepare_features(df)
            X_scaled = self.scaler.transform(X)
            
            # Get prediction probability
            risk_probability = self.model.predict_proba(X_scaled)[0][1]
            
            # Confidence based on prediction probability distance from 0.5
            confidence = 2 * abs(risk_probability - 0.5)
            
            # Identify risk factors
            risk_factors = self._identify_session_risk_factors(
                session_features, 
                risk_probability
            )
            
            return risk_probability, confidence, risk_factors
            
        except Exception as e:
            logger.error(f"Error in session prediction: {str(e)}")
            return 0.5, 0.3, ["Prediction error"]
    
    def _identify_session_risk_factors(
        self, 
        features: Dict[str, Any], 
        risk_score: float
    ) -> List[str]:
        """Identify specific session risk factors"""
        factors = []
        
        if risk_score > 0.6:
            # Check duration
            if features.get('duration', 0) > 5000:  # 5 seconds
                factors.append("Unusually long action duration")
            
            # Check status
            if features.get('status') == 'false':
                factors.append("Action failed")
            
            # Check for suspicious actions
            suspicious_actions = ['deleteCollaboratorById', 'removeUser', 'deleteData']
            if features.get('action') in suspicious_actions:
                factors.append(f"Sensitive action: {features.get('action')}")
        
        return factors if factors else ["Normal session behavior"]

class AccessTimeModel:
    """Model for analyzing access time patterns"""
    
    def __init__(self):
        self.model = IsolationForest(
            contamination=0.05,
            random_state=42
        )
        self.is_trained = False
        self.user_patterns = {}
        
    def prepare_features(self, access_data: pd.DataFrame) -> np.ndarray:
        """Prepare features for access time analysis"""
        features = []
        
        # Time features
        if 'timestamp' in access_data.columns:
            access_data['hour'] = pd.to_datetime(access_data['timestamp']).dt.hour
            access_data['minute'] = pd.to_datetime(access_data['timestamp']).dt.minute
            access_data['day_of_week'] = pd.to_datetime(access_data['timestamp']).dt.dayofweek
            access_data['day_of_month'] = pd.to_datetime(access_data['timestamp']).dt.day
            access_data['month'] = pd.to_datetime(access_data['timestamp']).dt.month
            
            # Time-based patterns
            access_data['is_weekend'] = access_data['day_of_week'].isin([5, 6]).astype(int)
            access_data['is_business_hours'] = access_data['hour'].between(9, 17).astype(int)
            access_data['is_night'] = ((access_data['hour'] < 6) | (access_data['hour'] > 22)).astype(int)
            
            # Cyclic encoding for hour
            access_data['hour_sin'] = np.sin(2 * np.pi * access_data['hour'] / 24)
            access_data['hour_cos'] = np.cos(2 * np.pi * access_data['hour'] / 24)
            
            # Cyclic encoding for day of week
            access_data['dow_sin'] = np.sin(2 * np.pi * access_data['day_of_week'] / 7)
            access_data['dow_cos'] = np.cos(2 * np.pi * access_data['day_of_week'] / 7)
            
            features = [
                'hour', 'day_of_week', 'is_weekend', 'is_business_hours', 
                'is_night', 'hour_sin', 'hour_cos', 'dow_sin', 'dow_cos'
            ]
        
        return access_data[features].values
    
    def train(self, training_data: pd.DataFrame):
        """Train the access time model"""
        try:
            logger.info("Training Access Time Model...")
            
            # Prepare features
            X = self.prepare_features(training_data)
            
            # Train model
            self.model.fit(X)
            self.is_trained = True
            
            # Build user-specific patterns
            if 'email' in training_data.columns:
                self._build_user_patterns(training_data)
            
            logger.info(f"Access time model trained on {len(X)} samples")
            
        except Exception as e:
            logger.error(f"Error training access time model: {str(e)}")
            raise
    
    def _build_user_patterns(self, data: pd.DataFrame):
        """Build user-specific access patterns"""
        for email in data['email'].unique():
            user_data = data[data['email'] == email]
            
            if 'timestamp' in user_data.columns:
                timestamps = pd.to_datetime(user_data['timestamp'])
                
                self.user_patterns[email] = {
                    'typical_hours': timestamps.dt.hour.mode().tolist(),
                    'typical_days': timestamps.dt.dayofweek.mode().tolist(),
                    'access_count': len(user_data),
                    'hour_distribution': timestamps.dt.hour.value_counts().to_dict(),
                    'day_distribution': timestamps.dt.dayofweek.value_counts().to_dict()
                }
    
    def predict(self, access_features: Dict[str, Any]) -> Tuple[float, float, List[str]]:
        """Predict access time risk score"""
        if not self.is_trained:
            return 0.5, 0.5, ["Model not trained"]
        
        try:
            # Convert to DataFrame
            df = pd.DataFrame([access_features])
            X = self.prepare_features(df)
            
            # Get anomaly score
            anomaly_score = self.model.score_samples(X)[0]
            
            # Convert to risk score
            risk_score = 1 / (1 + np.exp(anomaly_score * 2))
            
            # Check user-specific patterns
            email = access_features.get('email')
            if email in self.user_patterns:
                user_risk = self._calculate_user_specific_risk(
                    access_features, 
                    self.user_patterns[email]
                )
                # Combine global and user-specific risk
                risk_score = 0.7 * risk_score + 0.3 * user_risk
            
            confidence = 0.85 if email in self.user_patterns else 0.65
            
            # Identify risk factors
            risk_factors = self._identify_time_risk_factors(access_features, risk_score)
            
            return risk_score, confidence, risk_factors
            
        except Exception as e:
            logger.error(f"Error in access time prediction: {str(e)}")
            return 0.5, 0.3, ["Prediction error"]
    
    def _calculate_user_specific_risk(
        self, 
        features: Dict[str, Any], 
        user_pattern: Dict[str, Any]
    ) -> float:
        """Calculate risk based on user's specific patterns"""
        risk_score = 0.0
        
        timestamp = pd.to_datetime(features.get('timestamp'))
        hour = timestamp.hour
        day_of_week = timestamp.dayofweek
        
        # Check if access is during typical hours
        if hour not in user_pattern.get('typical_hours', []):
            hour_freq = user_pattern['hour_distribution'].get(hour, 0)
            total_accesses = user_pattern['access_count']
            if hour_freq / total_accesses < 0.05:  # Less than 5% of accesses
                risk_score += 0.4
        
        # Check if access is on typical days
        if day_of_week not in user_pattern.get('typical_days', []):
            day_freq = user_pattern['day_distribution'].get(day_of_week, 0)
            if day_freq / total_accesses < 0.1:  # Less than 10% of accesses
                risk_score += 0.3
        
        return min(risk_score, 1.0)
    
    def _identify_time_risk_factors(
        self, 
        features: Dict[str, Any], 
        risk_score: float
    ) -> List[str]:
        """Identify specific time-based risk factors"""
        factors = []
        
        if risk_score > 0.6:
            timestamp = pd.to_datetime(features.get('timestamp'))
            hour = timestamp.hour
            day_of_week = timestamp.dayofweek
            
            # Check for unusual hours
            if hour < 6 or hour > 22:
                factors.append(f"Access at unusual hour: {hour:02d}:00")
            
            # Check for weekend access
            if day_of_week in [5, 6]:
                factors.append("Weekend access detected")
            
            # Check for midnight access
            if 0 <= hour <= 4:
                factors.append("Midnight access detected")
        
        return factors if factors else ["Normal access time"]

class ModelManager:
    """Manages all fraud detection models"""
    
    def __init__(self):
        self.auth_model = AuthenticationBehaviorModel()
        self.session_model = SessionAnomalyModel()
        self.access_model = AccessTimeModel()
        self.is_ready = False
        self.model_dir = "saved_models"
        
    async def initialize(self):
        """Initialize all models"""
        try:
            # Create model directory if not exists
            os.makedirs(self.model_dir, exist_ok=True)
            
            # Load pre-trained models if available
            await self.load_models()
            
            # If no saved models, train on synthetic data
            if not self.is_ready:
                await self.train_on_synthetic_data()
            
            self.is_ready = True
            logger.info("All models initialized successfully")
            
        except Exception as e:
            logger.error(f"Error initializing models: {str(e)}")
            raise
    
    async def train_on_synthetic_data(self):
        """Train models on synthetic data for initial deployment"""
        logger.info("Training models on synthetic data...")
        
        # Generate synthetic training data
        synthetic_data = self._generate_synthetic_data(n_samples=10000)
        
        # Train each model
        await asyncio.gather(
            asyncio.to_thread(self.auth_model.train, synthetic_data),
            asyncio.to_thread(self.session_model.train, synthetic_data),
            asyncio.to_thread(self.access_model.train, synthetic_data)
        )
        
        # Save models
        await self.save_models()
        
    def _generate_synthetic_data(self, n_samples: int) -> pd.DataFrame:
        """Generate synthetic training data"""
        np.random.seed(42)
        
        # Generate timestamps
        base_time = datetime.now() - timedelta(days=30)
        timestamps = [
            base_time + timedelta(
                days=np.random.randint(0, 30),
                hours=np.random.randint(0, 24),
                minutes=np.random.randint(0, 60)
            )
            for _ in range(n_samples)
        ]
        
        # Generate features
        data = pd.DataFrame({
            'email': [f'user{i % 100}@example.com' for i in range(n_samples)],
            'timestamp': timestamps,
            'action': np.random.choice(
                ['login', 'view', 'edit', 'delete', 'share', 'download'],
                n_samples
            ),
            'status': np.random.choice(['true', 'false'], n_samples, p=[0.95, 0.05]),
            'duration': np.random.lognormal(6, 1.5, n_samples).astype(int),
            'ip': [f'192.168.{np.random.randint(0, 255)}.{np.random.randint(0, 255)}' 
                   for _ in range(n_samples)],
            'browser': np.random.choice(
                ['Chrome', 'Firefox', 'Safari', 'Edge'],
                n_samples,
                p=[0.6, 0.2, 0.15, 0.05]
            ),
            'os': np.random.choice(
                ['Windows', 'MacOS', 'Linux', 'iOS', 'Android'],
                n_samples,
                p=[0.5, 0.25, 0.1, 0.1, 0.05]
            ),
            'device_type': np.random.choice(
                ['Desktop', 'Mobile', 'Tablet'],
                n_samples,
                p=[0.7, 0.25, 0.05]
            ),
            'policy_key': np.random.choice(
                ['trust_services', 'admin', 'user', 'guest'],
                n_samples
            ),
            'service': np.random.choice(
                ['trust-service', 'auth-service', 'data-service'],
                n_samples
            )
        })
        
        return data
    
    async def predict_all(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Get predictions from all models"""
        predictions = {}
        
        # Run predictions in parallel
        auth_task = asyncio.to_thread(self.auth_model.predict, features)
        session_task = asyncio.to_thread(self.session_model.predict, features)
        access_task = asyncio.to_thread(self.access_model.predict, features)
        
        auth_result, session_result, access_result = await asyncio.gather(
            auth_task, session_task, access_task
        )
        
        predictions['authentication'] = {
            'score': auth_result[0],
            'confidence': auth_result[1],
            'factors': auth_result[2]
        }
        
        predictions['session'] = {
            'score': session_result[0],
            'confidence': session_result[1],
            'factors': session_result[2]
        }
        
        predictions['access_time'] = {
            'score': access_result[0],
            'confidence': access_result[1],
            'factors': access_result[2]
        }
        
        return predictions
    
    async def save_models(self):
        """Save all models to disk"""
        try:
            # Save authentication model
            with open(f"{self.model_dir}/auth_model.pkl", 'wb') as f:
                pickle.dump({
                    'model': self.auth_model.model,
                    'scaler': self.auth_model.scaler,
                    'label_encoders': self.auth_model.label_encoders,
                    'feature_names': self.auth_model.feature_names
                }, f)
            
            # Save session model
            with open(f"{self.model_dir}/session_model.pkl", 'wb') as f:
                pickle.dump({
                    'model': self.session_model.model,
                    'scaler': self.session_model.scaler,
                    'feature_importance': self.session_model.feature_importance
                }, f)
            
            # Save access time model
            with open(f"{self.model_dir}/access_model.pkl", 'wb') as f:
                pickle.dump({
                    'model': self.access_model.model,
                    'user_patterns': self.access_model.user_patterns
                }, f)
            
            logger.info("All models saved successfully")
            
        except Exception as e:
            logger.error(f"Error saving models: {str(e)}")
    
    async def load_models(self):
        """Load pre-trained models from disk"""
        try:
            # Load authentication model
            if os.path.exists(f"{self.model_dir}/auth_model.pkl"):
                with open(f"{self.model_dir}/auth_model.pkl", 'rb') as f:
                    auth_data = pickle.load(f)
                    self.auth_model.model = auth_data['model']
                    self.auth_model.scaler = auth_data['scaler']
                    self.auth_model.label_encoders = auth_data['label_encoders']
                    self.auth_model.feature_names = auth_data['feature_names']
                    self.auth_model.is_trained = True
            
            # Load session model
            if os.path.exists(f"{self.model_dir}/session_model.pkl"):
                with open(f"{self.model_dir}/session_model.pkl", 'rb') as f:
                    session_data = pickle.load(f)
                    self.session_model.model = session_data['model']
                    self.session_model.scaler = session_data['scaler']
                    self.session_model.feature_importance = session_data['feature_importance']
                    self.session_model.is_trained = True
            
            # Load access time model
            if os.path.exists(f"{self.model_dir}/access_model.pkl"):
                with open(f"{self.model_dir}/access_model.pkl", 'rb') as f:
                    access_data = pickle.load(f)
                    self.access_model.model = access_data['model']
                    self.access_model.user_patterns = access_data['user_patterns']
                    self.access_model.is_trained = True
            
            # Check if all models are loaded
            if (self.auth_model.is_trained and 
                self.session_model.is_trained and 
                self.access_model.is_trained):
                self.is_ready = True
                logger.info("All models loaded successfully")
            
        except Exception as e:
            logger.error(f"Error loading models: {str(e)}")
    
    async def retrain_models(self, model_name: Optional[str] = None):
        """Retrain models with new data"""
        logger.info(f"Retraining {'all models' if not model_name else model_name}...")
        
        # This would fetch real data from MongoDB in production
        # For now, we'll use synthetic data
        training_data = self._generate_synthetic_data(n_samples=20000)
        
        if model_name == 'authentication' or model_name is None:
            await asyncio.to_thread(self.auth_model.train, training_data)
        
        if model_name == 'session' or model_name is None:
            await asyncio.to_thread(self.session_model.train, training_data)
        
        if model_name == 'access_time' or model_name is None:
            await asyncio.to_thread(self.access_model.train, training_data)
        
        # Save updated models
        await self.save_models()
        
        logger.info("Model retraining completed")