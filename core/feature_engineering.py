# core/feature_engineering.py
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import hashlib
import ipaddress

import numpy as np
import pandas as pd
from collections import defaultdict

from database.mongodb import MongoDB
from database.models import DataAggregator

logger = logging.getLogger(__name__)

class FeatureEngineering:
    """Feature engineering for fraud detection models"""
    
    def __init__(self):
        self.feature_cache = {}
        self.feature_stats = defaultdict(dict)
        
    async def extract_features(
        self, 
        request_data: Dict[str, Any],
        db: MongoDB
    ) -> Dict[str, Any]:
        """Extract all features from request and historical data"""
        try:
            # Start with basic request features
            features = self._extract_basic_features(request_data)
            
            # Get user aggregated data
            aggregator = DataAggregator(db)
            user_data = await aggregator.get_aggregated_user_data(request_data['email'])
            
            # Extract historical features
            historical_features = self._extract_historical_features(user_data)
            features.update(historical_features)
            
            # Extract behavioral features
            behavioral_features = self._extract_behavioral_features(request_data, user_data)
            features.update(behavioral_features)
            
            # Extract network features
            network_features = self._extract_network_features(request_data)
            features.update(network_features)
            
            # Extract temporal features
            temporal_features = self._extract_temporal_features(request_data, user_data)
            features.update(temporal_features)
            
            # Extract device features
            device_features = self._extract_device_features(request_data, user_data)
            features.update(device_features)
            
            # Add derived features
            derived_features = self._extract_derived_features(features)
            features.update(derived_features)
            
            return features
            
        except Exception as e:
            logger.error(f"Error extracting features: {str(e)}")
            # Return basic features on error
            return self._extract_basic_features(request_data)
    
    def _extract_basic_features(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract basic features from request"""
        features = {
            'email': request_data.get('email', ''),
            'timestamp': request_data.get('timestamp', ''),
            'action': request_data.get('action', ''),
            'status': request_data.get('status', ''),
            'duration': request_data.get('duration', 0),
            'ip': request_data.get('ip', ''),
            'userAgent': request_data.get('userAgent', ''),
            'browser': request_data.get('browser', ''),
            'os': request_data.get('os', ''),
            'deviceType': request_data.get('deviceType', ''),
            'policyKey': request_data.get('policyKey', ''),
            'service': request_data.get('service', '')
        }
        
        # Parse timestamp
        try:
            dt = datetime.strptime(
                features['timestamp'], 
                "%a %b %d %H:%M:%S %Z %Y"
            )
            features['timestamp_parsed'] = dt
            features['hour'] = dt.hour
            features['day_of_week'] = dt.weekday()
            features['is_weekend'] = dt.weekday() >= 5
        except:
            features['timestamp_parsed'] = datetime.now()
            features['hour'] = datetime.now().hour
            features['day_of_week'] = datetime.now().weekday()
            features['is_weekend'] = False
        
        return features
    
    def _extract_historical_features(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract features from user's historical data"""
        features = {}
        
        # Profile features
        profile = user_data.get('profile', {})
        features['user_age_days'] = (
            datetime.now() - profile.get('created_at', datetime.now())
        ).days
        
        # Risk profile
        risk_profile = profile.get('risk_profile', {})
        features['fraud_attempts'] = risk_profile.get('fraud_attempts', 0)
        features['successful_auths'] = risk_profile.get('successful_authentications', 0)
        features['failed_auths'] = risk_profile.get('failed_authentications', 0)
        features['current_risk_level'] = risk_profile.get('current_risk_level', 'LOW')
        
        # Authentication statistics
        auth_stats = user_data.get('auth_stats', {})
        features['auth_success_rate'] = auth_stats.get('success_rate', 1.0)
        features['unique_ips_count'] = auth_stats.get('unique_ips', 0)
        features['unique_devices_count'] = auth_stats.get('unique_devices', 0)
        
        # Session statistics
        session_stats = user_data.get('session_stats', {})
        features['total_actions'] = session_stats.get('total_actions', 0)
        features['unique_actions_count'] = session_stats.get('unique_actions', 0)
        features['avg_duration'] = session_stats.get('avg_duration', 0)
        features['error_rate'] = session_stats.get('error_rate', 0)
        
        # Recent activity patterns
        recent_auth = user_data.get('recent_auth_events', [])
        recent_session = user_data.get('recent_session_events', [])
        
        if recent_auth:
            # Time since last authentication
            last_auth_time = recent_auth[0].get('timestamp', datetime.now())
            features['hours_since_last_auth'] = (
                datetime.now() - last_auth_time
            ).total_seconds() / 3600
            
            # Recent failure rate
            recent_failures = sum(
                1 for event in recent_auth[:10] 
                if not event.get('success', True)
            )
            features['recent_auth_failure_rate'] = recent_failures / min(len(recent_auth), 10)
        else:
            features['hours_since_last_auth'] = 999
            features['recent_auth_failure_rate'] = 0
        
        if recent_session:
            # Recent action diversity
            recent_actions = [event.get('action', '') for event in recent_session[:20]]
            features['recent_action_diversity'] = len(set(recent_actions)) / len(recent_actions)
            
            # Recent error rate
            recent_errors = sum(
                1 for event in recent_session[:20]
                if event.get('status', '').lower() == 'false'
            )
            features['recent_error_rate'] = recent_errors / min(len(recent_session), 20)
        else:
            features['recent_action_diversity'] = 0
            features['recent_error_rate'] = 0
        
        return features
    
    def _extract_behavioral_features(
        self, 
        request_data: Dict[str, Any],
        user_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Extract behavioral pattern features"""
        features = {}
        
        profile = user_data.get('profile', {})
        
        # Device familiarity
        typical_browsers = profile.get('typical_browsers', [])
        features['is_familiar_browser'] = request_data['browser'] in typical_browsers
        
        typical_devices = profile.get('typical_devices', [])
        features['is_familiar_device'] = request_data['deviceType'] in typical_devices
        
        typical_os = profile.get('typical_os', [])
        features['is_familiar_os'] = request_data['os'] in typical_os
        
        # IP familiarity
        typical_ips = profile.get('typical_ips', [])
        features['is_familiar_ip'] = request_data['ip'] in typical_ips
        
        # Action familiarity
        typical_actions = profile.get('typical_actions', [])
        features['is_familiar_action'] = request_data['action'] in typical_actions
        
        # Time pattern familiarity
        typical_hours = profile.get('typical_access_hours', [])
        current_hour = request_data.get('hour', datetime.now().hour)
        features['is_typical_hour'] = current_hour in typical_hours
        
        typical_days = profile.get('typical_access_days', [])
        current_day = request_data.get('day_of_week', datetime.now().weekday())
        features['is_typical_day'] = current_day in typical_days
        
        # Calculate familiarity score
        familiarity_factors = [
            features['is_familiar_browser'],
            features['is_familiar_device'],
            features['is_familiar_os'],
            features['is_familiar_ip'],
            features['is_familiar_action'],
            features['is_typical_hour'],
            features['is_typical_day']
        ]
        features['familiarity_score'] = sum(familiarity_factors) / len(familiarity_factors)
        
        # Action sensitivity
        sensitive_actions = [
            'delete', 'remove', 'admin', 'config', 'permission',
            'collaborator', 'user', 'data', 'export', 'download'
        ]
        action_lower = request_data['action'].lower()
        features['is_sensitive_action'] = any(
            sensitive in action_lower for sensitive in sensitive_actions
        )
        
        # Service risk level
        high_risk_services = ['admin-service', 'config-service', 'permission-service']
        features['is_high_risk_service'] = request_data['service'] in high_risk_services
        
        return features
    
    def _extract_network_features(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract network-related features"""
        features = {}
        
        ip = request_data['ip']
        
        try:
            # Parse IP address
            ip_obj = ipaddress.ip_address(ip)
            
            # IP type features
            features['is_private_ip'] = ip_obj.is_private
            features['is_loopback'] = ip_obj.is_loopback
            features['is_multicast'] = ip_obj.is_multicast
            
            # IP octets for geographic approximation
            if isinstance(ip_obj, ipaddress.IPv4Address):
                octets = str(ip_obj).split('.')
                features['ip_first_octet'] = int(octets[0])
                features['ip_second_octet'] = int(octets[1])
                features['ip_class'] = self._get_ip_class(int(octets[0]))
            else:
                features['ip_first_octet'] = 0
                features['ip_second_octet'] = 0
                features['ip_class'] = 'IPv6'
                
        except:
            features['is_private_ip'] = False
            features['is_loopback'] = False
            features['is_multicast'] = False
            features['ip_first_octet'] = 0
            features['ip_second_octet'] = 0
            features['ip_class'] = 'Invalid'
        
        # User agent features
        user_agent = request_data.get('userAgent', '').lower()
        
        # Bot detection
        bot_indicators = ['bot', 'crawler', 'spider', 'scraper', 'curl', 'wget']
        features['is_potential_bot'] = any(
            indicator in user_agent for indicator in bot_indicators
        )
        
        # Old browser detection
        old_browsers = ['msie', 'trident']
        features['is_old_browser'] = any(
            browser in user_agent for browser in old_browsers
        )
        
        # Mobile detection (more sophisticated than deviceType)
        mobile_indicators = ['mobile', 'android', 'iphone', 'ipad', 'tablet']
        features['is_mobile_ua'] = any(
            indicator in user_agent for indicator in mobile_indicators
        )
        
        # User agent length (unusually long or short can be suspicious)
        features['ua_length'] = len(user_agent)
        features['ua_length_unusual'] = len(user_agent) < 20 or len(user_agent) > 200
        
        return features
    
    def _extract_temporal_features(
        self, 
        request_data: Dict[str, Any],
        user_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Extract temporal pattern features"""
        features = {}
        
        current_time = request_data.get('timestamp_parsed', datetime.now())
        
        # Time-based features
        features['is_business_hours'] = 9 <= current_time.hour <= 17
        features['is_night_time'] = current_time.hour < 6 or current_time.hour > 22
        features['is_lunch_time'] = 12 <= current_time.hour <= 13
        
        # Velocity features - actions per time window
        recent_sessions = user_data.get('recent_session_events', [])
        
        if recent_sessions:
            # Actions in last hour
            one_hour_ago = current_time - timedelta(hours=1)
            actions_last_hour = sum(
                1 for event in recent_sessions
                if event.get('timestamp', datetime.min) > one_hour_ago
            )
            features['actions_per_hour'] = actions_last_hour
            
            # Actions in last day
            one_day_ago = current_time - timedelta(days=1)
            actions_last_day = sum(
                1 for event in recent_sessions
                if event.get('timestamp', datetime.min) > one_day_ago
            )
            features['actions_per_day'] = actions_last_day
            
            # Calculate velocity score
            avg_actions_per_day = user_data.get('profile', {}).get(
                'statistics', {}
            ).get('average_actions_per_day', 10)
            
            if avg_actions_per_day > 0:
                features['velocity_ratio'] = actions_last_day / avg_actions_per_day
            else:
                features['velocity_ratio'] = 1.0
        else:
            features['actions_per_hour'] = 0
            features['actions_per_day'] = 0
            features['velocity_ratio'] = 0
        
        # Time since profile creation
        profile_created = user_data.get('profile', {}).get('created_at', current_time)
        features['account_age_hours'] = (
            current_time - profile_created
        ).total_seconds() / 3600
        
        # New account indicator
        features['is_new_account'] = features['account_age_hours'] < 24
        
        return features
    
    def _extract_device_features(
        self, 
        request_data: Dict[str, Any],
        user_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Extract device fingerprinting features"""
        features = {}
        
        # Create device fingerprint
        device_string = f"{request_data['browser']}-{request_data['os']}-{request_data['deviceType']}"
        device_hash = hashlib.md5(device_string.encode()).hexdigest()[:8]
        features['device_fingerprint'] = device_hash
        
        # Check if this is a new device
        recent_sessions = user_data.get('recent_session_events', [])
        recent_devices = set()
        
        for event in recent_sessions[:50]:  # Check last 50 sessions
            event_device = f"{event.get('browser', '')}-{event.get('os', '')}-{event.get('device_type', '')}"
            event_hash = hashlib.md5(event_device.encode()).hexdigest()[:8]
            recent_devices.add(event_hash)
        
        features['is_new_device'] = device_hash not in recent_devices
        features['device_diversity'] = len(recent_devices)
        
        # Browser-OS compatibility check
        compatible_pairs = {
            'Safari': ['MacOS', 'iOS'],
            'Edge': ['Windows'],
            'Chrome': ['Windows', 'MacOS', 'Linux', 'Android'],
            'Firefox': ['Windows', 'MacOS', 'Linux', 'Android']
        }
        
        browser = request_data['browser']
        os = request_data['os']
        
        if browser in compatible_pairs:
            features['browser_os_compatible'] = any(
                compatible_os in os for compatible_os in compatible_pairs[browser]
            )
        else:
            features['browser_os_compatible'] = True  # Unknown browser, assume compatible
        
        # Device type consistency
        mobile_os = ['iOS', 'Android']
        desktop_os = ['Windows', 'MacOS', 'Linux']
        
        if request_data['deviceType'] == 'Mobile':
            features['device_os_consistent'] = any(mos in os for mos in mobile_os)
        elif request_data['deviceType'] == 'Desktop':
            features['device_os_consistent'] = any(dos in os for dos in desktop_os)
        else:
            features['device_os_consistent'] = True
        
        return features
    
    def _extract_derived_features(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Extract derived features from existing features"""
        derived = {}
        
        # Risk score components
        risk_factors = []
        
        # Authentication risk
        if features.get('auth_success_rate', 1.0) < 0.8:
            risk_factors.append(0.3)
        if features.get('recent_auth_failure_rate', 0) > 0.2:
            risk_factors.append(0.2)
        
        # Behavioral risk
        if features.get('familiarity_score', 1.0) < 0.5:
            risk_factors.append(0.3)
        if features.get('is_new_device', False):
            risk_factors.append(0.2)
        
        # Temporal risk
        if features.get('is_night_time', False):
            risk_factors.append(0.1)
        if features.get('velocity_ratio', 1.0) > 3:
            risk_factors.append(0.2)
        
        # Network risk
        if features.get('is_potential_bot', False):
            risk_factors.append(0.4)
        if not features.get('browser_os_compatible', True):
            risk_factors.append(0.3)
        
        # Action risk
        if features.get('is_sensitive_action', False):
            risk_factors.append(0.2)
        if features.get('error_rate', 0) > 0.1:
            risk_factors.append(0.1)
        
        # Calculate composite risk score
        if risk_factors:
            derived['composite_risk_score'] = min(sum(risk_factors), 1.0)
        else:
            derived['composite_risk_score'] = 0.0
        
        # Trust score (inverse of risk)
        derived['trust_score'] = 1.0 - derived['composite_risk_score']
        
        # Anomaly indicators count
        anomaly_indicators = [
            features.get('is_new_device', False),
            features.get('is_night_time', False),
            features.get('is_potential_bot', False),
            not features.get('browser_os_compatible', True),
            not features.get('device_os_consistent', True),
            features.get('velocity_ratio', 1.0) > 3,
            features.get('familiarity_score', 1.0) < 0.3
        ]
        derived['anomaly_count'] = sum(anomaly_indicators)
        
        # Session health score
        session_health_factors = [
            features.get('error_rate', 0) < 0.05,
            features.get('avg_duration', 1000) < 5000,
            features.get('recent_error_rate', 0) < 0.1,
            features.get('actions_per_hour', 0) < 100
        ]
        derived['session_health_score'] = sum(session_health_factors) / len(session_health_factors)
        
        return derived
    
    def _get_ip_class(self, first_octet: int) -> str:
        """Determine IP address class"""
        if 1 <= first_octet <= 126:
            return 'A'
        elif 128 <= first_octet <= 191:
            return 'B'
        elif 192 <= first_octet <= 223:
            return 'C'
        elif 224 <= first_octet <= 239:
            return 'D'
        else:
            return 'E'