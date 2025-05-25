# core/risk_engine.py
import logging
from typing import Dict, Any, List, Tuple
from datetime import datetime
import uuid
import time

logger = logging.getLogger(__name__)

class RiskEngine:
    """Risk assessment engine that combines model predictions"""
    
    def __init__(self):
        self.risk_thresholds = {
            'LOW': 0.3,
            'MEDIUM': 0.5,
            'HIGH': 0.7,
            'CRITICAL': 0.85
        }
        
        self.model_weights = {
            'authentication': 0.35,
            'session': 0.35,
            'access_time': 0.30
        }
        
        self.recommendation_templates = {
            'LOW': [
                "Continue monitoring user activity",
                "No immediate action required"
            ],
            'MEDIUM': [
                "Enable additional logging for this user",
                "Consider requesting additional authentication for sensitive actions",
                "Monitor for pattern changes in the next 24 hours"
            ],
            'HIGH': [
                "Request multi-factor authentication immediately",
                "Flag account for security review",
                "Limit access to sensitive operations",
                "Send security alert to user via email"
            ],
            'CRITICAL': [
                "Block current session immediately",
                "Require password reset and MFA setup",
                "Initiate security incident response",
                "Contact user through verified channel",
                "Review all recent account activity"
            ]
        }
    
    async def assess_risk(
        self,
        model_predictions: Dict[str, Any],
        request_data: Dict[str, Any],
        features: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Perform comprehensive risk assessment"""
        start_time = time.time()
        
        try:
            # Calculate overall risk score
            overall_score = self._calculate_overall_score(model_predictions)
            
            # Determine risk level
            risk_level = self._determine_risk_level(overall_score)
            
            # Format model scores
            model_scores = self._format_model_scores(model_predictions)
            
            # Identify risk factors
            risk_factors = self._identify_risk_factors(
                model_predictions,
                features,
                overall_score
            )
            
            # Generate recommendations
            recommendations = self._generate_recommendations(
                risk_level,
                risk_factors,
                features
            )
            
            # Apply business rules
            risk_level, overall_score = self._apply_business_rules(
                risk_level,
                overall_score,
                request_data,
                features
            )
            
            processing_time = int((time.time() - start_time) * 1000)
            
            return {
                'overall_score': round(overall_score, 3),
                'risk_level': risk_level,
                'model_scores': model_scores,
                'risk_factors': risk_factors,
                'recommendations': recommendations,
                'request_id': str(uuid.uuid4()),
                'processing_time_ms': processing_time
            }
            
        except Exception as e:
            logger.error(f"Error in risk assessment: {str(e)}")
            raise
    
    def _calculate_overall_score(self, predictions: Dict[str, Any]) -> float:
        """Calculate weighted overall risk score"""
        weighted_sum = 0.0
        total_weight = 0.0
        
        for model_name, weight in self.model_weights.items():
            if model_name in predictions:
                score = predictions[model_name]['score']
                confidence = predictions[model_name]['confidence']
                
                # Adjust weight by confidence
                adjusted_weight = weight * confidence
                weighted_sum += score * adjusted_weight
                total_weight += adjusted_weight
        
        if total_weight > 0:
            return weighted_sum / total_weight
        else:
            return 0.5  # Default neutral score
    
    def _determine_risk_level(self, score: float) -> str:
        """Determine risk level from score"""
        if score >= self.risk_thresholds['CRITICAL']:
            return 'CRITICAL'
        elif score >= self.risk_thresholds['HIGH']:
            return 'HIGH'
        elif score >= self.risk_thresholds['MEDIUM']:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _format_model_scores(self, predictions: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Format model scores for response"""
        formatted_scores = []
        
        model_display_names = {
            'authentication': 'Authentication Behavior',
            'session': 'Session Anomaly',
            'access_time': 'Access Time Pattern'
        }
        
        for model_name, display_name in model_display_names.items():
            if model_name in predictions:
                pred = predictions[model_name]
                formatted_scores.append({
                    'model_name': display_name,
                    'score': round(pred['score'], 3),
                    'confidence': round(pred['confidence'], 3),
                    'factors': pred['factors']
                })
        
        return formatted_scores
    
    def _identify_risk_factors(
        self,
        predictions: Dict[str, Any],
        features: Dict[str, Any],
        overall_score: float
    ) -> List[Dict[str, Any]]:
        """Identify and prioritize risk factors"""
        risk_factors = []
        
        # Collect factors from model predictions
        for model_name, pred in predictions.items():
            if pred['score'] > 0.5:  # Only include if model indicates risk
                for factor in pred['factors']:
                    if factor not in ["Normal authentication pattern", 
                                    "Normal session behavior", 
                                    "Normal access time"]:
                        severity = self._calculate_factor_severity(pred['score'])
                        risk_factors.append({
                            'factor': factor,
                            'severity': severity,
                            'source': model_name
                        })
        
        # Add feature-based risk factors
        feature_risks = self._identify_feature_risks(features)
        risk_factors.extend(feature_risks)
        
        # Deduplicate and prioritize
        unique_factors = {}
        for factor in risk_factors:
            key = factor['factor']
            if key not in unique_factors or \
               self._severity_score(factor['severity']) > \
               self._severity_score(unique_factors[key]['severity']):
                unique_factors[key] = factor
        
        # Sort by severity
        sorted_factors = sorted(
            unique_factors.values(),
            key=lambda x: self._severity_score(x['severity']),
            reverse=True
        )
        
        # Add descriptions
        for factor in sorted_factors:
            factor['description'] = self._get_factor_description(
                factor['factor'],
                factor['severity']
            )
        
        return sorted_factors[:10]  # Top 10 factors
    
    def _identify_feature_risks(self, features: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify risk factors from features"""
        feature_risks = []
        
        # New device risk
        if features.get('is_new_device', False):
            feature_risks.append({
                'factor': 'First time using this device',
                'severity': 'HIGH',
                'source': 'feature'
            })
        
        # Bot detection
        if features.get('is_potential_bot', False):
            feature_risks.append({
                'factor': 'Automated tool detected',
                'severity': 'CRITICAL',
                'source': 'feature'
            })
        
        # Velocity anomaly
        if features.get('velocity_ratio', 1.0) > 5:
            feature_risks.append({
                'factor': 'Unusually high activity rate',
                'severity': 'HIGH',
                'source': 'feature'
            })
        
        # Low familiarity
        if features.get('familiarity_score', 1.0) < 0.3:
            feature_risks.append({
                'factor': 'Multiple unfamiliar attributes',
                'severity': 'MEDIUM',
                'source': 'feature'
            })
        
        # Authentication failures
        if features.get('recent_auth_failure_rate', 0) > 0.5:
            feature_risks.append({
                'factor': 'High rate of authentication failures',
                'severity': 'HIGH',
                'source': 'feature'
            })
        
        # Sensitive action from new location
        if (features.get('is_sensitive_action', False) and 
            not features.get('is_familiar_ip', True)):
            feature_risks.append({
                'factor': 'Sensitive action from new location',
                'severity': 'HIGH',
                'source': 'feature'
            })
        
        # Incompatible browser/OS
        if not features.get('browser_os_compatible', True):
            feature_risks.append({
                'factor': 'Suspicious browser/OS combination',
                'severity': 'MEDIUM',
                'source': 'feature'
            })
        
        return feature_risks
    
    def _generate_recommendations(
        self,
        risk_level: str,
        risk_factors: List[Dict[str, Any]],
        features: Dict[str, Any]
    ) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        # Base recommendations for risk level
        recommendations.extend(self.recommendation_templates[risk_level])
        
        # Specific recommendations based on risk factors
        for factor in risk_factors[:3]:  # Top 3 factors
            factor_text = factor['factor'].lower()
            
            if 'new device' in factor_text:
                recommendations.append(
                    "Verify device through email confirmation"
                )
            elif 'automated' in factor_text or 'bot' in factor_text:
                recommendations.append(
                    "Implement CAPTCHA challenge"
                )
            elif 'high activity' in factor_text:
                recommendations.append(
                    "Implement rate limiting for this user"
                )
            elif 'authentication failures' in factor_text:
                recommendations.append(
                    "Lock account after 2 more failed attempts"
                )
            elif 'sensitive action' in factor_text:
                recommendations.append(
                    "Require elevated permissions confirmation"
                )
        
        # Feature-specific recommendations
        if features.get('is_new_account', False) and risk_level in ['HIGH', 'CRITICAL']:
            recommendations.append(
                "Apply new account restrictions for 48 hours"
            )
        
        if features.get('error_rate', 0) > 0.3:
            recommendations.append(
                "Investigate potential technical issues or attack patterns"
            )
        
        # Remove duplicates while preserving order
        seen = set()
        unique_recommendations = []
        for rec in recommendations:
            if rec not in seen:
                seen.add(rec)
                unique_recommendations.append(rec)
        
        return unique_recommendations[:7]  # Max 7 recommendations
    
    def _apply_business_rules(
        self,
        risk_level: str,
        risk_score: float,
        request_data: Dict[str, Any],
        features: Dict[str, Any]
    ) -> Tuple[str, float]:
        """Apply business-specific rules to adjust risk assessment"""
        
        # Rule 1: Admin actions always require extra scrutiny
        if (request_data.get('policyKey') == 'admin' or 
            'admin' in request_data.get('action', '').lower()):
            if risk_level == 'LOW':
                risk_level = 'MEDIUM'
            risk_score = max(risk_score, 0.4)
        
        # Rule 2: Trusted services get slight risk reduction
        trusted_services = ['trust-service', 'auth-service']
        if (request_data.get('service') in trusted_services and 
            risk_level in ['MEDIUM', 'HIGH']):
            risk_score *= 0.9
            
            # Recalculate risk level
            if risk_score < self.risk_thresholds['HIGH']:
                risk_level = 'MEDIUM'
            if risk_score < self.risk_thresholds['MEDIUM']:
                risk_level = 'LOW'
        
        # Rule 3: New accounts with high-risk actions
        if (features.get('is_new_account', False) and 
            features.get('is_sensitive_action', False)):
            risk_level = 'HIGH' if risk_level in ['LOW', 'MEDIUM'] else risk_level
            risk_score = max(risk_score, 0.7)
        
        # Rule 4: Whitelisted IPs (example)
        whitelisted_ips = ['192.168.1.1', '10.0.0.1']  # Example whitelist
        if request_data.get('ip') in whitelisted_ips:
            risk_score *= 0.5
            if risk_level == 'CRITICAL':
                risk_level = 'HIGH'
        
        # Rule 5: Failed actions increase risk
        if request_data.get('status') == 'false':
            risk_score = min(risk_score * 1.2, 1.0)
        
        return risk_level, risk_score
    
    def _calculate_factor_severity(self, score: float) -> str:
        """Calculate severity based on score"""
        if score >= 0.8:
            return 'CRITICAL'
        elif score >= 0.6:
            return 'HIGH'
        elif score >= 0.4:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _severity_score(self, severity: str) -> int:
        """Convert severity to numeric score for sorting"""
        severity_map = {
            'CRITICAL': 4,
            'HIGH': 3,
            'MEDIUM': 2,
            'LOW': 1
        }
        return severity_map.get(severity, 0)
    
    def _get_factor_description(self, factor: str, severity: str) -> str:
        """Get detailed description for risk factor"""
        descriptions = {
            'First time using this device': 
                f"This device has not been seen before for this user. "
                f"{severity} risk as it could indicate account compromise.",
            
            'Automated tool detected': 
                f"User agent suggests automated tools or bots. "
                f"This is a {severity} risk indicator for potential attacks.",
            
            'Unusually high activity rate': 
                f"Activity rate is significantly higher than normal. "
                f"This {severity} risk could indicate automated attacks or account takeover.",
            
            'Multiple unfamiliar attributes': 
                f"Several attributes don't match user's typical patterns. "
                f"This {severity} risk suggests potential unauthorized access.",
            
            'High rate of authentication failures': 
                f"Recent authentication attempts have high failure rate. "
                f"This {severity} risk could indicate brute force attempts.",
            
            'Sensitive action from new location': 
                f"High-risk action attempted from unfamiliar location. "
                f"This {severity} risk requires additional verification.",
            
            'Suspicious browser/OS combination': 
                f"Browser and OS combination is unusual or incompatible. "
                f"This {severity} risk might indicate spoofed user agent.",
            
            'Unusual access time': 
                f"Access time is outside user's normal patterns. "
                f"This {severity} risk could indicate different timezone or unauthorized access.",
            
            'New location detected': 
                f"Access from location not previously seen for this user. "
                f"This {severity} risk requires location verification.",
            
            'Weekend access detected': 
                f"Access during weekend when user typically doesn't work. "
                f"This {severity} risk might be normal but warrants monitoring.",
            
            'Midnight access detected': 
                f"Access during late night hours. "
                f"This {severity} risk is unusual for most business users.",
            
            'Unusually long action duration': 
                f"Action took much longer than typical. "
                f"This {severity} risk could indicate technical issues or manipulation.",
            
            'Action failed': 
                f"The requested action failed to complete. "
                f"This {severity} risk might indicate attack attempts or system issues.",
            
            'Normal session behavior':
                f"Session patterns match expected behavior. "
                f"Low risk indicator.",
            
            'Normal authentication pattern':
                f"Authentication matches user's typical patterns. "
                f"Low risk indicator.",
            
            'Normal access time':
                f"Access time aligns with user's regular schedule. "
                f"Low risk indicator."
        }
        
        # Return specific description or generic one
        return descriptions.get(
            factor,
            f"{factor}. Severity: {severity}. "
            f"This factor contributes to the overall risk assessment."
        )