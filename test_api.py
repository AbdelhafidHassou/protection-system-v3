# test_api.py
"""
Example usage and testing script for the Fraud Detection API
"""

import asyncio
import httpx
import json
from datetime import datetime, timedelta
import random
from typing import Dict, Any, List

# API Configuration
API_BASE_URL = "http://localhost:8000"
API_TIMEOUT = 30.0

# Test data generators
class TestDataGenerator:
    """Generate realistic test data for API testing"""
    
    BROWSERS = ["Chrome", "Firefox", "Safari", "Edge", "Opera"]
    OS_LIST = ["Windows NT", "MacOS", "Linux", "iOS", "Android"]
    DEVICE_TYPES = ["Desktop", "Mobile", "Tablet"]
    ACTIONS = [
        "login", "logout", "viewDashboard", "editProfile",
        "deleteCollaboratorById", "exportData", "changePassword",
        "updateSettings", "viewReports", "downloadFile"
    ]
    SERVICES = ["trust-service", "auth-service", "data-service", "admin-service"]
    POLICY_KEYS = ["trust_services", "admin", "user", "guest"]
    
    @staticmethod
    def generate_ip() -> str:
        """Generate random IP address"""
        return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"
    
    @staticmethod
    def generate_user_agent(browser: str, os: str) -> str:
        """Generate realistic user agent string"""
        ua_templates = {
            "Chrome": "Mozilla/5.0 ({os}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Firefox": "Mozilla/5.0 ({os}; rv:135.0) Gecko/20100101 Firefox/135.0",
            "Safari": "Mozilla/5.0 ({os}) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
            "Edge": "Mozilla/5.0 ({os}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
        }
        
        os_mapping = {
            "Windows NT": "Windows NT 10.0; Win64; x64",
            "MacOS": "Macintosh; Intel Mac OS X 10_15_7",
            "Linux": "X11; Linux x86_64",
            "iOS": "iPhone; CPU iPhone OS 17_0 like Mac OS X",
            "Android": "Linux; Android 13; SM-G998B"
        }
        
        template = ua_templates.get(browser, ua_templates["Chrome"])
        os_string = os_mapping.get(os, os_mapping["Windows NT"])
        
        return template.format(os=os_string)
    
    @classmethod
    def generate_normal_request(cls, email: str) -> Dict[str, Any]:
        """Generate a normal (low-risk) request"""
        browser = random.choice(cls.BROWSERS[:3])  # Common browsers
        os = random.choice(cls.OS_LIST[:3])  # Common OS
        
        return {
            "email": email,
            "timestamp": datetime.utcnow().strftime("%a %b %d %H:%M:%S UTC %Y"),
            "action": random.choice(["viewDashboard", "viewReports", "editProfile"]),
            "status": "true",
            "duration": random.randint(100, 1000),
            "ip": "192.168.1.100",  # Consistent IP
            "userAgent": cls.generate_user_agent(browser, os),
            "browser": browser,
            "os": os,
            "deviceType": "Desktop",
            "policyKey": "user",
            "service": "trust-service"
        }
    
    @classmethod
    def generate_suspicious_request(cls, email: str) -> Dict[str, Any]:
        """Generate a suspicious (high-risk) request"""
        browser = random.choice(cls.BROWSERS)
        os = random.choice(cls.OS_LIST)
        
        # Make it suspicious
        suspicious_features = random.choice([
            # Midnight access from new location
            {
                "timestamp": (datetime.utcnow().replace(hour=3)).strftime("%a %b %d %H:%M:%S UTC %Y"),
                "ip": cls.generate_ip(),
                "action": "deleteCollaboratorById"
            },
            # Bot-like user agent
            {
                "userAgent": "curl/7.68.0",
                "browser": "Unknown",
                "action": "exportData"
            },
            # Failed sensitive action
            {
                "action": "changePassword",
                "status": "false",
                "duration": random.randint(5000, 10000)
            },
            # Incompatible browser/OS
            {
                "browser": "Safari",
                "os": "Windows NT",
                "action": "admin.deleteAllUsers"
            }
        ])
        
        base_request = {
            "email": email,
            "timestamp": datetime.utcnow().strftime("%a %b %d %H:%M:%S UTC %Y"),
            "action": random.choice(cls.ACTIONS),
            "status": "true",
            "duration": random.randint(50, 5000),
            "ip": cls.generate_ip(),
            "userAgent": cls.generate_user_agent(browser, os),
            "browser": browser,
            "os": os,
            "deviceType": random.choice(cls.DEVICE_TYPES),
            "policyKey": random.choice(cls.POLICY_KEYS),
            "service": random.choice(cls.SERVICES)
        }
        
        base_request.update(suspicious_features)
        return base_request

class FraudDetectionAPITester:
    """Test client for the Fraud Detection API"""
    
    def __init__(self, base_url: str = API_BASE_URL):
        self.base_url = base_url
        self.client = httpx.AsyncClient(timeout=API_TIMEOUT)
        self.data_generator = TestDataGenerator()
    
    async def close(self):
        """Close the HTTP client"""
        await self.client.aclose()
    
    async def health_check(self) -> Dict[str, Any]:
        """Check API health"""
        response = await self.client.get(f"{self.base_url}/health")
        return response.json()
    
    async def analyze_fraud_risk(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze fraud risk for a request"""
        response = await self.client.post(
            f"{self.base_url}/api/v1/analyze",
            json=request_data
        )
        response.raise_for_status()
        return response.json()
    
    async def get_user_history(self, email: str, limit: int = 100) -> Dict[str, Any]:
        """Get user's fraud detection history"""
        response = await self.client.get(
            f"{self.base_url}/api/v1/user/{email}/history",
            params={"limit": limit}
        )
        response.raise_for_status()
        return response.json()
    
    async def submit_feedback(
        self, 
        email: str, 
        request_id: str, 
        was_fraud: bool,
        feedback: str = None
    ) -> Dict[str, Any]:
        """Submit feedback on detection accuracy"""
        response = await self.client.post(
            f"{self.base_url}/api/v1/feedback",
            json={
                "email": email,
                "request_id": request_id,
                "was_fraud": was_fraud,
                "feedback": feedback
            }
        )
        response.raise_for_status()
        return response.json()
    
    async def trigger_model_training(self, model_name: str = None) -> Dict[str, Any]:
        """Trigger model retraining"""
        response = await self.client.post(
            f"{self.base_url}/api/v1/train/trigger",
            json={"model_name": model_name} if model_name else {}
        )
        response.raise_for_status()
        return response.json()

async def run_basic_tests():
    """Run basic API tests"""
    tester = FraudDetectionAPITester()
    
    try:
        print("🚀 Starting Fraud Detection API Tests\n")
        
        # 1. Health Check
        print("1️⃣ Testing Health Check...")
        health = await tester.health_check()
        print(f"✅ API Status: {health['status']}")
        print(f"   Services: {json.dumps(health['services'], indent=2)}\n")
        
        # 2. Test Normal Request
        print("2️⃣ Testing Normal Request...")
        normal_request = tester.data_generator.generate_normal_request("normal.user@example.com")
        normal_result = await tester.analyze_fraud_risk(normal_request)
        print(f"✅ Risk Score: {normal_result['overall_risk_score']:.3f}")
        print(f"   Risk Level: {normal_result['risk_level']}")
        print(f"   Processing Time: {normal_result['metadata']['processing_time_ms']}ms\n")
        
        # 3. Test Suspicious Request
        print("3️⃣ Testing Suspicious Request...")
        suspicious_request = tester.data_generator.generate_suspicious_request("suspicious.user@example.com")
        suspicious_result = await tester.analyze_fraud_risk(suspicious_request)
        print(f"⚠️  Risk Score: {suspicious_result['overall_risk_score']:.3f}")
        print(f"   Risk Level: {suspicious_result['risk_level']}")
        print(f"   Risk Factors:")
        for factor in suspicious_result['risk_factors'][:3]:
            print(f"   - {factor['factor']} ({factor['severity']})")
        print(f"   Recommendations:")
        for rec in suspicious_result['recommendations'][:3]:
            print(f"   - {rec}")
        print()
        
        # 4. Test User History
        print("4️⃣ Testing User History...")
        history = await tester.get_user_history("normal.user@example.com")
        print(f"✅ Total Assessments: {history['total_assessments']}")
        print(f"   High Risk Count: {history['high_risk_count']}")
        print(f"   Risk Percentage: {history['risk_percentage']:.1f}%\n")
        
        # 5. Test Feedback Submission
        print("5️⃣ Testing Feedback Submission...")
        feedback_result = await tester.submit_feedback(
            email="normal.user@example.com",
            request_id=normal_result['metadata']['request_id'],
            was_fraud=False,
            feedback="Correctly identified as legitimate user"
        )
        print(f"✅ Feedback Status: {feedback_result['status']}\n")
        
        print("✅ All basic tests passed!")
        
    except Exception as e:
        print(f"❌ Test failed: {str(e)}")
    finally:
        await tester.close()

async def run_load_test(duration_seconds: int = 60, requests_per_second: int = 10):
    """Run a simple load test"""
    tester = FraudDetectionAPITester()
    
    print(f"🔥 Starting Load Test ({duration_seconds}s @ {requests_per_second} req/s)\n")
    
    start_time = asyncio.get_event_loop().time()
    end_time = start_time + duration_seconds
    
    total_requests = 0
    successful_requests = 0
    failed_requests = 0
    response_times = []
    risk_levels = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    
    try:
        while asyncio.get_event_loop().time() < end_time:
            # Create batch of requests
            batch_tasks = []
            for _ in range(requests_per_second):
                # Mix of normal and suspicious requests
                if random.random() < 0.8:  # 80% normal
                    request = tester.data_generator.generate_normal_request(
                        f"user{random.randint(1, 100)}@example.com"
                    )
                else:  # 20% suspicious
                    request = tester.data_generator.generate_suspicious_request(
                        f"user{random.randint(1, 100)}@example.com"
                    )
                
                batch_tasks.append(tester.analyze_fraud_risk(request))
            
            # Execute batch
            batch_start = asyncio.get_event_loop().time()
            results = await asyncio.gather(*batch_tasks, return_exceptions=True)
            
            # Process results
            for result in results:
                total_requests += 1
                if isinstance(result, Exception):
                    failed_requests += 1
                else:
                    successful_requests += 1
                    response_times.append(result['metadata']['processing_time_ms'])
                    risk_levels[result['risk_level']] += 1
            
            # Wait for next second
            elapsed = asyncio.get_event_loop().time() - batch_start
            if elapsed < 1.0:
                await asyncio.sleep(1.0 - elapsed)
        
        # Calculate statistics
        avg_response_time = sum(response_times) / len(response_times) if response_times else 0
        p95_response_time = sorted(response_times)[int(len(response_times) * 0.95)] if response_times else 0
        p99_response_time = sorted(response_times)[int(len(response_times) * 0.99)] if response_times else 0
        
        print("\n📊 Load Test Results:")
        print(f"   Total Requests: {total_requests}")
        print(f"   Successful: {successful_requests} ({successful_requests/total_requests*100:.1f}%)")
        print(f"   Failed: {failed_requests}")
        print(f"\n   Response Times:")
        print(f"   - Average: {avg_response_time:.1f}ms")
        print(f"   - P95: {p95_response_time:.1f}ms")
        print(f"   - P99: {p99_response_time:.1f}ms")
        print(f"\n   Risk Level Distribution:")
        for level, count in risk_levels.items():
            percentage = (count / successful_requests * 100) if successful_requests > 0 else 0
            print(f"   - {level}: {count} ({percentage:.1f}%)")
        
    except Exception as e:
        print(f"❌ Load test failed: {str(e)}")
    finally:
        await tester.close()

async def run_pattern_test():
    """Test specific fraud patterns"""
    tester = FraudDetectionAPITester()
    
    print("🎯 Testing Specific Fraud Patterns\n")
    
    patterns = [
        {
            "name": "Brute Force Attack",
            "description": "Multiple failed login attempts",
            "requests": [
                {
                    "email": "victim@example.com",
                    "action": "login",
                    "status": "false",
                    "duration": 100,
                    "ip": "45.67.89.123"
                } for _ in range(5)
            ]
        },
        {
            "name": "Account Takeover",
            "description": "Access from new location with sensitive actions",
            "requests": [
                {
                    "email": "victim@example.com",
                    "action": "changePassword",
                    "status": "true",
                    "ip": "123.45.67.89",
                    "browser": "Chrome",
                    "os": "Linux",
                    "deviceType": "Desktop"
                },
                {
                    "email": "victim@example.com",
                    "action": "deleteCollaboratorById",
                    "status": "true",
                    "ip": "123.45.67.89"
                }
            ]
        },
        {
            "name": "Data Exfiltration",
            "description": "Bulk data export at unusual time",
            "requests": [
                {
                    "email": "insider@example.com",
                    "action": "exportData",
                    "status": "true",
                    "duration": 8500,
                    "timestamp": (datetime.utcnow().replace(hour=2)).strftime("%a %b %d %H:%M:%S UTC %Y")
                }
            ]
        }
    ]
    
    try:
        for pattern in patterns:
            print(f"🔍 Testing: {pattern['name']}")
            print(f"   Description: {pattern['description']}")
            
            for i, req_template in enumerate(pattern['requests']):
                # Complete the request with default values
                request = tester.data_generator.generate_normal_request("test@example.com")
                request.update(req_template)
                
                result = await tester.analyze_fraud_risk(request)
                
                print(f"   Request {i+1}: Risk Score = {result['overall_risk_score']:.3f}, Level = {result['risk_level']}")
                if result['risk_factors']:
                    print(f"   Main Risk Factor: {result['risk_factors'][0]['factor']}")
            
            print()
        
        print("✅ Pattern tests completed!")
        
    except Exception as e:
        print(f"❌ Pattern test failed: {str(e)}")
    finally:
        await tester.close()

def print_menu():
    """Print the test menu"""
    print("\n" + "="*50)
    print("🛡️  Fraud Detection API Test Suite")
    print("="*50)
    print("1. Run Basic Tests")
    print("2. Run Load Test (60s)")
    print("3. Run Pattern Tests")
    print("4. Run All Tests")
    print("5. Exit")
    print("="*50)

async def main():
    """Main test runner"""
    while True:
        print_menu()
        choice = input("\nSelect option (1-5): ")
        
        if choice == "1":
            await run_basic_tests()
        elif choice == "2":
            duration = int(input("Duration (seconds) [60]: ") or "60")
            rps = int(input("Requests per second [10]: ") or "10")
            await run_load_test(duration, rps)
        elif choice == "3":
            await run_pattern_test()
        elif choice == "4":
            await run_basic_tests()
            print("\n" + "-"*50 + "\n")
            await run_pattern_test()
            print("\n" + "-"*50 + "\n")
            await run_load_test(30, 5)
        elif choice == "5":
            print("\n👋 Goodbye!")
            break
        else:
            print("❌ Invalid option. Please try again.")
        
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    print("""
    ╔══════════════════════════════════════════════╗
    ║     Fraud Detection API Test Suite           ║
    ║                                              ║
    ║  Make sure the API is running on port 8000  ║
    ║  before running these tests.                 ║
    ╚══════════════════════════════════════════════╝
    """)
    
    asyncio.run(main())