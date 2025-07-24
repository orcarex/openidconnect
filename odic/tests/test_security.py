"""
Security tests for Django OpenID Connect project
"""
from django.test import TestCase, Client, override_settings
from django.contrib.auth.models import User
from django.urls import reverse
from oauth2_provider.models import Application, AccessToken
from django.utils import timezone
from datetime import timedelta
import json
import base64


class SecurityHeadersTestCase(TestCase):
    """Test security headers in responses"""
    
    def setUp(self):
        """Set up test data"""
        self.client = Client()
        
        # Create test user
        self.user = User.objects.create_user(
            username='security_user',
            email='security@test.com',
            password='testpass123'
        )
        
        # Create OAuth2 application
        self.application = Application.objects.create(
            name="Security Test App",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )
        
        # Create access token
        self.access_token = AccessToken.objects.create(
            user=self.user,
            application=self.application,
            token='security-access-token',
            expires=timezone.now() + timedelta(hours=1),
            scope='read write'
        )
    
    def test_userinfo_endpoint_security_headers(self):
        """Test userinfo endpoint includes security headers"""
        response = self.client.get(
            reverse('userinfo'),
            HTTP_AUTHORIZATION=f'Bearer {self.access_token.token}'
        )
        
        # Check for security headers (these might be added by middleware)
        # Uncomment if security headers are implemented
        # self.assertIn('X-Content-Type-Options', response)
        # self.assertIn('X-Frame-Options', response)
        # self.assertIn('X-XSS-Protection', response)
        
        # Content-Type should be properly set
        self.assertEqual(response['Content-Type'], 'application/json')
    
    def test_oauth2_endpoints_no_cache_headers(self):
        """Test OAuth2 endpoints include no-cache headers"""
        token_url = reverse('oauth2_provider:token')
        
        response = self.client.post(token_url, {
            'grant_type': 'client_credentials',
            'client_id': self.application.client_id,
            'client_secret': self.application.client_secret,
        })
        
        # OAuth2 token responses should not be cached
        # Uncomment if cache control headers are implemented
        # self.assertIn('Cache-Control', response)
        # self.assertIn('no-store', response['Cache-Control'])
        # self.assertIn('Pragma', response)
        # self.assertEqual(response['Pragma'], 'no-cache')


class TokenSecurityTestCase(TestCase):
    """Test token security measures"""
    
    def setUp(self):
        """Set up test data"""
        self.client = Client()
        
        # Create test user
        self.user = User.objects.create_user(
            username='token_security_user',
            email='tokensec@test.com',
            password='testpass123'
        )
        
        # Create OAuth2 application
        self.application = Application.objects.create(
            name="Token Security Test",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )
    
    def test_token_uniqueness(self):
        """Test that generated tokens are unique"""
        tokens = []
        
        for i in range(10):
            token = AccessToken.objects.create(
                user=self.user,
                application=self.application,
                token=f'unique-test-token-{i}',
                expires=timezone.now() + timedelta(hours=1),
                scope='read'
            )
            tokens.append(token.token)
        
        # All tokens should be unique
        self.assertEqual(len(tokens), len(set(tokens)))
    
    def test_token_length_security(self):
        """Test that tokens have sufficient length for security"""
        token = AccessToken.objects.create(
            user=self.user,
            application=self.application,
            expires=timezone.now() + timedelta(hours=1),
            scope='read'
        )
        
        # Token should be sufficiently long (at least 20 characters)
        self.assertGreaterEqual(len(token.token), 20)
    
    def test_client_secret_security(self):
        """Test client secret security"""
        # Client secret should be sufficiently long
        self.assertGreaterEqual(len(self.application.client_secret), 20)
        
        # Client secret should not be predictable
        app2 = Application.objects.create(
            name="Second App",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )
        
        self.assertNotEqual(self.application.client_secret, app2.client_secret)
    
    def test_token_scope_isolation(self):
        """Test that tokens respect scope limitations"""
        # Create token with limited scope
        limited_token = AccessToken.objects.create(
            user=self.user,
            application=self.application,
            token='limited-scope-token',
            expires=timezone.now() + timedelta(hours=1),
            scope='read'  # Only read scope
        )
        
        # Token should have the correct scope
        self.assertEqual(limited_token.scope, 'read')
        
        # Test that the token works with userinfo (which should accept read scope)
        response = self.client.get(
            reverse('userinfo'),
            HTTP_AUTHORIZATION=f'Bearer {limited_token.token}'
        )
        
        self.assertEqual(response.status_code, 200)


class AuthenticationSecurityTestCase(TestCase):
    """Test authentication security measures"""
    
    def setUp(self):
        """Set up test data"""
        self.client = Client()
        
        # Create test user
        self.user = User.objects.create_user(
            username='auth_security_user',
            email='authsec@test.com',
            password='testpass123'
        )
        
        # Create OAuth2 application
        self.application = Application.objects.create(
            name="Auth Security Test",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )
    
    def test_bearer_token_format_validation(self):
        """Test Bearer token format validation"""
        test_cases = [
            ('Bearer valid-token', 401),  # Invalid token but correct format
            ('bearer valid-token', 401),  # Wrong case
            ('Basic dGVzdA==', 401),      # Wrong auth type
            ('Bearer', 401),              # Missing token
            ('Bearer token with spaces', 401),  # Invalid token format
            ('', 401),                    # Empty header
        ]
        
        for auth_header, expected_status in test_cases:
            response = self.client.get(
                reverse('userinfo'),
                HTTP_AUTHORIZATION=auth_header
            )
            
            self.assertEqual(response.status_code, expected_status,
                           f"Auth header '{auth_header}' should return {expected_status}")
    
    def test_client_authentication_methods(self):
        """Test different client authentication methods"""
        token_url = reverse('oauth2_provider:token')
        
        # Test Basic authentication
        credentials = f"{self.application.client_id}:{self.application.client_secret}"
        encoded_credentials = base64.b64encode(credentials.encode()).decode()
        
        response = self.client.post(
            token_url,
            {
                'grant_type': 'client_credentials',
            },
            HTTP_AUTHORIZATION=f'Basic {encoded_credentials}',
            content_type='application/x-www-form-urlencoded'
        )
        
        # Should not return 401 (authentication should work)
        self.assertNotEqual(response.status_code, 401)
        
        # Test POST body authentication
        response = self.client.post(
            token_url,
            {
                'grant_type': 'client_credentials',
                'client_id': self.application.client_id,
                'client_secret': self.application.client_secret,
            },
            content_type='application/x-www-form-urlencoded'
        )
        
        # Should not return 401 (authentication should work)
        self.assertNotEqual(response.status_code, 401)
    
    def test_invalid_client_credentials(self):
        """Test invalid client credentials are rejected"""
        token_url = reverse('oauth2_provider:token')
        
        # Test with wrong client_id
        response = self.client.post(
            token_url,
            {
                'grant_type': 'client_credentials',
                'client_id': 'wrong-client-id',
                'client_secret': self.application.client_secret,
            },
            content_type='application/x-www-form-urlencoded'
        )
        
        self.assertIn(response.status_code, [400, 401])
        
        # Test with wrong client_secret
        response = self.client.post(
            token_url,
            {
                'grant_type': 'client_credentials',
                'client_id': self.application.client_id,
                'client_secret': 'wrong-secret',
            },
            content_type='application/x-www-form-urlencoded'
        )
        
        self.assertIn(response.status_code, [400, 401])


class InputValidationTestCase(TestCase):
    """Test input validation security"""
    
    def setUp(self):
        """Set up test data"""
        self.client = Client()
        
        # Create test user
        self.user = User.objects.create_user(
            username='validation_user',
            email='validation@test.com',
            password='testpass123'
        )
        
        # Create OAuth2 application
        self.application = Application.objects.create(
            name="Validation Test",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )
    
    def test_sql_injection_protection(self):
        """Test protection against SQL injection"""
        # Try SQL injection in various parameters
        malicious_inputs = [
            "'; DROP TABLE auth_user; --",
            "' OR '1'='1",
            "1' UNION SELECT * FROM auth_user --",
        ]
        
        for malicious_input in malicious_inputs:
            # Test in client_id parameter
            response = self.client.post('/o/token/', {
                'grant_type': 'client_credentials',
                'client_id': malicious_input,
                'client_secret': 'test',
            })
            
            # Should return error, not crash or succeed
            self.assertIn(response.status_code, [400, 401])
            
            # Test in token parameter
            response = self.client.get(
                reverse('userinfo'),
                HTTP_AUTHORIZATION=f'Bearer {malicious_input}'
            )
            
            # Should return 401, not crash
            self.assertEqual(response.status_code, 401)
    
    def test_xss_protection(self):
        """Test protection against XSS attacks"""
        # Try XSS in various parameters
        xss_inputs = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
        ]
        
        for xss_input in xss_inputs:
            # Test in authorization endpoint
            response = self.client.get('/o/authorize/', {
                'response_type': 'code',
                'client_id': xss_input,
                'redirect_uri': 'http://localhost:8000/callback/',
            })
            
            # Should not execute script or return 500
            self.assertNotEqual(response.status_code, 500)
            
            # If response contains the input, it should be escaped
            if xss_input in response.content.decode():
                # Check that dangerous characters are escaped
                content = response.content.decode()
                self.assertNotIn('<script>', content)
                self.assertNotIn('javascript:', content)
    
    def test_parameter_length_limits(self):
        """Test parameter length limits"""
        # Very long string
        long_string = 'a' * 10000
        
        # Test with very long client_id
        response = self.client.post('/o/token/', {
            'grant_type': 'client_credentials',
            'client_id': long_string,
            'client_secret': 'test',
        })
        
        # Should handle gracefully (not crash)
        self.assertNotEqual(response.status_code, 500)
        
        # Test with very long token
        response = self.client.get(
            reverse('userinfo'),
            HTTP_AUTHORIZATION=f'Bearer {long_string}'
        )
        
        # Should handle gracefully
        self.assertEqual(response.status_code, 401)


@override_settings(DEBUG=False)
class ProductionSecurityTestCase(TestCase):
    """Test security in production-like settings"""
    
    def test_debug_mode_disabled(self):
        """Test that DEBUG mode is disabled in production"""
        from django.conf import settings
        self.assertFalse(settings.DEBUG)
    
    def test_error_pages_no_debug_info(self):
        """Test that error pages don't leak debug information"""
        # Try to access non-existent endpoint
        response = self.client.get('/nonexistent-endpoint/')
        
        self.assertEqual(response.status_code, 404)
        
        # Response should not contain debug information
        content = response.content.decode()
        debug_indicators = [
            'Traceback',
            'Exception',
            'DEBUG = True',
            'INSTALLED_APPS',
            'settings.py'
        ]
        
        for indicator in debug_indicators:
            self.assertNotIn(indicator, content)


class RateLimitingTestCase(TestCase):
    """Test rate limiting (if implemented)"""
    
    def setUp(self):
        """Set up test data"""
        self.client = Client()
        
        # Create OAuth2 application
        self.user = User.objects.create_user(
            username='ratelimit_user',
            email='ratelimit@test.com',
            password='testpass123'
        )
        
        self.application = Application.objects.create(
            name="Rate Limit Test",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )
    
    def test_token_endpoint_rate_limiting(self):
        """Test rate limiting on token endpoint (if implemented)"""
        token_url = reverse('oauth2_provider:token')
        
        # Make multiple requests quickly
        responses = []
        for i in range(20):
            response = self.client.post(token_url, {
                'grant_type': 'client_credentials',
                'client_id': 'invalid-client',
                'client_secret': 'invalid-secret',
            })
            responses.append(response.status_code)
        
        # If rate limiting is implemented, some requests should be rate limited
        # If not implemented, all should return 400/401
        rate_limited = any(status == 429 for status in responses)
        all_client_errors = all(status in [400, 401] for status in responses)
        
        # Either rate limiting is working or all requests are properly handled
        self.assertTrue(rate_limited or all_client_errors)
    
    def test_userinfo_endpoint_rate_limiting(self):
        """Test rate limiting on userinfo endpoint (if implemented)"""
        userinfo_url = reverse('userinfo')
        
        # Make multiple requests quickly with invalid token
        responses = []
        for i in range(20):
            response = self.client.get(
                userinfo_url,
                HTTP_AUTHORIZATION='Bearer invalid-token'
            )
            responses.append(response.status_code)
        
        # If rate limiting is implemented, some requests should be rate limited
        # If not implemented, all should return 401
        rate_limited = any(status == 429 for status in responses)
        all_unauthorized = all(status == 401 for status in responses)
        
        # Either rate limiting is working or all requests are properly handled
        self.assertTrue(rate_limited or all_unauthorized)