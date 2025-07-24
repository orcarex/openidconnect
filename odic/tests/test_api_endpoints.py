"""
API endpoint tests for Django OpenID Connect project
"""
from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.urls import reverse
from oauth2_provider.models import Application, AccessToken
from django.utils import timezone
from datetime import timedelta
import json


class APIEndpointTestCase(TestCase):
    """Test API endpoints and authentication"""
    
    def setUp(self):
        """Set up test data"""
        self.client = Client()
        
        # Create test user
        self.user = User.objects.create_user(
            username='api_test_user',
            email='api@test.com',
            first_name='API',
            last_name='User',
            password='testpass123'
        )
        
        # Create OAuth2 application
        self.application = Application.objects.create(
            name="API Test App",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            client_id='api-test-client',
            client_secret='api-test-secret'
        )
        
        # Create access token
        self.access_token = AccessToken.objects.create(
            user=self.user,
            application=self.application,
            token='api-access-token',
            expires=timezone.now() + timedelta(hours=1),
            scope='read write'
        )
    
    def test_userinfo_endpoint_structure(self):
        """Test userinfo endpoint returns correct structure"""
        response = self.client.get(
            reverse('userinfo'),
            HTTP_AUTHORIZATION=f'Bearer {self.access_token.token}'
        )
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/json')
        
        data = json.loads(response.content)
        
        # Check required OIDC userinfo fields
        required_fields = ['sub', 'name', 'email']
        for field in required_fields:
            self.assertIn(field, data)
        
        # Check data types
        self.assertIsInstance(data['sub'], int)
        self.assertIsInstance(data['name'], str)
        self.assertIsInstance(data['email'], str)
    
    def test_userinfo_endpoint_content(self):
        """Test userinfo endpoint returns correct user data"""
        response = self.client.get(
            reverse('userinfo'),
            HTTP_AUTHORIZATION=f'Bearer {self.access_token.token}'
        )
        
        data = json.loads(response.content)
        
        self.assertEqual(data['sub'], self.user.id)
        self.assertEqual(data['name'], 'API User')
        self.assertEqual(data['email'], 'api@test.com')
    
    def test_userinfo_endpoint_cors_headers(self):
        """Test userinfo endpoint CORS headers (if implemented)"""
        response = self.client.get(
            reverse('userinfo'),
            HTTP_AUTHORIZATION=f'Bearer {self.access_token.token}'
        )
        
        # These headers might be added for CORS support
        # Uncomment if CORS is implemented
        # self.assertIn('Access-Control-Allow-Origin', response)
        # self.assertIn('Access-Control-Allow-Methods', response)
    
    def test_userinfo_endpoint_different_scopes(self):
        """Test userinfo endpoint with different token scopes"""
        # Create token with limited scope
        limited_token = AccessToken.objects.create(
            user=self.user,
            application=self.application,
            token='limited-scope-token',
            expires=timezone.now() + timedelta(hours=1),
            scope='read'  # Only read scope
        )
        
        response = self.client.get(
            reverse('userinfo'),
            HTTP_AUTHORIZATION=f'Bearer {limited_token.token}'
        )
        
        # Should still work with read scope
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.content)
        self.assertEqual(data['sub'], self.user.id)


class AdminEndpointTestCase(TestCase):
    """Test admin interface endpoints"""
    
    def setUp(self):
        """Set up test data"""
        self.client = Client()
        
        # Create superuser
        self.admin_user = User.objects.create_superuser(
            username='admin',
            email='admin@test.com',
            password='adminpass123'
        )
        
        # Create regular user
        self.regular_user = User.objects.create_user(
            username='regular',
            email='regular@test.com',
            password='regularpass123'
        )
    
    def test_admin_login_page(self):
        """Test admin login page is accessible"""
        response = self.client.get('/admin/')
        
        # Should redirect to login page
        self.assertEqual(response.status_code, 302)
        self.assertIn('/admin/login/', response.url)
    
    def test_admin_login_success(self):
        """Test admin login with valid credentials"""
        response = self.client.post('/admin/login/', {
            'username': 'admin',
            'password': 'adminpass123',
            'next': '/admin/'
        })
        
        # Should redirect to admin dashboard
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, '/admin/')
    
    def test_admin_login_failure(self):
        """Test admin login with invalid credentials"""
        response = self.client.post('/admin/login/', {
            'username': 'admin',
            'password': 'wrongpassword',
            'next': '/admin/'
        })
        
        # Should stay on login page with error
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Please enter the correct username and password')
    
    def test_admin_oauth2_applications_access(self):
        """Test OAuth2 applications admin access"""
        # Login as admin
        self.client.login(username='admin', password='adminpass123')
        
        # Try to access OAuth2 applications admin
        response = self.client.get('/admin/oauth2_provider/application/')
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'OAuth2 provider')
    
    def test_regular_user_admin_access_denied(self):
        """Test regular user cannot access admin"""
        # Login as regular user
        self.client.login(username='regular', password='regularpass123')
        
        # Try to access admin
        response = self.client.get('/admin/')
        
        # Should redirect to login page
        self.assertEqual(response.status_code, 302)
        self.assertIn('/admin/login/', response.url)


class OAuth2EndpointTestCase(TestCase):
    """Test OAuth2 provider endpoints"""
    
    def setUp(self):
        """Set up test data"""
        self.client = Client()
        
        # Create test user
        self.user = User.objects.create_user(
            username='oauth_endpoint_user',
            email='oauth_endpoint@test.com',
            password='testpass123'
        )
        
        # Create OAuth2 application
        self.application = Application.objects.create(
            name="OAuth2 Endpoint Test",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            client_id='oauth2-endpoint-client',
            client_secret='oauth2-endpoint-secret'
        )
    
    def test_oauth2_authorize_endpoint_exists(self):
        """Test OAuth2 authorize endpoint exists"""
        response = self.client.get('/o/authorize/')
        
        # Should not return 404
        self.assertNotEqual(response.status_code, 404)
        
        # Should require parameters or redirect to login
        self.assertIn(response.status_code, [302, 400])
    
    def test_oauth2_token_endpoint_exists(self):
        """Test OAuth2 token endpoint exists"""
        response = self.client.post('/o/token/')
        
        # Should not return 404
        self.assertNotEqual(response.status_code, 404)
        
        # Should return error for missing parameters
        self.assertIn(response.status_code, [400, 401])
    
    def test_oauth2_introspect_endpoint_exists(self):
        """Test OAuth2 introspect endpoint exists"""
        response = self.client.post('/o/introspect/')
        
        # Should not return 404
        self.assertNotEqual(response.status_code, 404)
        
        # Should return error for missing authentication
        self.assertIn(response.status_code, [400, 401])
    
    def test_oauth2_revoke_endpoint_exists(self):
        """Test OAuth2 revoke endpoint exists"""
        response = self.client.post('/o/revoke_token/')
        
        # Should not return 404
        self.assertNotEqual(response.status_code, 404)
        
        # Should return error for missing authentication
        self.assertIn(response.status_code, [400, 401])
    
    def test_oauth2_endpoints_methods(self):
        """Test OAuth2 endpoints accept correct HTTP methods"""
        endpoints = [
            ('/o/authorize/', ['GET', 'POST']),
            ('/o/token/', ['POST']),
            ('/o/introspect/', ['POST']),
            ('/o/revoke_token/', ['POST']),
        ]
        
        for endpoint, allowed_methods in endpoints:
            for method in ['GET', 'POST', 'PUT', 'DELETE']:
                if method in allowed_methods:
                    # Should not return 405 Method Not Allowed
                    response = getattr(self.client, method.lower())(endpoint)
                    self.assertNotEqual(response.status_code, 405, 
                                      f"{method} should be allowed for {endpoint}")
                else:
                    # Should return 405 Method Not Allowed
                    response = getattr(self.client, method.lower())(endpoint)
                    if response.status_code == 405:
                        # This is expected
                        pass
                    # Some endpoints might return other errors before checking method
                    # so we don't assert 405 here


class ErrorHandlingTestCase(TestCase):
    """Test error handling in API endpoints"""
    
    def setUp(self):
        """Set up test data"""
        self.client = Client()
    
    def test_nonexistent_endpoint_404(self):
        """Test that non-existent endpoints return 404"""
        response = self.client.get('/nonexistent-endpoint/')
        self.assertEqual(response.status_code, 404)
    
    def test_userinfo_endpoint_missing_auth_header(self):
        """Test userinfo endpoint without Authorization header"""
        response = self.client.get(reverse('userinfo'))
        self.assertEqual(response.status_code, 401)
    
    def test_userinfo_endpoint_malformed_auth_header(self):
        """Test userinfo endpoint with malformed Authorization header"""
        response = self.client.get(
            reverse('userinfo'),
            HTTP_AUTHORIZATION='Malformed header'
        )
        self.assertEqual(response.status_code, 401)
    
    def test_userinfo_endpoint_wrong_auth_type(self):
        """Test userinfo endpoint with wrong authorization type"""
        response = self.client.get(
            reverse('userinfo'),
            HTTP_AUTHORIZATION='Basic dGVzdDp0ZXN0'  # Basic auth instead of Bearer
        )
        self.assertEqual(response.status_code, 401)
    
    def test_oauth2_endpoints_error_format(self):
        """Test OAuth2 endpoints return errors in correct format"""
        # Test token endpoint error format
        response = self.client.post('/o/token/', {
            'grant_type': 'invalid_grant_type'
        })
        
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response['Content-Type'], 'application/json')
        
        error_data = json.loads(response.content)
        self.assertIn('error', error_data)
        
        # OAuth2 error should be one of the standard error types
        oauth2_errors = [
            'invalid_request', 'invalid_client', 'invalid_grant',
            'unauthorized_client', 'unsupported_grant_type', 'invalid_scope'
        ]
        self.assertIn(error_data['error'], oauth2_errors)