from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.urls import reverse
from oauth2_provider.models import Application, AccessToken
from oauth2_provider import models as oauth2_models
from django.utils import timezone
from datetime import timedelta
import json


class UserInfoViewTestCase(TestCase):
    """Test cases for the userinfo endpoint"""
    
    def setUp(self):
        """Set up test data"""
        self.client = Client()
        
        # Create test user
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            first_name='Test',
            last_name='User',
            password='testpass123'
        )
        
        # Create OAuth2 application
        self.application = Application.objects.create(
            name="Test Application",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            client_id='test-client-id',
            client_secret='test-client-secret'
        )
        
        # Create access token
        self.access_token = AccessToken.objects.create(
            user=self.user,
            application=self.application,
            token='test-access-token',
            expires=timezone.now() + timedelta(hours=1),
            scope='read write'
        )
    
    def test_userinfo_with_valid_token(self):
        """Test userinfo endpoint with valid access token"""
        response = self.client.get(
            reverse('userinfo'),
            HTTP_AUTHORIZATION=f'Bearer {self.access_token.token}'
        )
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/json')
        
        data = json.loads(response.content)
        self.assertEqual(data['sub'], self.user.id)
        self.assertEqual(data['name'], 'Test User')
        self.assertEqual(data['email'], 'test@example.com')
    
    def test_userinfo_without_token(self):
        """Test userinfo endpoint without access token"""
        response = self.client.get(reverse('userinfo'))
        
        # OAuth2 protected resource returns 403 for missing token
        self.assertIn(response.status_code, [401, 403])
    
    def test_userinfo_with_invalid_token(self):
        """Test userinfo endpoint with invalid access token"""
        response = self.client.get(
            reverse('userinfo'),
            HTTP_AUTHORIZATION='Bearer invalid-token'
        )
        
        # OAuth2 protected resource returns 403 for invalid token
        self.assertIn(response.status_code, [401, 403])
    
    def test_userinfo_with_expired_token(self):
        """Test userinfo endpoint with expired access token"""
        # Create expired token
        expired_token = AccessToken.objects.create(
            user=self.user,
            application=self.application,
            token='expired-token',
            expires=timezone.now() - timedelta(hours=1),
            scope='read write'
        )
        
        response = self.client.get(
            reverse('userinfo'),
            HTTP_AUTHORIZATION=f'Bearer {expired_token.token}'
        )
        
        # OAuth2 protected resource returns 403 for expired token
        self.assertIn(response.status_code, [401, 403])
    
    def test_userinfo_user_without_full_name(self):
        """Test userinfo endpoint with user without full name"""
        # Create user without first/last name
        user_no_name = User.objects.create_user(
            username='noname',
            email='noname@example.com',
            password='testpass123'
        )
        
        token_no_name = AccessToken.objects.create(
            user=user_no_name,
            application=self.application,
            token='no-name-token',
            expires=timezone.now() + timedelta(hours=1),
            scope='read write'
        )
        
        response = self.client.get(
            reverse('userinfo'),
            HTTP_AUTHORIZATION=f'Bearer {token_no_name.token}'
        )
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(data['name'], '')  # get_full_name() returns empty string
        self.assertEqual(data['email'], 'noname@example.com')


class OAuth2IntegrationTestCase(TestCase):
    """Integration tests for OAuth2 functionality"""
    
    def setUp(self):
        """Set up test data"""
        self.client = Client()
        
        # Create test user
        self.user = User.objects.create_user(
            username='oauth_user',
            email='oauth@example.com',
            password='oauthpass123'
        )
        
        # Create OAuth2 application
        self.application = Application.objects.create(
            name="OAuth Test App",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            client_id='oauth-client-id',
            client_secret='oauth-client-secret'
        )
    
    def test_oauth2_application_creation(self):
        """Test OAuth2 application is created correctly"""
        self.assertEqual(self.application.name, "OAuth Test App")
        self.assertEqual(self.application.client_type, Application.CLIENT_CONFIDENTIAL)
        self.assertEqual(self.application.authorization_grant_type, Application.GRANT_AUTHORIZATION_CODE)
        self.assertIsNotNone(self.application.client_id)
        self.assertIsNotNone(self.application.client_secret)
    
    def test_authorization_endpoint_requires_login(self):
        """Test that authorization endpoint requires user login"""
        auth_url = reverse('oauth2_provider:authorize')
        params = {
            'response_type': 'code',
            'client_id': self.application.client_id,
            'redirect_uri': 'http://localhost:8000/callback/',
            'scope': 'read',
            'state': 'test-state'
        }
        
        response = self.client.get(auth_url, params)
        
        # Should redirect to login page
        self.assertEqual(response.status_code, 302)
        self.assertIn('/admin/login/', response.url)
    
    def test_token_endpoint_exists(self):
        """Test that token endpoint is accessible"""
        token_url = reverse('oauth2_provider:token')
        
        # POST request without proper credentials should return 400 or 401
        response = self.client.post(token_url, {
            'grant_type': 'authorization_code',
            'code': 'invalid-code',
            'client_id': self.application.client_id,
            'client_secret': self.application.client_secret,
        })
        
        # Should return error (not 404), meaning endpoint exists
        self.assertIn(response.status_code, [400, 401])


class SettingsTestCase(TestCase):
    """Test Django settings configuration"""
    
    def test_installed_apps_configuration(self):
        """Test that required apps are installed"""
        from django.conf import settings
        
        required_apps = [
            'oauth2_provider',
            'rest_framework',
            'djoser',
            'dj_rest_auth',
            'allauth',
            'custom_protected_resource'
        ]
        
        for app in required_apps:
            self.assertIn(app, settings.INSTALLED_APPS)
    
    def test_database_configuration(self):
        """Test database configuration"""
        from django.conf import settings
        
        self.assertIn('default', settings.DATABASES)
        self.assertIsNotNone(settings.DATABASES['default']['ENGINE'])
    
    def test_secret_key_exists(self):
        """Test that SECRET_KEY is configured"""
        from django.conf import settings
        
        self.assertIsNotNone(settings.SECRET_KEY)
        self.assertNotEqual(settings.SECRET_KEY, '')


class EnvironmentConfigTestCase(TestCase):
    """Test environment configuration"""
    
    def test_debug_setting(self):
        """Test DEBUG setting"""
        from django.conf import settings
        
        # DEBUG should be boolean
        self.assertIsInstance(settings.DEBUG, bool)
    
    def test_allowed_hosts_setting(self):
        """Test ALLOWED_HOSTS setting"""
        from django.conf import settings
        
        # ALLOWED_HOSTS should be a list
        self.assertIsInstance(settings.ALLOWED_HOSTS, list)
        
        # Should contain at least localhost for development
        expected_hosts = ['localhost', '127.0.0.1', 'testserver', '0.0.0.0']
        for host in expected_hosts:
            self.assertIn(host, settings.ALLOWED_HOSTS)


class OAuth2ProviderConfigTestCase(TestCase):
    """Test OAuth2 provider configuration"""
    
    def test_oauth2_provider_settings(self):
        """Test OAuth2 provider settings are configured"""
        from django.conf import settings
        
        self.assertTrue(hasattr(settings, 'OAUTH2_PROVIDER'))
        oauth2_settings = settings.OAUTH2_PROVIDER
        
        # Check essential settings
        self.assertIn('ACCESS_TOKEN_EXPIRE_SECONDS', oauth2_settings)
        self.assertIn('AUTHORIZATION_CODE_EXPIRE_SECONDS', oauth2_settings)
        self.assertIn('OIDC_ENABLED', oauth2_settings)
        self.assertTrue(oauth2_settings['OIDC_ENABLED'])
        
        # Check scopes configuration
        self.assertIn('SCOPES', oauth2_settings)
        scopes = oauth2_settings['SCOPES']
        self.assertIn('openid', scopes)
        self.assertIn('profile', scopes)
        self.assertIn('email', scopes)
    
    def test_rest_framework_oauth2_integration(self):
        """Test REST framework OAuth2 integration"""
        from django.conf import settings
        
        self.assertTrue(hasattr(settings, 'REST_FRAMEWORK'))
        rest_settings = settings.REST_FRAMEWORK
        
        # Check authentication classes
        self.assertIn('DEFAULT_AUTHENTICATION_CLASSES', rest_settings)
        auth_classes = rest_settings['DEFAULT_AUTHENTICATION_CLASSES']
        
        self.assertIn('oauth2_provider.contrib.rest_framework.OAuth2Authentication', auth_classes)
        self.assertIn('rest_framework_simplejwt.authentication.JWTAuthentication', auth_classes)


class CompleteOAuth2FlowTestCase(TestCase):
    """Test complete OAuth2 authorization code flow"""
    
    def setUp(self):
        """Set up test data"""
        self.client = Client()
        
        # Create test user
        self.user = User.objects.create_user(
            username='flow_user',
            email='flow@example.com',
            password='flowpass123',
            first_name='Flow',
            last_name='Test'
        )
        
        # Create OAuth2 application
        self.application = Application.objects.create(
            name="Flow Test App",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            client_id='flow-client-id',
            client_secret='flow-client-secret'
        )
    
    def test_complete_authorization_flow(self):
        """Test complete OAuth2 authorization code flow"""
        # Step 1: Login user
        login_success = self.client.login(username='flow_user', password='flowpass123')
        self.assertTrue(login_success)
        
        # Step 2: Request authorization
        auth_url = reverse('oauth2_provider:authorize')
        auth_params = {
            'response_type': 'code',
            'client_id': self.application.client_id,
            'redirect_uri': 'http://localhost:8000/callback/',
            'scope': 'openid profile email',
            'state': 'test-state-123'
        }
        
        # GET request should show authorization form
        auth_get_response = self.client.get(auth_url, auth_params)
        self.assertEqual(auth_get_response.status_code, 200)
        self.assertContains(auth_get_response, 'Authorize')
        
        # Step 3: Grant authorization
        auth_params['allow'] = 'Authorize'
        auth_post_response = self.client.post(auth_url, auth_params)
        
        # Should redirect with authorization code
        self.assertEqual(auth_post_response.status_code, 302)
        self.assertIn('code=', auth_post_response.url)
        self.assertIn('state=test-state-123', auth_post_response.url)
        
        # Extract authorization code
        redirect_url = auth_post_response.url
        code = redirect_url.split('code=')[1].split('&')[0]
        
        # Step 4: Exchange code for access token
        token_url = reverse('oauth2_provider:token')
        token_data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': 'http://localhost:8000/callback/',
            'client_id': self.application.client_id,
            'client_secret': self.application.client_secret,
        }
        
        token_response = self.client.post(token_url, token_data)
        self.assertEqual(token_response.status_code, 200)
        
        token_json = json.loads(token_response.content)
        self.assertIn('access_token', token_json)
        self.assertIn('token_type', token_json)
        self.assertEqual(token_json['token_type'], 'Bearer')
        self.assertIn('expires_in', token_json)
        
        access_token = token_json['access_token']
        
        # Step 5: Use access token to access protected resource
        userinfo_response = self.client.get(
            reverse('userinfo'),
            HTTP_AUTHORIZATION=f'Bearer {access_token}'
        )
        
        self.assertEqual(userinfo_response.status_code, 200)
        userinfo_data = json.loads(userinfo_response.content)
        
        self.assertEqual(userinfo_data['sub'], self.user.id)
        self.assertEqual(userinfo_data['name'], 'Flow Test')
        self.assertEqual(userinfo_data['email'], 'flow@example.com')
    
    def test_authorization_with_invalid_client_id(self):
        """Test authorization with invalid client ID"""
        self.client.login(username='flow_user', password='flowpass123')
        
        auth_url = reverse('oauth2_provider:authorize')
        auth_params = {
            'response_type': 'code',
            'client_id': 'invalid-client-id',
            'redirect_uri': 'http://localhost:8000/callback/',
            'scope': 'openid profile email',
            'state': 'test-state'
        }
        
        response = self.client.get(auth_url, auth_params)
        # Should return error (400 or show error page)
        self.assertIn(response.status_code, [400, 200])  # 200 if error is shown on page
        if response.status_code == 200:
            self.assertContains(response, 'error')
    
    def test_token_exchange_with_invalid_code(self):
        """Test token exchange with invalid authorization code"""
        token_url = reverse('oauth2_provider:token')
        token_data = {
            'grant_type': 'authorization_code',
            'code': 'invalid-authorization-code',
            'redirect_uri': 'http://localhost:8000/callback/',
            'client_id': self.application.client_id,
            'client_secret': self.application.client_secret,
        }
        
        response = self.client.post(token_url, token_data)
        self.assertEqual(response.status_code, 400)
        
        error_data = json.loads(response.content)
        self.assertIn('error', error_data)


class SecurityTestCase(TestCase):
    """Security-focused test cases"""
    
    def setUp(self):
        """Set up test data"""
        self.client = Client()
        
        self.user = User.objects.create_user(
            username='security_user',
            email='security@example.com',
            password='securitypass123'
        )
        
        self.application = Application.objects.create(
            name="Security Test App",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )
        
        self.access_token = AccessToken.objects.create(
            user=self.user,
            application=self.application,
            token='security-test-token',
            expires=timezone.now() + timedelta(hours=1),
            scope='openid profile email'
        )
    
    def test_userinfo_requires_authentication(self):
        """Test that UserInfo endpoint requires authentication"""
        response = self.client.get(reverse('userinfo'))
        self.assertEqual(response.status_code, 401)
    
    def test_invalid_bearer_token_format(self):
        """Test invalid Bearer token format"""
        response = self.client.get(
            reverse('userinfo'),
            HTTP_AUTHORIZATION='InvalidFormat token-here'
        )
        self.assertEqual(response.status_code, 401)
    
    def test_missing_authorization_header(self):
        """Test missing Authorization header"""
        response = self.client.get(reverse('userinfo'))
        self.assertEqual(response.status_code, 401)
    
    def test_sql_injection_protection(self):
        """Test SQL injection protection in token validation"""
        malicious_token = "'; DROP TABLE oauth2_provider_accesstoken; --"
        response = self.client.get(
            reverse('userinfo'),
            HTTP_AUTHORIZATION=f'Bearer {malicious_token}'
        )
        self.assertEqual(response.status_code, 401)
        
        # Verify table still exists by checking if we can create a token
        try:
            AccessToken.objects.create(
                user=self.user,
                application=self.application,
                token='test-after-injection',
                expires=timezone.now() + timedelta(hours=1),
                scope='read'
            )
            table_exists = True
        except Exception:
            table_exists = False
        
        self.assertTrue(table_exists, "AccessToken table should still exist after SQL injection attempt")
    
    def test_xss_protection_in_userinfo(self):
        """Test XSS protection in UserInfo response"""
        # Create user with potentially malicious data
        xss_user = User.objects.create_user(
            username='xss_user',
            email='<script>alert("xss")</script>@example.com',
            password='xsspass123',
            first_name='<script>alert("xss")</script>',
            last_name='Test'
        )
        
        xss_token = AccessToken.objects.create(
            user=xss_user,
            application=self.application,
            token='xss-test-token',
            expires=timezone.now() + timedelta(hours=1),
            scope='openid profile email'
        )
        
        response = self.client.get(
            reverse('userinfo'),
            HTTP_AUTHORIZATION=f'Bearer {xss_token.token}'
        )
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/json')
        
        # JSON response should contain the data as-is (JSON automatically handles escaping)
        data = json.loads(response.content)
        self.assertIn('<script>', data['email'])
        self.assertIn('<script>', data['name'])
    
    def test_token_scope_validation(self):
        """Test that tokens are validated properly"""
        # Create token with different scope
        limited_token = AccessToken.objects.create(
            user=self.user,
            application=self.application,
            token='limited-scope-token',
            expires=timezone.now() + timedelta(hours=1),
            scope='read'  # Different scope
        )
        
        response = self.client.get(
            reverse('userinfo'),
            HTTP_AUTHORIZATION=f'Bearer {limited_token.token}'
        )
        
        # Should still work as the @protected_resource decorator doesn't check specific scopes
        self.assertEqual(response.status_code, 200)


class TokenManagementTestCase(TestCase):
    """Test cases for token management functionality"""
    
    def setUp(self):
        """Set up test data"""
        self.client = Client()
        
        self.user = User.objects.create_user(
            username='token_user',
            email='token@example.com',
            password='tokenpass123'
        )
        
        self.application = Application.objects.create(
            name="Token Test App",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )
    
    def test_token_introspection(self):
        """Test OAuth2 token introspection endpoint"""
        # Create access token
        access_token = AccessToken.objects.create(
            user=self.user,
            application=self.application,
            token='introspection-test-token',
            expires=timezone.now() + timedelta(hours=1),
            scope='openid profile email'
        )
        
        # Test introspection
        introspect_url = reverse('oauth2_provider:introspect')
        response = self.client.post(introspect_url, {
            'token': access_token.token,
            'client_id': self.application.client_id,
            'client_secret': self.application.client_secret,
        })
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        
        self.assertTrue(data['active'])
        self.assertEqual(data['scope'], 'openid profile email')
        self.assertEqual(data['username'], self.user.username)
    
    def test_token_revocation(self):
        """Test OAuth2 token revocation endpoint"""
        # Create access token
        access_token = AccessToken.objects.create(
            user=self.user,
            application=self.application,
            token='revocation-test-token',
            expires=timezone.now() + timedelta(hours=1),
            scope='openid profile email'
        )
        
        # Verify token works
        userinfo_response = self.client.get(
            reverse('userinfo'),
            HTTP_AUTHORIZATION=f'Bearer {access_token.token}'
        )
        self.assertEqual(userinfo_response.status_code, 200)
        
        # Revoke token
        revoke_url = reverse('oauth2_provider:revoke-token')
        revoke_response = self.client.post(revoke_url, {
            'token': access_token.token,
            'client_id': self.application.client_id,
            'client_secret': self.application.client_secret,
        })
        
        self.assertEqual(revoke_response.status_code, 200)
        
        # Verify token no longer works
        userinfo_response_after = self.client.get(
            reverse('userinfo'),
            HTTP_AUTHORIZATION=f'Bearer {access_token.token}'
        )
        self.assertEqual(userinfo_response_after.status_code, 401)
    
    def test_expired_token_cleanup(self):
        """Test that expired tokens are properly handled"""
        # Create expired token
        expired_token = AccessToken.objects.create(
            user=self.user,
            application=self.application,
            token='expired-cleanup-token',
            expires=timezone.now() - timedelta(hours=1),
            scope='openid profile email'
        )
        
        # Try to use expired token
        response = self.client.get(
            reverse('userinfo'),
            HTTP_AUTHORIZATION=f'Bearer {expired_token.token}'
        )
        
        self.assertEqual(response.status_code, 401)
        
        # Verify token still exists in database (cleanup is usually done by management command)
        self.assertTrue(AccessToken.objects.filter(token=expired_token.token).exists())


class PerformanceTestCase(TestCase):
    """Performance-related test cases"""
    
    def setUp(self):
        """Set up test data"""
        self.client = Client()
        
        self.user = User.objects.create_user(
            username='perf_user',
            email='perf@example.com',
            password='perfpass123'
        )
        
        self.application = Application.objects.create(
            name="Performance Test App",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )
        
        self.access_token = AccessToken.objects.create(
            user=self.user,
            application=self.application,
            token='performance-test-token',
            expires=timezone.now() + timedelta(hours=1),
            scope='openid profile email'
        )
    
    def test_userinfo_response_time(self):
        """Test UserInfo endpoint response time"""
        import time
        
        start_time = time.time()
        response = self.client.get(
            reverse('userinfo'),
            HTTP_AUTHORIZATION=f'Bearer {self.access_token.token}'
        )
        end_time = time.time()
        
        response_time = end_time - start_time
        
        self.assertEqual(response.status_code, 200)
        # Response should be fast (less than 1 second for simple endpoint)
        self.assertLess(response_time, 1.0)
    
    def test_multiple_concurrent_requests(self):
        """Test handling multiple requests to UserInfo endpoint"""
        import threading
        import time
        
        results = []
        
        def make_request():
            response = self.client.get(
                reverse('userinfo'),
                HTTP_AUTHORIZATION=f'Bearer {self.access_token.token}'
            )
            results.append(response.status_code)
        
        # Create multiple threads
        threads = []
        for i in range(10):
            thread = threading.Thread(target=make_request)
            threads.append(thread)
        
        # Start all threads
        start_time = time.time()
        for thread in threads:
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        end_time = time.time()
        
        # All requests should succeed
        self.assertEqual(len(results), 10)
        for status_code in results:
            self.assertEqual(status_code, 200)
        
        # Total time should be reasonable
        total_time = end_time - start_time
        self.assertLess(total_time, 5.0)  # Should complete within 5 seconds
