"""
Basic functionality tests for Django OpenID Connect project
"""
from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.urls import reverse
from oauth2_provider.models import Application, AccessToken
from django.utils import timezone
from datetime import timedelta
import json


class BasicFunctionalityTestCase(TestCase):
    """Test basic functionality of the application"""
    
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
        )
        
        # Create valid access token
        self.access_token = AccessToken.objects.create(
            user=self.user,
            application=self.application,
            token='test-access-token',
            expires=timezone.now() + timedelta(hours=1),
            scope='read write'
        )
    
    def test_userinfo_endpoint_with_valid_token(self):
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
    
    def test_userinfo_endpoint_without_token(self):
        """Test userinfo endpoint without access token"""
        response = self.client.get(reverse('userinfo'))
        
        # Should return unauthorized (401 or 403 depending on OAuth2 implementation)
        self.assertIn(response.status_code, [401, 403])
    
    def test_userinfo_endpoint_with_invalid_token(self):
        """Test userinfo endpoint with invalid access token"""
        response = self.client.get(
            reverse('userinfo'),
            HTTP_AUTHORIZATION='Bearer invalid-token'
        )
        
        # Should return unauthorized (401 or 403 depending on OAuth2 implementation)
        self.assertIn(response.status_code, [401, 403])
    
    def test_oauth2_application_creation(self):
        """Test OAuth2 application is created correctly"""
        self.assertEqual(self.application.name, "Test Application")
        self.assertEqual(self.application.client_type, Application.CLIENT_CONFIDENTIAL)
        self.assertEqual(self.application.authorization_grant_type, Application.GRANT_AUTHORIZATION_CODE)
        self.assertIsNotNone(self.application.client_id)
        self.assertIsNotNone(self.application.client_secret)
    
    def test_access_token_creation(self):
        """Test access token is created correctly"""
        self.assertEqual(self.access_token.user, self.user)
        self.assertEqual(self.access_token.application, self.application)
        self.assertEqual(self.access_token.scope, 'read write')
        self.assertFalse(self.access_token.is_expired())
    
    def test_user_creation(self):
        """Test user is created correctly"""
        self.assertEqual(self.user.username, 'testuser')
        self.assertEqual(self.user.email, 'test@example.com')
        self.assertEqual(self.user.get_full_name(), 'Test User')
        self.assertTrue(self.user.check_password('testpass123'))


class SettingsTestCase(TestCase):
    """Test Django settings configuration"""
    
    def test_required_settings_exist(self):
        """Test that required settings are configured"""
        from django.conf import settings
        
        required_settings = [
            'SECRET_KEY',
            'DEBUG',
            'ALLOWED_HOSTS',
            'INSTALLED_APPS',
            'DATABASES'
        ]
        
        for setting_name in required_settings:
            self.assertTrue(
                hasattr(settings, setting_name),
                f"Required setting {setting_name} is missing"
            )
    
    def test_oauth2_apps_installed(self):
        """Test OAuth2 related apps are installed"""
        from django.conf import settings
        
        required_apps = [
            'oauth2_provider',
            'rest_framework',
            'custom_protected_resource'
        ]
        
        for app in required_apps:
            self.assertIn(app, settings.INSTALLED_APPS)
    
    def test_secret_key_configured(self):
        """Test SECRET_KEY is configured"""
        from django.conf import settings
        
        self.assertIsNotNone(settings.SECRET_KEY)
        self.assertNotEqual(settings.SECRET_KEY, '')
        self.assertGreater(len(settings.SECRET_KEY), 20)


class URLConfigTestCase(TestCase):
    """Test URL configuration"""
    
    def test_userinfo_url_exists(self):
        """Test userinfo URL exists"""
        try:
            url = reverse('userinfo')
            self.assertEqual(url, '/userinfo/')
        except Exception as e:
            self.fail(f"userinfo URL not found: {e}")
    
    def test_oauth2_urls_exist(self):
        """Test OAuth2 URLs exist"""
        oauth2_urls = [
            'oauth2_provider:authorize',
            'oauth2_provider:token',
        ]
        
        for url_name in oauth2_urls:
            try:
                url = reverse(url_name)
                self.assertIsNotNone(url)
            except Exception as e:
                self.fail(f"OAuth2 URL {url_name} not found: {e}")
    
    def test_admin_url_exists(self):
        """Test admin URL exists"""
        response = self.client.get('/admin/')
        
        # Should redirect to login, not return 404
        self.assertEqual(response.status_code, 302)


class DatabaseTestCase(TestCase):
    """Test database functionality"""
    
    def test_database_connection(self):
        """Test database connection works"""
        # Try to create and retrieve a user
        user = User.objects.create_user(
            username='dbtest',
            email='dbtest@example.com',
            password='testpass123'
        )
        
        retrieved_user = User.objects.get(username='dbtest')
        self.assertEqual(user.id, retrieved_user.id)
        self.assertEqual(user.email, retrieved_user.email)
    
    def test_oauth2_models_work(self):
        """Test OAuth2 models work with database"""
        user = User.objects.create_user(
            username='oauth2test',
            email='oauth2test@example.com',
            password='testpass123'
        )
        
        app = Application.objects.create(
            name="DB Test App",
            user=user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )
        
        token = AccessToken.objects.create(
            user=user,
            application=app,
            token='db-test-token',
            expires=timezone.now() + timedelta(hours=1),
            scope='read'
        )
        
        # Verify we can retrieve the objects
        retrieved_app = Application.objects.get(name="DB Test App")
        retrieved_token = AccessToken.objects.get(token='db-test-token')
        
        self.assertEqual(app.id, retrieved_app.id)
        self.assertEqual(token.id, retrieved_token.id)


class SecurityBasicsTestCase(TestCase):
    """Test basic security measures"""
    
    def test_userinfo_requires_authentication(self):
        """Test userinfo endpoint requires authentication"""
        response = self.client.get(reverse('userinfo'))
        
        # Should not return 200 (success)
        self.assertNotEqual(response.status_code, 200)
        # Should return some form of unauthorized/forbidden
        self.assertIn(response.status_code, [401, 403])
    
    def test_admin_requires_authentication(self):
        """Test admin requires authentication"""
        response = self.client.get('/admin/')
        
        # Should redirect to login
        self.assertEqual(response.status_code, 302)
    
    def test_oauth2_endpoints_exist(self):
        """Test OAuth2 endpoints exist and don't crash"""
        endpoints = [
            '/o/authorize/',
            '/o/token/',
        ]
        
        for endpoint in endpoints:
            response = self.client.get(endpoint)
            # Should not return 404 or 500
            self.assertNotIn(response.status_code, [404, 500])


class EnvironmentTestCase(TestCase):
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
        
        # Should contain testserver for tests
        self.assertIn('testserver', settings.ALLOWED_HOSTS)
    
    def test_database_configuration(self):
        """Test database configuration"""
        from django.conf import settings
        
        self.assertIn('default', settings.DATABASES)
        default_db = settings.DATABASES['default']
        
        self.assertIn('ENGINE', default_db)
        self.assertIsNotNone(default_db['ENGINE'])