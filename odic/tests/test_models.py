"""
Model tests for Django OpenID Connect project
"""
from django.test import TestCase
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from oauth2_provider.models import Application, AccessToken, RefreshToken, Grant
from django.utils import timezone
from datetime import timedelta


class UserModelTestCase(TestCase):
    """Test User model functionality"""
    
    def test_user_creation(self):
        """Test user creation with required fields"""
        user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        
        self.assertEqual(user.username, 'testuser')
        self.assertEqual(user.email, 'test@example.com')
        self.assertTrue(user.check_password('testpass123'))
        self.assertTrue(user.is_active)
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)
    
    def test_superuser_creation(self):
        """Test superuser creation"""
        admin = User.objects.create_superuser(
            username='admin',
            email='admin@example.com',
            password='adminpass123'
        )
        
        self.assertEqual(admin.username, 'admin')
        self.assertTrue(admin.is_active)
        self.assertTrue(admin.is_staff)
        self.assertTrue(admin.is_superuser)
    
    def test_user_string_representation(self):
        """Test user string representation"""
        user = User.objects.create_user(
            username='stringtest',
            email='string@example.com',
            password='testpass123'
        )
        
        self.assertEqual(str(user), 'stringtest')
    
    def test_user_get_full_name(self):
        """Test user get_full_name method"""
        user = User.objects.create_user(
            username='fullnametest',
            email='fullname@example.com',
            first_name='John',
            last_name='Doe',
            password='testpass123'
        )
        
        self.assertEqual(user.get_full_name(), 'John Doe')
    
    def test_user_get_full_name_empty(self):
        """Test user get_full_name with empty names"""
        user = User.objects.create_user(
            username='emptyname',
            email='empty@example.com',
            password='testpass123'
        )
        
        self.assertEqual(user.get_full_name(), '')


class OAuth2ApplicationModelTestCase(TestCase):
    """Test OAuth2 Application model"""
    
    def setUp(self):
        """Set up test data"""
        self.user = User.objects.create_user(
            username='appowner',
            email='owner@example.com',
            password='testpass123'
        )
    
    def test_application_creation(self):
        """Test OAuth2 application creation"""
        app = Application.objects.create(
            name="Test Application",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )
        
        self.assertEqual(app.name, "Test Application")
        self.assertEqual(app.user, self.user)
        self.assertEqual(app.client_type, Application.CLIENT_CONFIDENTIAL)
        self.assertEqual(app.authorization_grant_type, Application.GRANT_AUTHORIZATION_CODE)
        self.assertIsNotNone(app.client_id)
        self.assertIsNotNone(app.client_secret)
    
    def test_application_string_representation(self):
        """Test application string representation"""
        app = Application.objects.create(
            name="String Test App",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )
        
        self.assertEqual(str(app), "String Test App")
    
    def test_application_client_types(self):
        """Test different client types"""
        # Confidential client
        confidential_app = Application.objects.create(
            name="Confidential App",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )
        
        self.assertEqual(confidential_app.client_type, Application.CLIENT_CONFIDENTIAL)
        
        # Public client
        public_app = Application.objects.create(
            name="Public App",
            user=self.user,
            client_type=Application.CLIENT_PUBLIC,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )
        
        self.assertEqual(public_app.client_type, Application.CLIENT_PUBLIC)
    
    def test_application_grant_types(self):
        """Test different grant types"""
        grant_types = [
            Application.GRANT_AUTHORIZATION_CODE,
            Application.GRANT_IMPLICIT,
            Application.GRANT_PASSWORD,
            Application.GRANT_CLIENT_CREDENTIALS,
        ]
        
        for grant_type in grant_types:
            app = Application.objects.create(
                name=f"App {grant_type}",
                user=self.user,
                client_type=Application.CLIENT_CONFIDENTIAL,
                authorization_grant_type=grant_type,
            )
            
            self.assertEqual(app.authorization_grant_type, grant_type)


class AccessTokenModelTestCase(TestCase):
    """Test AccessToken model"""
    
    def setUp(self):
        """Set up test data"""
        self.user = User.objects.create_user(
            username='tokenuser',
            email='token@example.com',
            password='testpass123'
        )
        
        self.application = Application.objects.create(
            name="Token Test App",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )
    
    def test_access_token_creation(self):
        """Test access token creation"""
        token = AccessToken.objects.create(
            user=self.user,
            application=self.application,
            token='test-access-token',
            expires=timezone.now() + timedelta(hours=1),
            scope='read write'
        )
        
        self.assertEqual(token.user, self.user)
        self.assertEqual(token.application, self.application)
        self.assertEqual(token.token, 'test-access-token')
        self.assertEqual(token.scope, 'read write')
        self.assertIsNotNone(token.expires)
    
    def test_access_token_string_representation(self):
        """Test access token string representation"""
        token = AccessToken.objects.create(
            user=self.user,
            application=self.application,
            token='string-test-token',
            expires=timezone.now() + timedelta(hours=1),
            scope='read'
        )
        
        # String representation typically shows truncated token
        self.assertIn('string-test-token', str(token))
    
    def test_access_token_is_expired(self):
        """Test access token expiration check"""
        # Create expired token
        expired_token = AccessToken.objects.create(
            user=self.user,
            application=self.application,
            token='expired-token',
            expires=timezone.now() - timedelta(hours=1),
            scope='read'
        )
        
        self.assertTrue(expired_token.is_expired())
        
        # Create valid token
        valid_token = AccessToken.objects.create(
            user=self.user,
            application=self.application,
            token='valid-token',
            expires=timezone.now() + timedelta(hours=1),
            scope='read'
        )
        
        self.assertFalse(valid_token.is_expired())
    
    def test_access_token_scopes(self):
        """Test access token with different scopes"""
        scopes = ['read', 'write', 'read write', 'admin', '']
        
        for scope in scopes:
            token = AccessToken.objects.create(
                user=self.user,
                application=self.application,
                token=f'token-{scope.replace(" ", "-")}',
                expires=timezone.now() + timedelta(hours=1),
                scope=scope
            )
            
            self.assertEqual(token.scope, scope)


class RefreshTokenModelTestCase(TestCase):
    """Test RefreshToken model"""
    
    def setUp(self):
        """Set up test data"""
        self.user = User.objects.create_user(
            username='refreshuser',
            email='refresh@example.com',
            password='testpass123'
        )
        
        self.application = Application.objects.create(
            name="Refresh Test App",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )
        
        self.access_token = AccessToken.objects.create(
            user=self.user,
            application=self.application,
            token='access-token-for-refresh',
            expires=timezone.now() + timedelta(hours=1),
            scope='read write'
        )
    
    def test_refresh_token_creation(self):
        """Test refresh token creation"""
        refresh_token = RefreshToken.objects.create(
            user=self.user,
            application=self.application,
            token='test-refresh-token',
            access_token=self.access_token
        )
        
        self.assertEqual(refresh_token.user, self.user)
        self.assertEqual(refresh_token.application, self.application)
        self.assertEqual(refresh_token.token, 'test-refresh-token')
        self.assertEqual(refresh_token.access_token, self.access_token)
    
    def test_refresh_token_string_representation(self):
        """Test refresh token string representation"""
        refresh_token = RefreshToken.objects.create(
            user=self.user,
            application=self.application,
            token='string-refresh-token',
            access_token=self.access_token
        )
        
        self.assertIn('string-refresh-token', str(refresh_token))


class GrantModelTestCase(TestCase):
    """Test Grant model (authorization codes)"""
    
    def setUp(self):
        """Set up test data"""
        self.user = User.objects.create_user(
            username='grantuser',
            email='grant@example.com',
            password='testpass123'
        )
        
        self.application = Application.objects.create(
            name="Grant Test App",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )
    
    def test_grant_creation(self):
        """Test grant (authorization code) creation"""
        grant = Grant.objects.create(
            user=self.user,
            application=self.application,
            code='test-auth-code',
            expires=timezone.now() + timedelta(minutes=10),
            redirect_uri='http://localhost:8000/callback/',
            scope='read write'
        )
        
        self.assertEqual(grant.user, self.user)
        self.assertEqual(grant.application, self.application)
        self.assertEqual(grant.code, 'test-auth-code')
        self.assertEqual(grant.redirect_uri, 'http://localhost:8000/callback/')
        self.assertEqual(grant.scope, 'read write')
        self.assertIsNotNone(grant.expires)
    
    def test_grant_is_expired(self):
        """Test grant expiration check"""
        # Create expired grant
        expired_grant = Grant.objects.create(
            user=self.user,
            application=self.application,
            code='expired-code',
            expires=timezone.now() - timedelta(minutes=1),
            redirect_uri='http://localhost:8000/callback/',
            scope='read'
        )
        
        self.assertTrue(expired_grant.is_expired())
        
        # Create valid grant
        valid_grant = Grant.objects.create(
            user=self.user,
            application=self.application,
            code='valid-code',
            expires=timezone.now() + timedelta(minutes=10),
            redirect_uri='http://localhost:8000/callback/',
            scope='read'
        )
        
        self.assertFalse(valid_grant.is_expired())
    
    def test_grant_string_representation(self):
        """Test grant string representation"""
        grant = Grant.objects.create(
            user=self.user,
            application=self.application,
            code='string-test-code',
            expires=timezone.now() + timedelta(minutes=10),
            redirect_uri='http://localhost:8000/callback/',
            scope='read'
        )
        
        self.assertIn('string-test-code', str(grant))


class ModelRelationshipTestCase(TestCase):
    """Test relationships between models"""
    
    def setUp(self):
        """Set up test data"""
        self.user = User.objects.create_user(
            username='relationuser',
            email='relation@example.com',
            password='testpass123'
        )
        
        self.application = Application.objects.create(
            name="Relationship Test App",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
        )
    
    def test_user_application_relationship(self):
        """Test user to application relationship"""
        # User should have applications
        self.assertIn(self.application, self.user.oauth2_provider_application.all())
        
        # Application should belong to user
        self.assertEqual(self.application.user, self.user)
    
    def test_application_tokens_relationship(self):
        """Test application to tokens relationship"""
        # Create tokens for application
        access_token = AccessToken.objects.create(
            user=self.user,
            application=self.application,
            token='relation-access-token',
            expires=timezone.now() + timedelta(hours=1),
            scope='read'
        )
        
        refresh_token = RefreshToken.objects.create(
            user=self.user,
            application=self.application,
            token='relation-refresh-token',
            access_token=access_token
        )
        
        # Application should have tokens
        self.assertIn(access_token, self.application.accesstoken_set.all())
        self.assertIn(refresh_token, self.application.refreshtoken_set.all())
    
    def test_access_refresh_token_relationship(self):
        """Test access token to refresh token relationship"""
        access_token = AccessToken.objects.create(
            user=self.user,
            application=self.application,
            token='access-for-refresh',
            expires=timezone.now() + timedelta(hours=1),
            scope='read'
        )
        
        refresh_token = RefreshToken.objects.create(
            user=self.user,
            application=self.application,
            token='refresh-for-access',
            access_token=access_token
        )
        
        # Refresh token should reference access token
        self.assertEqual(refresh_token.access_token, access_token)
        
        # Access token should have refresh token (reverse relationship)
        self.assertEqual(access_token.refresh_token, refresh_token)