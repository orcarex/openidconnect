"""
Test cases for Django settings and configuration
"""
from django.test import TestCase, override_settings
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
import os


class SettingsConfigurationTestCase(TestCase):
    """Test Django settings configuration"""
    
    def test_required_settings_exist(self):
        """Test that all required settings are configured"""
        required_settings = [
            'SECRET_KEY',
            'DEBUG',
            'ALLOWED_HOSTS',
            'INSTALLED_APPS',
            'MIDDLEWARE',
            'ROOT_URLCONF',
            'DATABASES',
            'OAUTH2_PROVIDER',
            'REST_FRAMEWORK'
        ]
        
        for setting_name in required_settings:
            self.assertTrue(
                hasattr(settings, setting_name),
                f"Required setting {setting_name} is missing"
            )
    
    def test_secret_key_configuration(self):
        """Test SECRET_KEY configuration"""
        self.assertIsNotNone(settings.SECRET_KEY)
        self.assertNotEqual(settings.SECRET_KEY, '')
        self.assertGreater(len(settings.SECRET_KEY), 20)
    
    def test_debug_setting_type(self):
        """Test DEBUG setting is boolean"""
        self.assertIsInstance(settings.DEBUG, bool)
    
    def test_allowed_hosts_configuration(self):
        """Test ALLOWED_HOSTS configuration"""
        self.assertIsInstance(settings.ALLOWED_HOSTS, list)
        
        # Should contain development hosts
        expected_hosts = ['localhost', '127.0.0.1', 'testserver']
        for host in expected_hosts:
            self.assertIn(host, settings.ALLOWED_HOSTS)
    
    def test_installed_apps_oauth2(self):
        """Test OAuth2 related apps are installed"""
        oauth2_apps = [
            'oauth2_provider',
            'rest_framework',
            'custom_protected_resource'
        ]
        
        for app in oauth2_apps:
            self.assertIn(app, settings.INSTALLED_APPS)
    
    def test_installed_apps_auth(self):
        """Test authentication related apps are installed"""
        auth_apps = [
            'djoser',
            'dj_rest_auth',
            'allauth',
            'allauth.account',
            'allauth.socialaccount'
        ]
        
        for app in auth_apps:
            self.assertIn(app, settings.INSTALLED_APPS)
    
    def test_middleware_configuration(self):
        """Test middleware configuration"""
        required_middleware = [
            'django.middleware.security.SecurityMiddleware',
            'django.contrib.sessions.middleware.SessionMiddleware',
            'django.middleware.common.CommonMiddleware',
            'django.middleware.csrf.CsrfViewMiddleware',
            'django.contrib.auth.middleware.AuthenticationMiddleware',
            'django.contrib.messages.middleware.MessageMiddleware',
            'allauth.account.middleware.AccountMiddleware'
        ]
        
        for middleware in required_middleware:
            self.assertIn(middleware, settings.MIDDLEWARE)
    
    def test_database_configuration(self):
        """Test database configuration"""
        self.assertIn('default', settings.DATABASES)
        default_db = settings.DATABASES['default']
        
        self.assertIn('ENGINE', default_db)
        self.assertIsNotNone(default_db['ENGINE'])


class OAuth2ProviderSettingsTestCase(TestCase):
    """Test OAuth2 provider settings"""
    
    def test_oauth2_provider_settings_exist(self):
        """Test OAuth2 provider settings are configured"""
        self.assertTrue(hasattr(settings, 'OAUTH2_PROVIDER'))
        oauth2_settings = settings.OAUTH2_PROVIDER
        
        required_keys = [
            'ACCESS_TOKEN_EXPIRE_SECONDS',
            'AUTHORIZATION_CODE_EXPIRE_SECONDS',
            'OIDC_ENABLED',
            'SCOPES'
        ]
        
        for key in required_keys:
            self.assertIn(key, oauth2_settings)
    
    def test_oauth2_oidc_enabled(self):
        """Test OIDC is enabled"""
        oauth2_settings = settings.OAUTH2_PROVIDER
        self.assertTrue(oauth2_settings['OIDC_ENABLED'])
    
    def test_oauth2_scopes_configuration(self):
        """Test OAuth2 scopes configuration"""
        oauth2_settings = settings.OAUTH2_PROVIDER
        scopes = oauth2_settings['SCOPES']
        
        required_scopes = ['openid', 'profile', 'email']
        for scope in required_scopes:
            self.assertIn(scope, scopes)
            self.assertIsInstance(scopes[scope], str)
    
    def test_oauth2_token_expiration(self):
        """Test OAuth2 token expiration settings"""
        oauth2_settings = settings.OAUTH2_PROVIDER
        
        # Access token should expire (reasonable time)
        access_token_expire = oauth2_settings['ACCESS_TOKEN_EXPIRE_SECONDS']
        self.assertIsInstance(access_token_expire, int)
        self.assertGreater(access_token_expire, 0)
        self.assertLessEqual(access_token_expire, 86400)  # Max 24 hours
        
        # Authorization code should expire quickly
        auth_code_expire = oauth2_settings['AUTHORIZATION_CODE_EXPIRE_SECONDS']
        self.assertIsInstance(auth_code_expire, int)
        self.assertGreater(auth_code_expire, 0)
        self.assertLessEqual(auth_code_expire, 3600)  # Max 1 hour


class RestFrameworkSettingsTestCase(TestCase):
    """Test REST framework settings"""
    
    def test_rest_framework_settings_exist(self):
        """Test REST framework settings are configured"""
        self.assertTrue(hasattr(settings, 'REST_FRAMEWORK'))
        rest_settings = settings.REST_FRAMEWORK
        
        required_keys = [
            'DEFAULT_AUTHENTICATION_CLASSES',
            'DEFAULT_PERMISSION_CLASSES'
        ]
        
        for key in required_keys:
            self.assertIn(key, rest_settings)
    
    def test_rest_framework_authentication_classes(self):
        """Test REST framework authentication classes"""
        rest_settings = settings.REST_FRAMEWORK
        auth_classes = rest_settings['DEFAULT_AUTHENTICATION_CLASSES']
        
        expected_classes = [
            'oauth2_provider.contrib.rest_framework.OAuth2Authentication',
            'rest_framework_simplejwt.authentication.JWTAuthentication'
        ]
        
        for auth_class in expected_classes:
            self.assertIn(auth_class, auth_classes)
    
    def test_rest_framework_permission_classes(self):
        """Test REST framework permission classes"""
        rest_settings = settings.REST_FRAMEWORK
        permission_classes = rest_settings['DEFAULT_PERMISSION_CLASSES']
        
        self.assertIn('rest_framework.permissions.IsAuthenticated', permission_classes)


class JWTSettingsTestCase(TestCase):
    """Test JWT settings"""
    
    def test_simple_jwt_settings_exist(self):
        """Test Simple JWT settings are configured"""
        self.assertTrue(hasattr(settings, 'SIMPLE_JWT'))
        jwt_settings = settings.SIMPLE_JWT
        
        required_keys = [
            'ACCESS_TOKEN_LIFETIME',
            'REFRESH_TOKEN_LIFETIME',
            'ALGORITHM',
            'SIGNING_KEY'
        ]
        
        for key in required_keys:
            self.assertIn(key, jwt_settings)
    
    def test_jwt_signing_key(self):
        """Test JWT signing key"""
        jwt_settings = settings.SIMPLE_JWT
        signing_key = jwt_settings['SIGNING_KEY']
        
        self.assertIsNotNone(signing_key)
        self.assertNotEqual(signing_key, '')
        # Should use SECRET_KEY
        self.assertEqual(signing_key, settings.SECRET_KEY)
    
    def test_jwt_algorithm(self):
        """Test JWT algorithm"""
        jwt_settings = settings.SIMPLE_JWT
        algorithm = jwt_settings['ALGORITHM']
        
        # Should use secure algorithm
        self.assertIn(algorithm, ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512'])


class EnvironmentSettingsTestCase(TestCase):
    """Test environment-based settings"""
    
    def test_environment_variables_loaded(self):
        """Test that environment variables are properly loaded"""
        # These should be loaded from django-environ
        self.assertIsInstance(settings.DEBUG, bool)
        self.assertIsInstance(settings.ALLOWED_HOSTS, list)
        self.assertIsNotNone(settings.SECRET_KEY)
    
    @override_settings(DEBUG=False)
    def test_production_settings(self):
        """Test production-like settings"""
        # When DEBUG is False, certain security settings should be considered
        self.assertFalse(settings.DEBUG)
        
        # In production, ALLOWED_HOSTS should not contain '*'
        if not settings.DEBUG:
            self.assertNotIn('*', settings.ALLOWED_HOSTS)
    
    def test_database_url_parsing(self):
        """Test database URL parsing"""
        # Should have default database configuration
        self.assertIn('default', settings.DATABASES)
        default_db = settings.DATABASES['default']
        
        # Should have proper database engine
        self.assertIn('ENGINE', default_db)
        self.assertTrue(default_db['ENGINE'].startswith('django.db.backends.'))


class SecuritySettingsTestCase(TestCase):
    """Test security-related settings"""
    
    def test_secret_key_security(self):
        """Test SECRET_KEY security"""
        secret_key = settings.SECRET_KEY
        
        # Should not be the default insecure key
        self.assertNotIn('django-insecure', secret_key.lower())
        
        # Should be sufficiently long
        self.assertGreaterEqual(len(secret_key), 50)
    
    def test_middleware_security(self):
        """Test security middleware is configured"""
        middleware = settings.MIDDLEWARE
        
        # Security middleware should be first
        self.assertEqual(
            middleware[0],
            'django.middleware.security.SecurityMiddleware'
        )
        
        # CSRF middleware should be present
        self.assertIn(
            'django.middleware.csrf.CsrfViewMiddleware',
            middleware
        )
    
    def test_password_validators(self):
        """Test password validators are configured"""
        self.assertTrue(hasattr(settings, 'AUTH_PASSWORD_VALIDATORS'))
        validators = settings.AUTH_PASSWORD_VALIDATORS
        
        # Should have at least basic validators
        self.assertGreater(len(validators), 0)
        
        # Check for common validators
        validator_names = [v['NAME'] for v in validators]
        expected_validators = [
            'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
            'django.contrib.auth.password_validation.MinimumLengthValidator',
            'django.contrib.auth.password_validation.CommonPasswordValidator',
            'django.contrib.auth.password_validation.NumericPasswordValidator'
        ]
        
        for validator in expected_validators:
            self.assertIn(validator, validator_names)


class LocalizationSettingsTestCase(TestCase):
    """Test localization settings"""
    
    def test_language_settings(self):
        """Test language and localization settings"""
        self.assertTrue(hasattr(settings, 'LANGUAGE_CODE'))
        self.assertTrue(hasattr(settings, 'TIME_ZONE'))
        self.assertTrue(hasattr(settings, 'USE_I18N'))
        self.assertTrue(hasattr(settings, 'USE_TZ'))
        
        # Should use timezone-aware datetimes
        self.assertTrue(settings.USE_TZ)
    
    def test_static_files_settings(self):
        """Test static files settings"""
        self.assertTrue(hasattr(settings, 'STATIC_URL'))
        self.assertIsNotNone(settings.STATIC_URL)
        
        # Should end with slash
        self.assertTrue(settings.STATIC_URL.endswith('/'))


class AllAuthSettingsTestCase(TestCase):
    """Test django-allauth settings"""
    
    def test_site_id_configured(self):
        """Test SITE_ID is configured"""
        self.assertTrue(hasattr(settings, 'SITE_ID'))
        self.assertIsInstance(settings.SITE_ID, int)
        self.assertEqual(settings.SITE_ID, 1)
    
    def test_socialaccount_providers(self):
        """Test social account providers configuration"""
        if hasattr(settings, 'SOCIALACCOUNT_PROVIDERS'):
            providers = settings.SOCIALACCOUNT_PROVIDERS
            
            # If Google is configured, check its settings
            if 'google' in providers:
                google_config = providers['google']
                self.assertIn('SCOPE', google_config)
                self.assertIsInstance(google_config['SCOPE'], list)


class DjRestAuthSettingsTestCase(TestCase):
    """Test dj-rest-auth settings"""
    
    def test_rest_auth_settings_exist(self):
        """Test REST_AUTH settings are configured"""
        if hasattr(settings, 'REST_AUTH'):
            rest_auth_settings = settings.REST_AUTH
            
            # Check JWT configuration if enabled
            if rest_auth_settings.get('USE_JWT'):
                self.assertIn('JWT_AUTH_COOKIE', rest_auth_settings)
                self.assertIn('JWT_AUTH_REFRESH_COOKIE', rest_auth_settings)