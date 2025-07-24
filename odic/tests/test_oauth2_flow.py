"""
Comprehensive OAuth2 flow tests for Django OpenID Connect project
"""
from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.urls import reverse
from oauth2_provider.models import Application, AccessToken, RefreshToken, Grant
from django.utils import timezone
from datetime import timedelta
import json
import base64
from urllib.parse import urlparse, parse_qs


class OAuth2AuthorizationCodeFlowTestCase(TestCase):
    """Test OAuth2 Authorization Code Flow"""
    
    def setUp(self):
        """Set up test data"""
        self.client = Client()
        
        # Create test user
        self.user = User.objects.create_user(
            username='oauth_test_user',
            email='oauth@test.com',
            password='testpass123'
        )
        
        # Create OAuth2 application
        self.application = Application.objects.create(
            name="Test OAuth2 App",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            client_id='test-oauth2-client',
            client_secret='test-oauth2-secret'
        )
        
        self.redirect_uri = 'http://localhost:8000/callback/'
    
    def test_authorization_endpoint_get_parameters(self):
        """Test authorization endpoint with GET parameters"""
        # Login user first
        self.client.login(username='oauth_test_user', password='testpass123')
        
        auth_url = reverse('oauth2_provider:authorize')
        params = {
            'response_type': 'code',
            'client_id': self.application.client_id,
            'redirect_uri': self.redirect_uri,
            'scope': 'read write',
            'state': 'test-state-123'
        }
        
        response = self.client.get(auth_url, params)
        
        # Should show authorization form
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Authorize')
        self.assertContains(response, self.application.name)
    
    def test_authorization_endpoint_post_allow(self):
        """Test authorization endpoint POST with allow"""
        # Login user first
        self.client.login(username='oauth_test_user', password='testpass123')
        
        auth_url = reverse('oauth2_provider:authorize')
        data = {
            'response_type': 'code',
            'client_id': self.application.client_id,
            'redirect_uri': self.redirect_uri,
            'scope': 'read write',
            'state': 'test-state-123',
            'allow': 'Authorize'
        }
        
        response = self.client.post(auth_url, data)
        
        # Should redirect to callback URL with authorization code
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.url.startswith(self.redirect_uri))
        
        # Parse redirect URL to get authorization code
        parsed_url = urlparse(response.url)
        query_params = parse_qs(parsed_url.query)
        
        self.assertIn('code', query_params)
        self.assertIn('state', query_params)
        self.assertEqual(query_params['state'][0], 'test-state-123')
    
    def test_authorization_endpoint_post_deny(self):
        """Test authorization endpoint POST with deny"""
        # Login user first
        self.client.login(username='oauth_test_user', password='testpass123')
        
        auth_url = reverse('oauth2_provider:authorize')
        data = {
            'response_type': 'code',
            'client_id': self.application.client_id,
            'redirect_uri': self.redirect_uri,
            'scope': 'read write',
            'state': 'test-state-123',
            'cancel': 'Cancel'
        }
        
        response = self.client.post(auth_url, data)
        
        # Should redirect to callback URL with error
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.url.startswith(self.redirect_uri))
        
        # Parse redirect URL to check for error
        parsed_url = urlparse(response.url)
        query_params = parse_qs(parsed_url.query)
        
        self.assertIn('error', query_params)
        self.assertEqual(query_params['error'][0], 'access_denied')
    
    def test_token_endpoint_authorization_code_grant(self):
        """Test token endpoint with authorization code grant"""
        # Create a grant (authorization code)
        grant = Grant.objects.create(
            user=self.user,
            application=self.application,
            code='test-auth-code',
            expires=timezone.now() + timedelta(minutes=10),
            redirect_uri=self.redirect_uri,
            scope='read write'
        )
        
        token_url = reverse('oauth2_provider:token')
        
        # Prepare Basic Auth header
        credentials = f"{self.application.client_id}:{self.application.client_secret}"
        encoded_credentials = base64.b64encode(credentials.encode()).decode()
        
        data = {
            'grant_type': 'authorization_code',
            'code': grant.code,
            'redirect_uri': self.redirect_uri,
        }
        
        response = self.client.post(
            token_url,
            data,
            HTTP_AUTHORIZATION=f'Basic {encoded_credentials}',
            content_type='application/x-www-form-urlencoded'
        )
        
        self.assertEqual(response.status_code, 200)
        
        token_data = json.loads(response.content)
        self.assertIn('access_token', token_data)
        self.assertIn('refresh_token', token_data)
        self.assertIn('token_type', token_data)
        self.assertEqual(token_data['token_type'], 'Bearer')
        self.assertIn('expires_in', token_data)
        self.assertIn('scope', token_data)
    
    def test_token_endpoint_invalid_grant(self):
        """Test token endpoint with invalid authorization code"""
        token_url = reverse('oauth2_provider:token')
        
        credentials = f"{self.application.client_id}:{self.application.client_secret}"
        encoded_credentials = base64.b64encode(credentials.encode()).decode()
        
        data = {
            'grant_type': 'authorization_code',
            'code': 'invalid-code',
            'redirect_uri': self.redirect_uri,
        }
        
        response = self.client.post(
            token_url,
            data,
            HTTP_AUTHORIZATION=f'Basic {encoded_credentials}',
            content_type='application/x-www-form-urlencoded'
        )
        
        self.assertEqual(response.status_code, 400)
        
        error_data = json.loads(response.content)
        self.assertIn('error', error_data)
        self.assertEqual(error_data['error'], 'invalid_grant')


class OAuth2RefreshTokenTestCase(TestCase):
    """Test OAuth2 Refresh Token functionality"""
    
    def setUp(self):
        """Set up test data"""
        self.client = Client()
        
        # Create test user
        self.user = User.objects.create_user(
            username='refresh_test_user',
            email='refresh@test.com',
            password='testpass123'
        )
        
        # Create OAuth2 application
        self.application = Application.objects.create(
            name="Refresh Token Test App",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            client_id='refresh-test-client',
            client_secret='refresh-test-secret'
        )
        
        # Create access token and refresh token
        self.access_token = AccessToken.objects.create(
            user=self.user,
            application=self.application,
            token='test-access-token',
            expires=timezone.now() + timedelta(hours=1),
            scope='read write'
        )
        
        self.refresh_token = RefreshToken.objects.create(
            user=self.user,
            application=self.application,
            token='test-refresh-token',
            access_token=self.access_token
        )
    
    def test_refresh_token_grant(self):
        """Test refresh token grant"""
        token_url = reverse('oauth2_provider:token')
        
        credentials = f"{self.application.client_id}:{self.application.client_secret}"
        encoded_credentials = base64.b64encode(credentials.encode()).decode()
        
        data = {
            'grant_type': 'refresh_token',
            'refresh_token': self.refresh_token.token,
        }
        
        response = self.client.post(
            token_url,
            data,
            HTTP_AUTHORIZATION=f'Basic {encoded_credentials}',
            content_type='application/x-www-form-urlencoded'
        )
        
        self.assertEqual(response.status_code, 200)
        
        token_data = json.loads(response.content)
        self.assertIn('access_token', token_data)
        self.assertIn('refresh_token', token_data)
        self.assertEqual(token_data['token_type'], 'Bearer')
        
        # New tokens should be different from old ones
        self.assertNotEqual(token_data['access_token'], self.access_token.token)
        self.assertNotEqual(token_data['refresh_token'], self.refresh_token.token)
    
    def test_refresh_token_invalid(self):
        """Test refresh token with invalid token"""
        token_url = reverse('oauth2_provider:token')
        
        credentials = f"{self.application.client_id}:{self.application.client_secret}"
        encoded_credentials = base64.b64encode(credentials.encode()).decode()
        
        data = {
            'grant_type': 'refresh_token',
            'refresh_token': 'invalid-refresh-token',
        }
        
        response = self.client.post(
            token_url,
            data,
            HTTP_AUTHORIZATION=f'Basic {encoded_credentials}',
            content_type='application/x-www-form-urlencoded'
        )
        
        self.assertEqual(response.status_code, 400)
        
        error_data = json.loads(response.content)
        self.assertIn('error', error_data)
        self.assertEqual(error_data['error'], 'invalid_grant')


class OAuth2TokenIntrospectionTestCase(TestCase):
    """Test OAuth2 Token Introspection"""
    
    def setUp(self):
        """Set up test data"""
        self.client = Client()
        
        # Create test user
        self.user = User.objects.create_user(
            username='introspect_user',
            email='introspect@test.com',
            password='testpass123'
        )
        
        # Create OAuth2 application
        self.application = Application.objects.create(
            name="Introspection Test App",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            client_id='introspect-client',
            client_secret='introspect-secret'
        )
        
        # Create access token
        self.access_token = AccessToken.objects.create(
            user=self.user,
            application=self.application,
            token='introspect-access-token',
            expires=timezone.now() + timedelta(hours=1),
            scope='read write'
        )
    
    def test_token_introspection_valid_token(self):
        """Test token introspection with valid token"""
        introspect_url = reverse('oauth2_provider:introspect')
        
        credentials = f"{self.application.client_id}:{self.application.client_secret}"
        encoded_credentials = base64.b64encode(credentials.encode()).decode()
        
        data = {
            'token': self.access_token.token,
        }
        
        response = self.client.post(
            introspect_url,
            data,
            HTTP_AUTHORIZATION=f'Basic {encoded_credentials}',
            content_type='application/x-www-form-urlencoded'
        )
        
        self.assertEqual(response.status_code, 200)
        
        introspect_data = json.loads(response.content)
        self.assertTrue(introspect_data['active'])
        self.assertEqual(introspect_data['scope'], 'read write')
        self.assertEqual(introspect_data['client_id'], self.application.client_id)
        self.assertIn('exp', introspect_data)
    
    def test_token_introspection_invalid_token(self):
        """Test token introspection with invalid token"""
        introspect_url = reverse('oauth2_provider:introspect')
        
        credentials = f"{self.application.client_id}:{self.application.client_secret}"
        encoded_credentials = base64.b64encode(credentials.encode()).decode()
        
        data = {
            'token': 'invalid-token',
        }
        
        response = self.client.post(
            introspect_url,
            data,
            HTTP_AUTHORIZATION=f'Basic {encoded_credentials}',
            content_type='application/x-www-form-urlencoded'
        )
        
        self.assertEqual(response.status_code, 200)
        
        introspect_data = json.loads(response.content)
        self.assertFalse(introspect_data['active'])


class OAuth2TokenRevocationTestCase(TestCase):
    """Test OAuth2 Token Revocation"""
    
    def setUp(self):
        """Set up test data"""
        self.client = Client()
        
        # Create test user
        self.user = User.objects.create_user(
            username='revoke_user',
            email='revoke@test.com',
            password='testpass123'
        )
        
        # Create OAuth2 application
        self.application = Application.objects.create(
            name="Revocation Test App",
            user=self.user,
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            client_id='revoke-client',
            client_secret='revoke-secret'
        )
        
        # Create access token
        self.access_token = AccessToken.objects.create(
            user=self.user,
            application=self.application,
            token='revoke-access-token',
            expires=timezone.now() + timedelta(hours=1),
            scope='read write'
        )
    
    def test_token_revocation(self):
        """Test token revocation"""
        revoke_url = reverse('oauth2_provider:revoke-token')
        
        credentials = f"{self.application.client_id}:{self.application.client_secret}"
        encoded_credentials = base64.b64encode(credentials.encode()).decode()
        
        data = {
            'token': self.access_token.token,
        }
        
        response = self.client.post(
            revoke_url,
            data,
            HTTP_AUTHORIZATION=f'Basic {encoded_credentials}',
            content_type='application/x-www-form-urlencoded'
        )
        
        self.assertEqual(response.status_code, 200)
        
        # Token should be deleted from database
        with self.assertRaises(AccessToken.DoesNotExist):
            AccessToken.objects.get(token=self.access_token.token)
    
    def test_token_revocation_invalid_token(self):
        """Test token revocation with invalid token"""
        revoke_url = reverse('oauth2_provider:revoke-token')
        
        credentials = f"{self.application.client_id}:{self.application.client_secret}"
        encoded_credentials = base64.b64encode(credentials.encode()).decode()
        
        data = {
            'token': 'invalid-token',
        }
        
        response = self.client.post(
            revoke_url,
            data,
            HTTP_AUTHORIZATION=f'Basic {encoded_credentials}',
            content_type='application/x-www-form-urlencoded'
        )
        
        # Should still return 200 (per RFC)
        self.assertEqual(response.status_code, 200)