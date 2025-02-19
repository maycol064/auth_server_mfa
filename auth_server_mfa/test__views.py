from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from rest_framework.authtoken.models import Token
from django.contrib.auth import get_user_model
import pyotp
from .models import MFAToken

User = get_user_model()

class AuthViewSetTestCase(APITestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.token = Token.objects.create(user=self.user)

    def test_health_check(self):
        """Test health check endpoint"""
        response = self.client.get('/auth/healty/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, {'healty': 'ok'})

    def test_register_success(self):
        """Test successful user registration"""
        data = {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password': 'newpass123'
        }
        response = self.client.post('/auth/register/', data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(User.objects.filter(username='newuser').exists())
        self.assertIn('token', response.data)
        self.assertIn('user', response.data)

    def test_register_duplicate_username(self):
        """Test registration with existing username"""
        data = {
            'username': 'testuser',  # Already exists
            'email': 'another@example.com',
            'password': 'newpass123'
        }
        response = self.client.post('/auth/register/', data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_login_success(self):
        """Test successful login"""
        data = {
            'username': 'testuser',
            'password': 'testpass123'
        }
        response = self.client.post('/auth/login/', data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('token', response.data)
        self.assertIn('user', response.data)

    def test_login_invalid_credentials(self):
        """Test login with invalid credentials"""
        data = {
            'username': 'testuser',
            'password': 'wrongpass'
        }
        response = self.client.post('/auth/login/', data)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_login_with_mfa_enabled(self):
        """Test login when MFA is enabled"""
        # Enable MFA for user
        self.user.mfa_secret = pyotp.random_base32()
        self.user.mfa_enabled = True
        self.user.save()

        data = {
            'username': 'testuser',
            'password': 'testpass123'
        }
        response = self.client.post('/auth/login/', data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['requires_mfa'])
        self.assertIn('mfa_token', response.data)

    def test_verify_mfa_success(self):
        """Test successful MFA verification"""
        # Setup MFA
        secret = pyotp.random_base32()
        self.user.mfa_secret = secret
        self.user.mfa_enabled = True
        self.user.save()

        # Generate valid token
        totp = pyotp.TOTP(secret)
        valid_token = totp.now()

        data = {
            'user_id': self.user.id,
            'token': valid_token
        }
        response = self.client.post('/auth/verify_mfa/', data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('token', response.data)

    def test_verify_mfa_invalid_token(self):
        """Test MFA verification with invalid token"""
        # Setup MFA
        self.user.mfa_secret = pyotp.random_base32()
        self.user.mfa_enabled = True
        self.user.save()

        data = {
            'user_id': self.user.id,
            'token': '123456'  # Invalid token
        }
        response = self.client.post('/auth/verify_mfa/', data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_initiate_mfa_setup(self):
        """Test initiating MFA setup"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
        response = self.client.post('/auth/initiate_mfa_setup/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('secret', response.data)
        self.assertIn('qr_uri', response.data)

    def test_verify_and_enable_mfa(self):
        """Test verifying and enabling MFA"""
        # Setup MFA
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
        secret = pyotp.random_base32()
        self.user.mfa_secret = secret
        self.user.save()

        # Generate valid token
        totp = pyotp.TOTP(secret)
        valid_token = totp.now()

        data = {'code': valid_token}
        response = self.client.post('/auth/verify_and_enable_mfa/', data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertTrue(self.user.mfa_enabled)

    def test_disable_mfa(self):
        """Test disabling MFA"""
        # Setup MFA
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
        self.user.mfa_secret = pyotp.random_base32()
        self.user.mfa_enabled = True
        self.user.save()

        response = self.client.post('/auth/disable_mfa/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertFalse(self.user.mfa_enabled)
        self.assertIsNone(self.user.mfa_secret)

    def test_logout(self):
        """Test user logout"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
        response = self.client.post('/auth/logout/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Verify token was deleted
        self.assertFalse(Token.objects.filter(user=self.user).exists())