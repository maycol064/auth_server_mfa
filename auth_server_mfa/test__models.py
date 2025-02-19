from django.test import TestCase
from django.utils import timezone
from django.contrib.auth import get_user_model
from datetime import timedelta
import pyotp
from .models import MFAToken

User = get_user_model()

class UserMFATestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )

    def test_generate_mfa_secret(self):
        """Test MFA secret generation"""
        # Initial state
        self.assertIsNone(self.user.mfa_secret)
        
        # Generate secret
        secret = self.user.generate_mfa_secret()
        
        # Verify secret was generated and saved
        self.assertIsNotNone(secret)
        self.assertEqual(len(secret), 32)
        self.assertEqual(self.user.mfa_secret, secret)
        
        # Verify new secret can be generated
        new_secret = self.user.generate_mfa_secret()
        self.assertNotEqual(secret, new_secret)

    def test_verify_mfa_token_success(self):
        """Test successful MFA token verification"""
        # Setup MFA
        self.user.generate_mfa_secret()
        self.user.mfa_enabled = True
        self.user.save()
        
        # Generate valid token
        totp = pyotp.TOTP(self.user.mfa_secret)
        token = totp.now()
        
        # Verify token
        self.assertTrue(self.user.verify_mfa_token(token))
        self.assertEqual(self.user.failed_mfa_attempts, 0)
        self.assertIsNotNone(self.user.last_mfa_attempt)

    def verify_mfa_token(self, token):
        if not self.mfa_enabled or not self.mfa_secret:
            return False
            
        if not token or len(token) != 6:
            self.failed_mfa_attempts += 1
            self.last_mfa_attempt = timezone.now()
            self.save()
            return False
            
        totp = pyotp.TOTP(self.mfa_secret)
        if totp.verify(token):
            # Reset failed attempts on successful verification
            self.failed_mfa_attempts = 0
            self.last_mfa_attempt = timezone.now()
            self.save()
            return True
        else:
            # Increment failed attempts counter
            self.failed_mfa_attempts += 1
            self.last_mfa_attempt = timezone.now()
            self.save()
            return False

    def test_verify_mfa_disabled(self):
        """Test verification when MFA is disabled"""
        # Generate secret but keep MFA disabled
        self.user.generate_mfa_secret()
        self.user.mfa_enabled = False
        self.user.save()
        
        # Generate valid token
        totp = pyotp.TOTP(self.user.mfa_secret)
        token = totp.now()
        
        # Verify token fails when MFA is disabled
        self.assertFalse(self.user.verify_mfa_token(token))

    def test_get_mfa_uri(self):
        """Test MFA URI generation"""
        # Without secret
        self.assertIsNone(self.user.get_mfa_uri())
        
        # With secret
        self.user.generate_mfa_secret()
        uri = self.user.get_mfa_uri()
        
        # Verify URI format
        self.assertIsNotNone(uri)
        self.assertIn('otpauth://totp/', uri)
        # Usar email codificado
        self.assertIn('test%40example.com', uri)  # Cambiar esta línea
        self.assertIn(self.user.mfa_secret, uri)
        self.assertIn('YourAppName', uri)

class MFATokenModelTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )

    def test_token_creation(self):
        """Test MFA token creation"""
        token = MFAToken.objects.create(
            user=self.user,
            token='123456'
        )
        
        self.assertEqual(token.user, self.user)
        self.assertEqual(token.token, '123456')
        self.assertIsNotNone(token.created_at)
        self.assertIsNotNone(token.expires_at)
        
        # Verify expiration time is roughly 5 minutes from creation
        expected_expiry = token.created_at + timedelta(minutes=5)
        difference = abs((expected_expiry - token.expires_at).total_seconds())
        self.assertLess(difference, 5)  # Allow 5 seconds tolerance

    def test_token_expiration(self):
        """Test token expiration functionality"""
        # Create token that's already expired
        expired_token = MFAToken.objects.create(
            user=self.user,
            token='123456',
            expires_at=timezone.now() - timedelta(minutes=1)
        )
        
        # Create token that's not expired
        valid_token = MFAToken.objects.create(
            user=self.user,
            token='654321'
        )
        
        # Query expired and valid tokens
        expired_tokens = MFAToken.objects.filter(
            expires_at__lt=timezone.now()
        )
        valid_tokens = MFAToken.objects.filter(
            expires_at__gt=timezone.now()
        )
        
        self.assertIn(expired_token, expired_tokens)
        self.assertIn(valid_token, valid_tokens)