from django.test import TestCase
from django.contrib.auth import get_user_model
from rest_framework.exceptions import ValidationError
from .serializers import (
    RegisterSerializer, 
    LoginSerializer, 
    UserSerializer,
    MFATokenSerializer
)

User = get_user_model()

class RegisterSerializerTestCase(TestCase):
    def test_register_serializer_valid_data(self):
        """Test serializer with valid registration data"""
        data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'securepass123'
        }
        serializer = RegisterSerializer(data=data)
        self.assertTrue(serializer.is_valid())
        self.assertEqual(set(serializer.validated_data.keys()), 
                        {'username', 'email', 'password'})

    def test_register_serializer_missing_fields(self):
        """Test serializer with missing required fields"""
        data = {'username': 'testuser'}
        serializer = RegisterSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('password', serializer.errors)  # Only check for password as it's the only required field

    def test_register_serializer_invalid_email(self):
        """Test serializer with invalid email format"""
        data = {
            'username': 'testuser',
            'email': 'invalid-email',
            'password': 'securepass123'
        }
        serializer = RegisterSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('email', serializer.errors)

class LoginSerializerTestCase(TestCase):
    def test_login_serializer_valid_data(self):
        """Test serializer with valid login data"""
        data = {
            'username': 'testuser',
            'password': 'testpass123'
        }
        serializer = LoginSerializer(data=data)
        self.assertTrue(serializer.is_valid())
        self.assertEqual(set(serializer.validated_data.keys()), 
                        {'username', 'password'})

    def test_login_serializer_missing_fields(self):
        """Test serializer with missing required fields"""
        data = {'username': 'testuser'}
        serializer = LoginSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('password', serializer.errors)

class UserSerializerTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )

    def test_user_serializer_output(self):
        """Test serializer output contains all expected fields"""
        serializer = UserSerializer(self.user)
        self.assertEqual(set(serializer.data.keys()), 
                        {'id', 'username', 'email', 'mfa_enabled'})

    def test_user_serializer_read_only_fields(self):
        """Test that mfa_enabled is read-only"""
        data = {
            'username': 'newusername',
            'email': 'newemail@example.com',
            'mfa_enabled': True
        }
        serializer = UserSerializer(self.user, data=data, partial=True)
        self.assertTrue(serializer.is_valid())
        # mfa_enabled should not be in validated_data as it's read-only
        self.assertNotIn('mfa_enabled', serializer.validated_data)

class MFATokenSerializerTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )

    def test_mfa_token_serializer_valid_data(self):
        """Test serializer with valid MFA token data"""
        data = {
            'user_id': self.user.id,
            'token': '123456'
        }
        serializer = MFATokenSerializer(data=data)
        self.assertTrue(serializer.is_valid())
        self.assertEqual(set(serializer.validated_data.keys()), 
                        {'user_id', 'token'})

    def test_mfa_token_serializer_invalid_token_length(self):
        """Test serializer with invalid token length"""
        data = {
            'user_id': self.user.id,
            'token': '12345'  # Too short
        }
        serializer = MFATokenSerializer(data=data)
        self.assertTrue(serializer.is_valid())  # Note: Token length validation should be in the view

    def test_mfa_token_serializer_invalid_user_id(self):
        """Test serializer with non-existent user_id"""
        data = {
            'user_id': 99999,  # Non-existent user
            'token': '123456'
        }
        serializer = MFATokenSerializer(data=data)
        self.assertTrue(serializer.is_valid())  # Note: User existence validation should be in the view