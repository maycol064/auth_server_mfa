from django.db import models
from django.contrib.auth.models import AbstractUser
from django.db import transaction
import pyotp
from django.conf import settings
from django.utils import timezone
from datetime import timedelta

class User(AbstractUser):
    mfa_secret = models.CharField(max_length=32, null=True, blank=True)
    mfa_enabled = models.BooleanField(default=False)
    failed_mfa_attempts = models.IntegerField(default=0)
    last_mfa_attempt = models.DateTimeField(null=True)
    totp_counter = models.IntegerField(default=0)
    
    class Meta:
        indexes = [
            models.Index(fields=['username']),
            models.Index(fields=['email']),
        ]

    @transaction.atomic
    def verify_mfa_token(self, token):
        if not self.mfa_enabled or not self.mfa_secret:
            return False

        if not token or len(token) != 6:
            return False

        try:
            totp = pyotp.TOTP(self.mfa_secret)
            valid = totp.verify(token, valid_window=1)
            
            if valid:
                self.last_mfa_attempt = timezone.now()
                self.failed_mfa_attempts = 0
                self.save(update_fields=['last_mfa_attempt', 'failed_mfa_attempts'])
                return True
            
            self.failed_mfa_attempts += 1
            self.last_mfa_attempt = timezone.now()
            self.save(update_fields=['failed_mfa_attempts', 'last_mfa_attempt'])
            return False
            
        except Exception as e:
            print(f"Error verifying MFA token: {str(e)}")
            return False

    def generate_mfa_secret(self):
        self.mfa_secret = pyotp.random_base32()
        self.save(update_fields=['mfa_secret'])
        return self.mfa_secret

    def get_mfa_uri(self):
        if not self.mfa_secret:
            return None
        totp = pyotp.TOTP(self.mfa_secret)
        return totp.provisioning_uri(
            name=self.email,
            issuer_name="YourAppName"
        )

def get_expiry_time():
    return timezone.now() + timedelta(minutes=5)

class MFAToken(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    token = models.CharField(max_length=6, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(default=get_expiry_time)

    class Meta:
        indexes = [
            models.Index(fields=['user', 'token']),
            models.Index(fields=['expires_at']),
        ]