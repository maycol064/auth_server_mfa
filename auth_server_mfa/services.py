from django.core.cache import cache
from django.db import transaction
from datetime import datetime, timedelta
import logging
import pyotp
import ntplib

logger = logging.getLogger(__name__)

class TimeService:
    _ntp_server = 'pool.ntp.org'
    _time_offset = 0
    _last_sync = None
    _sync_interval = timedelta(hours=1)

    @classmethod
    def sync_time(cls):
        try:
            if (cls._last_sync is None or 
                datetime.now() - cls._last_sync > cls._sync_interval):
                ntp_client = ntplib.NTPClient()
                response = ntp_client.request(cls._ntp_server, timeout=5)
                cls._time_offset = response.offset
                cls._last_sync = datetime.now()
                logger.info(f"NTP sync completed. Offset: {cls._time_offset}")
        except Exception as e:
            logger.warning(f"NTP sync failed: {str(e)}")

    @classmethod
    def get_current_time(cls):
        if cls._last_sync is None:
            cls.sync_time()
        return datetime.now() + timedelta(seconds=cls._time_offset)

class MFAService:
    MAX_ATTEMPTS = 3
    LOCKOUT_DURATION = timedelta(minutes=15)
    TOKEN_VALIDITY_WINDOW = 1 
    
    @staticmethod
    def get_lock_key(user_id):
        return f"mfa_lock_{user_id}"
    
    @staticmethod
    def get_attempt_key(user_id):
        return f"mfa_attempts_{user_id}"

    @classmethod
    @transaction.atomic
    def handle_mfa_attempt(cls, user, token):
        lock_key = cls.get_lock_key(user.id)
        attempt_key = cls.get_attempt_key(user.id)
        
        if cache.get(lock_key):
            return False, "Usuario bloqueado temporalmente"
        
        TimeService.sync_time()
        
        attempts = cache.get(attempt_key, 0)
        
        if user.verify_mfa_token(token):
            cache.delete(attempt_key)
            return True, "Token válido"
            
        attempts += 1
        cache.set(attempt_key, attempts, timeout=cls.LOCKOUT_DURATION.seconds)
        
        if attempts >= cls.MAX_ATTEMPTS:
            cache.set(lock_key, True, timeout=cls.LOCKOUT_DURATION.seconds)
            logger.warning(f"Usuario {user.id} bloqueado por múltiples intentos fallidos de MFA")
            return False, "Máximo de intentos alcanzado. Usuario bloqueado temporalmente"
            
        return False, f"Token inválido. Intentos restantes: {cls.MAX_ATTEMPTS - attempts}"

    @classmethod
    def generate_backup_codes(cls, user):
        backup_codes = []
        for _ in range(8): 
            code = pyotp.random_base32()[:8]  
            backup_codes.append(code)
        return backup_codes