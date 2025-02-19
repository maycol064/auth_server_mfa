from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import authenticate, login, logout
from django.utils import timezone
from datetime import timedelta
import pyotp
from django.db import transaction
from rest_framework.renderers import JSONRenderer
from .serializers import UserSerializer, LoginSerializer, MFATokenSerializer, RegisterSerializer
from .models import User, MFAToken
from django.core.exceptions import ValidationError

class AuthViewSet(viewsets.ViewSet):
    renderer_classes = [JSONRenderer]
    authentication_classes = [TokenAuthentication]
    permission_classes = []

    @action(detail=False, methods=['post'])
    def register(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            try:
                with transaction.atomic():
                    user = User.objects.create_user(
                        username=serializer.validated_data['username'],
                        email=serializer.validated_data['email'],
                        password=serializer.validated_data['password']
                    )
                    
                    token, _ = Token.objects.get_or_create(user=user)
                    
                    return Response({
                        'message': 'Usuario registrado exitosamente',
                        'token': token.key,
                        'user': UserSerializer(user).data
                    }, status=status.HTTP_201_CREATED)
            except ValidationError as e:
                return Response(
                    {'error': str(e)},
                    status=status.HTTP_400_BAD_REQUEST
                )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['post'])
    def login(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = authenticate(
                username=serializer.validated_data['username'],
                password=serializer.validated_data['password']
            )
            
            if user:
                login(request, user)
                token, _ = Token.objects.get_or_create(user=user)
                
                if user.mfa_enabled:
                    with transaction.atomic():
                        totp = pyotp.TOTP(user.mfa_secret)
                        current_token = totp.now()
                        
                        MFAToken.objects.filter(
                            user=user,
                            expires_at__lt=timezone.now()
                        ).delete()
                        
                        mfa_token = MFAToken.objects.create(
                            user=user,
                            token=current_token,
                            expires_at=timezone.now() + timedelta(minutes=5)
                        )
                        
                        return Response({
                            'message': 'Se requiere verificación MFA',
                            'requires_mfa': True,
                            'user_id': user.id,
                            'token': token.key,
                            'mfa_token': mfa_token.token
                        })
                
                return Response({
                    'message': 'Login exitoso',
                    'token': token.key,
                    'user': UserSerializer(user).data
                })
                
            return Response(
                {'error': 'Credenciales inválidas'}, 
                status=status.HTTP_401_UNAUTHORIZED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['post'])
    def verify_mfa(self, request):
        serializer = MFATokenSerializer(data=request.data)
        if serializer.is_valid():
            try:
                with transaction.atomic():
                    user = User.objects.select_for_update().get(
                        pk=serializer.validated_data['user_id']
                    )
                    token = serializer.validated_data['token']
                    if not user.mfa_enabled:
                        return Response(
                            {'error': 'MFA no está habilitado para este usuario'},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                    if user.verify_mfa_token(token):
                        user.last_mfa_attempt = timezone.now()
                        user.failed_mfa_attempts = 0
                        user.save(update_fields=['last_mfa_attempt', 'failed_mfa_attempts'])
                        
                        auth_token, _ = Token.objects.get_or_create(user=user)
                        return Response({
                            'message': 'Verificación MFA exitosa',
                            'token': auth_token.key,
                            'user': UserSerializer(user).data
                        })
                    
                    user.failed_mfa_attempts += 1
                    user.last_mfa_attempt = timezone.now()
                    user.save(update_fields=['failed_mfa_attempts', 'last_mfa_attempt'])
                    
                    return Response(
                        {'error': 'Token MFA inválido'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                    
            except User.DoesNotExist:
                return Response(
                    {'error': 'Usuario no encontrado'},
                    status=status.HTTP_404_NOT_FOUND
                )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['post'], permission_classes=[IsAuthenticated])
    def initiate_mfa_setup(self, request):
        if not request.user.is_authenticated:
            return Response(
                {'error': 'Se requiere autenticación'},
                status=status.HTTP_401_UNAUTHORIZED
            )
            
        user = request.user
        if user.mfa_enabled:
            return Response(
                {'error': 'MFA ya está habilitado'},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        try:
            with transaction.atomic():
                secret = pyotp.random_base32()
                user.mfa_secret = secret
                user.mfa_setup_pending = True
                user.mfa_enabled = False
                user.failed_mfa_attempts = 0
                user.last_mfa_attempt = None
                user.totp_counter = 0
                user.save()
                
                totp = pyotp.TOTP(secret)
                provisioning_uri = totp.provisioning_uri(
                    user.email,
                    issuer_name="SecureBankBC"
                )
                
                return Response({
                    'message': 'Configuración MFA iniciada. Por favor verifica con un código.',
                    'secret': secret,
                    'qr_uri': provisioning_uri
                })
        except Exception as e:
            return Response(
                {'error': f'Error al iniciar configuración MFA: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=False, methods=['post'], permission_classes=[IsAuthenticated])
    def verify_and_enable_mfa(self, request):
        if not request.user.is_authenticated:
            return Response(
                {'error': 'Se requiere autenticación'},
                status=status.HTTP_401_UNAUTHORIZED
            )
            
        user = request.user
        if user.mfa_enabled:
            return Response(
                {'error': 'MFA ya está habilitado'},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        code = request.data.get('code')
        if not code:
            return Response(
                {'error': 'Se requiere código de verificación'},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        try:
            totp = pyotp.TOTP(user.mfa_secret)
            if totp.verify(code):
                user.mfa_enabled = True
                user.save()
                
                return Response({
                    'message': 'MFA verificado y habilitado exitosamente',
                    'user': UserSerializer(user).data
                })
            else:
                return Response(
                    {'error': 'Código inválido'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        except Exception as e:
            return Response(
                {'error': f'Error al verificar MFA: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=False, methods=['post'])
    def disable_mfa(self, request):
        if not request.user.is_authenticated:
            return Response(
                {'error': 'Se requiere autenticación'},
                status=status.HTTP_401_UNAUTHORIZED
            )
            
        user = request.user
        if not user.mfa_enabled:
            return Response(
                {'error': 'MFA no está habilitado'},
                status=status.HTTP_400_BAD_REQUEST
            )
            
        try:
            with transaction.atomic():
                user.mfa_secret = None
                user.mfa_enabled = False
                user.failed_mfa_attempts = 0
                user.last_mfa_attempt = None
                user.totp_counter = 0
                user.save()
                
                return Response({
                    'message': 'MFA deshabilitado exitosamente',
                    'user': UserSerializer(user).data
                })
        except Exception as e:
            return Response(
                {'error': f'Error al deshabilitar MFA: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=False, methods=['post'])
    def logout(self, request):
        try:
            if hasattr(request.user, 'auth_token'):
                request.user.auth_token.delete()  
            logout(request) 

            return Response({'message': 'Sesión cerrada exitosamente'}, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response(
                {'error': f'Error al cerrar sesión: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )