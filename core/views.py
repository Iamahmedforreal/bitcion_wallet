from django.shortcuts import render
from rest_framework import status, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.generics import CreateAPIView, RetrieveUpdateAPIView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.tokens import RefreshToken, OutstandingToken, BlacklistedToken
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
from django.contrib.auth.models import User
from django.contrib.auth import logout
from .serializers import (
    UserRegistrationSerializer,
    UserProfileSerializer,
    UserUpdateSerializer,
    ChangePasswordSerializer,
    TwoFactorToggleSerializer
)
from .models import Customer, Wallet
from .permissions import IsOwnerOrReadOnly, IsWalletOwner


class CustomTokenObtainPairView(TokenObtainPairView):
    """Custom JWT token obtain view with additional user information"""
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['user_id'] = user.id
        token['staff'] = user.is_staff

        return token

        
        
    
 


class UserRegistrationView(CreateAPIView):
    """User registration view"""
    queryset = User.objects.all()
    serializer_class = UserRegistrationSerializer
    permission_classes = [permissions.AllowAny]
    
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        
        # Generate tokens for the new user
        refresh = RefreshToken.for_user(user)
        
        return Response({
            'message': 'User registered successfully',
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                
            },
            'tokens': {
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }
        }, status=status.HTTP_201_CREATED)


class UserProfileView(RetrieveUpdateAPIView):
    """User profile view for retrieving and updating user information"""
    serializer_class = UserProfileSerializer
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrReadOnly]
    
    def get_object(self):
        return self.request.user
    
    def get_serializer_class(self):
        if self.request.method in ['PUT', 'PATCH']:
            return UserUpdateSerializer
        return UserProfileSerializer


class LogoutView(APIView):
    """Logout view that blacklists the refresh token"""
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        try:
            refresh_token = request.data.get('refresh')
            if refresh_token:
                token = RefreshToken(refresh_token)
                token.blacklist()
            return Response(
                {'message': 'Successfully logged out'}, 
                status=status.HTTP_200_OK
            )
        except Exception as e:
            return Response(
                {'error': 'Invalid token or logout failed'}, 
                status=status.HTTP_400_BAD_REQUEST
            )


class ChangePasswordView(APIView):
    """View for changing user password"""
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            # Blacklist all existing tokens for security
            try:
                tokens = OutstandingToken.objects.filter(user=request.user)
                for token in tokens:
                    BlacklistedToken.objects.get_or_create(token=token)
            except:
                pass  # In case blacklisting is not enabled
            
            return Response(
                {'message': 'Password changed successfully. Please login again.'}, 
                status=status.HTTP_200_OK
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class TwoFactorToggleView(APIView):
    """View for enabling/disabling two-factor authentication"""
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        serializer = TwoFactorToggleSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            customer = serializer.save()
            return Response({
                'message': f'Two-factor authentication {"enabled" if customer.two_factor_auth else "disabled"}',
                'two_factor_auth': customer.two_factor_auth
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def user_info(request):
    """Get current user information"""
    try:
        customer = Customer.objects.get(user=request.user)
        wallet = Wallet.objects.get(user=request.user)
        
        data = {
            'id': request.user.id,
            'username': request.user.username,
            'email': request.user.email,
            'first_name': request.user.first_name,
            'last_name': request.user.last_name,
            'phone': customer.phone,
            'two_factor_auth': customer.two_factor_auth,
            'wallet_address': wallet.address,
            'wallet_balance': str(wallet.balance),
            'date_joined': request.user.date_joined,
            'last_login': request.user.last_login,
        }
        return Response(data, status=status.HTTP_200_OK)
    except (Customer.DoesNotExist, Wallet.DoesNotExist) as e:
        return Response(
            {'error': 'User profile or wallet not found'}, 
            status=status.HTTP_404_NOT_FOUND
        )


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def wallet_info(request):
    """Get user wallet information"""
    try:
        wallet = Wallet.objects.get(user=request.user)
        data = {
            'address': wallet.address,
            'balance': str(wallet.balance),
            'created_at': wallet.created_at,
            'updated_at': wallet.updated_at,
        }
        return Response(data, status=status.HTTP_200_OK)
    except Wallet.DoesNotExist:
        return Response(
            {'error': 'Wallet not found'}, 
            status=status.HTTP_404_NOT_FOUND
        )

