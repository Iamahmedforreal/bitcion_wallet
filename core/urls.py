from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from . import views

app_name = 'core'

urlpatterns = [
    # Authentication endpoints
    path('auth/register/', views.UserRegistrationView.as_view(), name='register'),
    path('auth/login/', views.CustomTokenObtainPairView.as_view(), name='login'),
    path('auth/logout/', views.LogoutView.as_view(), name='logout'),
    path('auth/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    
    # User profile endpoints
    path('auth/profile/', views.UserProfileView.as_view(), name='profile'),
    path('auth/change-password/', views.ChangePasswordView.as_view(), name='change_password'),
    path('auth/toggle-2fa/', views.TwoFactorToggleView.as_view(), name='toggle_2fa'),
    
    # User information endpoints
    path('user/info/', views.user_info, name='user_info'),
    path('user/wallet/', views.wallet_info, name='wallet_info'),
]