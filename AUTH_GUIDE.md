# Bitcoin App Authentication & JWT Guide

This document provides a comprehensive guide to the authentication and permission system implemented in your Bitcoin application using JWT (JSON Web Tokens).

## Features Implemented

### 🔐 Authentication System
- User registration with automatic wallet creation
- JWT-based login/logout
- Token refresh mechanism
- Password change functionality
- Two-factor authentication toggle
- Token blacklisting for secure logout

### 🛡️ Permission System
- Custom permission classes for different resources
- Wallet ownership verification
- Transaction access controls
- Admin and superuser permissions
- Two-factor authentication requirements

### 🏦 Automatic Setup
- Customer profile creation on registration
- Bitcoin wallet creation with unique address
- Integration with existing User model

## API Endpoints

### Authentication Endpoints

#### User Registration
```http
POST /api/v1/auth/register/
Content-Type: application/json

{
    "username": "johndoe",
    "email": "john@example.com",
    "password": "securePassword123!",
    "password_confirm": "securePassword123!",
    "first_name": "John",
    "last_name": "Doe",
    "phone": "+1234567890"
}
```

**Response:**
```json
{
    "message": "User registered successfully",
    "user": {
        "id": 1,
        "username": "johndoe",
        "email": "john@example.com",
        "first_name": "John",
        "last_name": "Doe"
    },
    "tokens": {
        "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
        "access": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
    }
}
```

#### User Login
```http
POST /api/v1/auth/login/
Content-Type: application/json

{
    "username": "johndoe",
    "password": "securePassword123!"
}
```

**Response:**
```json
{
    "access": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "user": {
        "id": 1,
        "username": "johndoe",
        "email": "john@example.com",
        "first_name": "John",
        "last_name": "Doe",
        "phone": "+1234567890",
        "two_factor_auth": false,
        "wallet_address": "bc1abc123...",
        "wallet_balance": "0.00000000"
    }
}
```

#### Token Refresh
```http
POST /api/v1/auth/token/refresh/
Content-Type: application/json

{
    "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

#### User Logout
```http
POST /api/v1/auth/logout/
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
Content-Type: application/json

{
    "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

### Profile Management

#### Get User Profile
```http
GET /api/v1/auth/profile/
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
```

#### Update User Profile
```http
PATCH /api/v1/auth/profile/
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
Content-Type: application/json

{
    "first_name": "John",
    "last_name": "Smith",
    "email": "johnsmith@example.com",
    "phone": "+1234567891"
}
```

#### Change Password
```http
POST /api/v1/auth/change-password/
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
Content-Type: application/json

{
    "old_password": "oldPassword123!",
    "new_password": "newPassword123!",
    "new_password_confirm": "newPassword123!"
}
```

#### Toggle Two-Factor Authentication
```http
POST /api/v1/auth/toggle-2fa/
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
Content-Type: application/json

{
    "enable": true,
    "password": "currentPassword123!"
}
```

### User Information

#### Get User Info
```http
GET /api/v1/user/info/
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
```

#### Get Wallet Info
```http
GET /api/v1/user/wallet/
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
```

## JWT Configuration

### Token Settings
- **Access Token Lifetime:** 60 minutes
- **Refresh Token Lifetime:** 7 days
- **Token Rotation:** Enabled (new refresh token on each refresh)
- **Blacklisting:** Enabled (tokens are blacklisted after rotation)

### Custom Token Claims
The JWT tokens include additional user information:
- `username`
- `email`
- `is_staff`
- `is_superuser`
- `phone` (if customer profile exists)
- `two_factor_auth` (if customer profile exists)

## Permission Classes

### Available Permission Classes

1. **IsOwnerOrReadOnly** - Users can only edit their own objects
2. **IsWalletOwner** - Users can only access their own wallets
3. **IsCustomerOrReadOnly** - Customer profile access control
4. **IsTransactionOwner** - Transaction access for involved parties only
5. **IsAdminOrOwner** - Admin users or object owners
6. **IsSuperUserOrReadOnly** - Read access for all, write for superusers only
7. **CanModifyWallet** - Wallet modification permissions
8. **CanCreateTransaction** - Transaction creation permissions
9. **TwoFactorRequired** - Requires 2FA to be enabled
10. **IsActiveUser** - Requires active user account

### Usage Example
```python
from core.permissions import IsWalletOwner, TwoFactorRequired

class WalletTransferView(APIView):
    permission_classes = [IsWalletOwner, TwoFactorRequired]
    
    def post(self, request):
        # Only wallet owners with 2FA enabled can transfer
        pass
```

## Security Features

### 🔒 Token Security
- Tokens are blacklisted on logout
- All tokens are invalidated on password change
- Refresh token rotation prevents token reuse
- Custom signing key configuration

### 🛡️ Permission Security
- Granular permissions for different operations
- Wallet ownership verification
- Transaction participant verification
- Two-factor authentication requirements

### 🚫 Protection Against
- Token replay attacks (through blacklisting)
- Unauthorized wallet access
- Cross-user data access
- Password reuse (through validation)

## Client-Side Implementation

### Using the Authentication System

#### JavaScript Example
```javascript
// Registration
const register = async (userData) => {
    const response = await fetch('/api/v1/auth/register/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(userData)
    });
    
    const data = await response.json();
    if (data.tokens) {
        localStorage.setItem('access_token', data.tokens.access);
        localStorage.setItem('refresh_token', data.tokens.refresh);
    }
    return data;
};

// Login
const login = async (username, password) => {
    const response = await fetch('/api/v1/auth/login/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, password })
    });
    
    const data = await response.json();
    if (data.access) {
        localStorage.setItem('access_token', data.access);
        localStorage.setItem('refresh_token', data.refresh);
    }
    return data;
};

// Authenticated request
const makeAuthenticatedRequest = async (url, options = {}) => {
    const token = localStorage.getItem('access_token');
    
    const response = await fetch(url, {
        ...options,
        headers: {
            ...options.headers,
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
        },
    });
    
    if (response.status === 401) {
        // Token expired, try to refresh
        await refreshToken();
        // Retry request with new token
        return makeAuthenticatedRequest(url, options);
    }
    
    return response;
};

// Token refresh
const refreshToken = async () => {
    const refresh = localStorage.getItem('refresh_token');
    
    const response = await fetch('/api/v1/auth/token/refresh/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ refresh })
    });
    
    const data = await response.json();
    if (data.access) {
        localStorage.setItem('access_token', data.access);
    }
    return data;
};

// Logout
const logout = async () => {
    const refresh = localStorage.getItem('refresh_token');
    
    await fetch('/api/v1/auth/logout/', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${localStorage.getItem('access_token')}`,
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ refresh })
    });
    
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
};
```

## Testing the System

### 1. Start the Development Server
```bash
python manage.py runserver
```

### 2. Test Registration
```bash
curl -X POST http://localhost:8000/api/v1/auth/register/ \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "TestPass123!",
    "password_confirm": "TestPass123!",
    "first_name": "Test",
    "last_name": "User",
    "phone": "+1234567890"
  }'
```

### 3. Test Login
```bash
curl -X POST http://localhost:8000/api/v1/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "TestPass123!"
  }'
```

### 4. Test Protected Endpoint
```bash
curl -X GET http://localhost:8000/api/v1/user/info/ \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## Troubleshooting

### Common Issues

1. **Token Expired Error**
   - Use the refresh token to get a new access token
   - Check if refresh token is also expired

2. **Permission Denied**
   - Verify user has correct permissions
   - Check if 2FA is required for the operation

3. **Invalid Token**
   - Token may be blacklisted
   - Re-authenticate to get new tokens

### Debug Mode
In development, you can check token validation in Django admin at:
- `/admin/token_blacklist/outstandingtoken/`
- `/admin/token_blacklist/blacklistedtoken/`

## Next Steps

1. Implement transaction endpoints with proper permissions
2. Add email verification for registration
3. Implement actual 2FA with TOTP/SMS
4. Add rate limiting for authentication endpoints
5. Implement password reset functionality

This authentication system provides a solid foundation for your Bitcoin application with proper security measures and user management capabilities.