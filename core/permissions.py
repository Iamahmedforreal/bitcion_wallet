from rest_framework import permissions
from django.contrib.auth.models import User
from .models import Customer, Wallet


class IsOwnerOrReadOnly(permissions.BasePermission):
    """
    Custom permission to only allow owners of an object to edit it.
    """
    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed for any request,
        # so we'll always allow GET, HEAD or OPTIONS requests.
        if request.method in permissions.SAFE_METHODS:
            return True
        
        # Write permissions are only allowed to the owner of the object.
        return obj == request.user


class IsWalletOwner(permissions.BasePermission):
    """
    Custom permission to only allow wallet owners to access their wallet.
    """
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated
    
    def has_object_permission(self, request, view, obj):
        # Check if the user owns the wallet
        if hasattr(obj, 'user'):
            return obj.user == request.user
        return False


class IsCustomerOrReadOnly(permissions.BasePermission):
    """
    Custom permission for customer profile access.
    """
    def has_object_permission(self, request, view, obj):
        # Read permissions for authenticated users
        if request.method in permissions.SAFE_METHODS:
            return request.user and request.user.is_authenticated
        
        # Write permissions only for the customer owner
        if hasattr(obj, 'user'):
            return obj.user == request.user
        return False


class IsTransactionOwner(permissions.BasePermission):
    """
    Custom permission for transaction access.
    Only users involved in the transaction can view/modify it.
    """
    def has_object_permission(self, request, view, obj):
        if not request.user or not request.user.is_authenticated:
            return False
        
        # Check if user is involved in the transaction
        user_wallet = None
        try:
            user_wallet = Wallet.objects.get(user=request.user)
        except Wallet.DoesNotExist:
            return False
        
        # User can access if they own either the from_wallet or to_wallet
        return (obj.from_wallet == user_wallet or 
                obj.to_wallet == user_wallet)


class IsAdminOrOwner(permissions.BasePermission):
    """
    Custom permission that allows access to admin users or object owners.
    """
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated
    
    def has_object_permission(self, request, view, obj):
        # Admin users have full access
        if request.user.is_staff or request.user.is_superuser:
            return True
        
        # Regular users can only access their own objects
        if hasattr(obj, 'user'):
            return obj.user == request.user
        return obj == request.user


class IsSuperUserOrReadOnly(permissions.BasePermission):
    """
    Custom permission that allows read access to authenticated users
    but write access only to superusers.
    """
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        
        if request.method in permissions.SAFE_METHODS:
            return True
        
        return request.user.is_superuser


class CanModifyWallet(permissions.BasePermission):
    """
    Permission class for wallet modification operations.
    Users can only modify their own wallets.
    """
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated
    
    def has_object_permission(self, request, view, obj):
        # Only the wallet owner can modify the wallet
        return obj.user == request.user


class CanCreateTransaction(permissions.BasePermission):
    """
    Permission class for creating transactions.
    Users can only create transactions from their own wallets.
    """
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        
        # For POST requests (creating transactions), check if user owns the from_wallet
        if request.method == 'POST':
            from_wallet_id = request.data.get('from_wallet')
            if from_wallet_id:
                try:
                    wallet = Wallet.objects.get(id=from_wallet_id)
                    return wallet.user == request.user
                except Wallet.DoesNotExist:
                    return False
        
        return True


class TwoFactorRequired(permissions.BasePermission):
    """
    Permission class that requires two-factor authentication to be enabled.
    """
    message = "Two-factor authentication is required for this operation."
    
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        
        try:
            customer = Customer.objects.get(user=request.user)
            return customer.two_factor_auth
        except Customer.DoesNotExist:
            return False


class IsActiveUser(permissions.BasePermission):
    """
    Permission class that checks if the user account is active.
    """
    message = "User account is not active."
    
    def has_permission(self, request, view):
        return (request.user and 
                request.user.is_authenticated and 
                request.user.is_active)