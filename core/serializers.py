from rest_framework import serializers
from django.contrib.auth.models import User
from django.db import transaction
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from rest_framework.validators import UniqueValidator
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from .models import Customer, Transaction, Wallet
import uuid





class UserRegistrationSerializer(serializers.ModelSerializer):
    """Serializer for user registration"""
    password  = serializers.CharField(min_length=8, write_only=True)
    password_confirm = serializers.CharField(write_only=True)
    first_name = serializers.CharField( max_length=100 , required=True)
    last_name = serializers.CharField( max_length=100 , required=True) 
    phone = serializers.CharField(max_length=15 , required=True)

    class Meta:
        model = User
        fields = ('username', 'password', 'password_confirm', 'email', 'first_name', 'last_name', 'phone')
        extra_kwargs = {
            'email': {'required': True, 'validators': [UniqueValidator(queryset=User.objects.all())]},
        }
    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        return attrs
    
    def validate_phone(self , value):
        if Customer.objects.filter(phone = value).exists():
            raise serializers.ValidationError({"phone number already exists"})
        return value
    
    def create(self , validated_date):
        validated_date.pop('password_confirm')
        phone = validated_date.pop('phone')
       
        with transaction.atomic(): 
            user = User.objects.create_user(**validated_date)
            customer = Customer.objects.create(user=user)
            wallet_address = f"bc1{str(uuid.uuid4()).replace('-', '')[:30]}"
            wallet = Wallet.objects.create(user=user , address = wallet_address)
        return user



    
class UserLoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        username = attrs.get('username')
        password = attrs.get('password')

        if username and password:
            user = authenticate(username=username, password=password)
            if not user:
                raise serializers.ValidationError("Invalid username or password.")
            if not user.is_active:
                raise serializers.ValidationError("User account is disabled.")
            attrs['user'] = user
            return attrs
        else:
            raise serializers.ValidationError("Both username and password are required.")

        


    


class UserProfileSerializer(serializers.ModelSerializer):
    """Serializer for user profile information"""
    phone = serializers.CharField(source='customer.phone', read_only=True)
    two_factor_auth = serializers.BooleanField(source='customer.two_factor_auth', read_only=True)
    wallet_address = serializers.CharField(source='wallet.address', read_only=True)
    wallet_balance = serializers.DecimalField(
        source='wallet.balance', 
        max_digits=20, 
        decimal_places=8, 
        read_only=True
    )
    
    class Meta:
        model = User
        fields = (
            'id', 'username', 'email', 'first_name', 'last_name', 
            'phone', 'two_factor_auth', 'wallet_address', 'wallet_balance',
            'date_joined', 'last_login'
        )
        read_only_fields = ('id', 'username', 'date_joined', 'last_login')


class UserUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating user profile"""
    phone = serializers.CharField(max_length=15, required=False)
    
    class Meta:
        model = User
        fields = ('first_name', 'last_name', 'email', 'phone')
    
    def validate_phone(self, value):
        user = self.instance
        if Customer.objects.filter(phone=value).exclude(user=user).exists():
            raise serializers.ValidationError("This phone number is already in use.")
        return value
    
    def update(self, instance, validated_data):
        phone = validated_data.pop('phone', None)
        
        # Update user fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        
        # Update phone if provided
        if phone:
            customer, created = Customer.objects.get_or_create(user=instance)
            customer.phone = phone
            customer.save()
        
        return instance


class ChangePasswordSerializer(serializers.Serializer):
    """Serializer for changing password"""
    old_password = serializers.CharField(required=True, style={'input_type': 'password'})
    new_password = serializers.CharField(required=True, validators=[validate_password], style={'input_type': 'password'})
    new_password_confirm = serializers.CharField(required=True, style={'input_type': 'password'})
    
    def validate(self, attrs):
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError({"new_password": "New password fields didn't match."})
        return attrs
    
    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Old password is not correct")
        return value
    
    def save(self, **kwargs):
        password = self.validated_data['new_password']
        user = self.context['request'].user
        user.set_password(password)
        user.save()
        return user


class TwoFactorToggleSerializer(serializers.Serializer):
    """Serializer for enabling/disabling two-factor authentication"""
    enable = serializers.BooleanField(required=True)
    password = serializers.CharField(required=True, style={'input_type': 'password'})
    
    def validate_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Password is incorrect")
        return value
    
    def save(self, **kwargs):
        user = self.context['request'].user
        enable = self.validated_data['enable']
        
        customer, created = Customer.objects.get_or_create(user=user)
        customer.two_factor_auth = enable
        customer.save()
        
        return customer