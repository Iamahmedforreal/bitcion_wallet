from rest_framework import serializers
from .models import Transaction , Wallet , Customer
from decimal import Decimal
from django.contrib.auth.models import User
from django.db import transaction as db_transaction
from django.contrib.auth import authenticate


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True , required=True , min_length=8)
    password_confirm = serializers.CharField(write_only=True)
    first_name = serializers.CharField(required=True)
    last_name = serializers.CharField(required=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'password_confirm', 'first_name', 'last_name']

    def validate(self ,attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError("Password fields didn't match.")
        return attrs
    
    def create(self, validated_data):
        validated_data.pop('password_confirm')
    
        with db_transaction.atomic():
            user = User.objects.create_user(**validated_data)
            Customer.objects.create_user(user=user)
            Wallet.objects.create_user(user=user , balance = 0.0)
        return user
    
class LoginSerializer(serializers.Serializer):
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
        else:
            raise serializers.ValidationError("Both username and password are required.")
      

            

        


    
