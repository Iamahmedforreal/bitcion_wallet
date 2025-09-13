from django.contrib import admin
from .models import Customer, Wallet, Transaction

@admin.register(Customer)
class CustomerAdmin(admin.ModelAdmin):
    list_display = ('user', 'phone', 'created_at' , 'updated_at')
    search_fields = ('user__username', 'phone')
    list_filter = ('created_at',)

@admin.register(Wallet)
class WalletAdmin(admin.ModelAdmin):
    list_display = ('user', 'balance', 'address', 'created_at' , 'updated_at')
    search_fields = ('user__username', 'address')
    list_filter = ('created_at',)

@admin.register(Transaction)
class TransactionAdmin(admin.ModelAdmin):
    list_display  = ('from_wallet', 'to_wallet', 'amount', 'transaction_type', 'status', 'created_at' , 'updated_at')
    search_fields = ('from_wallet__user__username', 'to_wallet__user__username', 'transaction_type', 'status')
    list_filter = ('transaction_type', 'status', 'created_at')
    ordering = ('-created_at',)

