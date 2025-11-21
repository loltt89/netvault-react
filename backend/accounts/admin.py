from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User, AuditLog


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = ['email', 'username', 'role', 'is_active', 'two_factor_enabled', 'date_joined']
    list_filter = ['role', 'is_active', 'two_factor_enabled', 'is_ldap_user']
    search_fields = ['email', 'username', 'first_name', 'last_name']
    ordering = ['-date_joined']

    fieldsets = (
        (None, {'fields': ('email', 'username', 'password')}),
        ('Personal info', {'fields': ('first_name', 'last_name')}),
        ('Permissions', {'fields': ('role', 'is_active', 'is_staff', 'is_superuser')}),
        ('2FA', {'fields': ('two_factor_enabled', 'two_factor_secret')}),
        ('LDAP', {'fields': ('is_ldap_user', 'ldap_dn')}),
        ('Preferences', {'fields': ('preferred_language', 'theme')}),
        ('Important dates', {'fields': ('last_login', 'date_joined', 'last_password_change')}),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'username', 'password1', 'password2', 'role'),
        }),
    )


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ['user', 'action', 'resource_type', 'resource_name', 'timestamp', 'success']
    list_filter = ['action', 'resource_type', 'success', 'timestamp']
    search_fields = ['user__email', 'resource_name', 'description']
    readonly_fields = ['user', 'action', 'resource_type', 'resource_id', 'resource_name',
                       'description', 'ip_address', 'user_agent', 'timestamp', 'success', 'error_message']
    ordering = ['-timestamp']

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False
