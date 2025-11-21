"""
LDAP/Active Directory Configuration for NetVault

Copy these settings to your settings.py and configure according to your AD setup
"""
import ldap
from django_auth_ldap.config import LDAPSearch, GroupOfNamesType

# LDAP Server Configuration
# Example for Active Directory:
# AUTH_LDAP_SERVER_URI = "ldap://dc.example.com:389"
# For LDAPS (secure): "ldaps://dc.example.com:636"
AUTH_LDAP_SERVER_URI = "ldap://localhost:389"

# Bind credentials for searching LDAP
# Use a service account with read permissions
AUTH_LDAP_BIND_DN = "CN=netvault-svc,OU=Service Accounts,DC=example,DC=com"
AUTH_LDAP_BIND_PASSWORD = "your-service-account-password"

# User search configuration
AUTH_LDAP_USER_SEARCH = LDAPSearch(
    "OU=Users,DC=example,DC=com",  # Base DN for user search
    ldap.SCOPE_SUBTREE,
    "(sAMAccountName=%(user)s)"  # Search filter (for AD, use sAMAccountName)
)

# Alternative search filter for email-based login:
# "(mail=%(user)s)"

# User attribute mapping
AUTH_LDAP_USER_ATTR_MAP = {
    "first_name": "givenName",
    "last_name": "sn",
    "email": "mail",
    "username": "sAMAccountName",
}

# Group search configuration
AUTH_LDAP_GROUP_SEARCH = LDAPSearch(
    "OU=Groups,DC=example,DC=com",  # Base DN for group search
    ldap.SCOPE_SUBTREE,
    "(objectClass=group)"  # For AD, use 'group'; for OpenLDAP, use 'groupOfNames'
)

AUTH_LDAP_GROUP_TYPE = GroupOfNamesType(name_attr="cn")

# User flags configuration
AUTH_LDAP_USER_FLAGS_BY_GROUP = {
    "is_staff": "CN=NetVault-Admins,OU=Groups,DC=example,DC=com",
    "is_superuser": "CN=Domain Admins,OU=Groups,DC=example,DC=com",
}

# Mirror LDAP groups to Django groups
AUTH_LDAP_MIRROR_GROUPS = True

# Find and populate user groups
AUTH_LDAP_FIND_GROUP_PERMS = True

# Cache groups for performance (seconds)
AUTH_LDAP_CACHE_TIMEOUT = 3600

# LDAP connection options
AUTH_LDAP_CONNECTION_OPTIONS = {
    ldap.OPT_DEBUG_LEVEL: 0,
    ldap.OPT_REFERRALS: 0,  # Important for Active Directory
    ldap.OPT_NETWORK_TIMEOUT: 10,
}

# Start TLS for security (if not using LDAPS)
AUTH_LDAP_START_TLS = False

# Always update user on login
AUTH_LDAP_ALWAYS_UPDATE_USER = True

# Create local users from LDAP
AUTH_LDAP_CREATE_USER = True

# Signal handlers for user population
# Connect signal in accounts/apps.py:
# from django_auth_ldap.backend import populate_user
# from accounts.ldap_backend import populate_user_from_ldap
# populate_user.connect(populate_user_from_ldap)

# Logging configuration for LDAP debugging
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'loggers': {
        'django_auth_ldap': {
            'handlers': ['console'],
            'level': 'DEBUG',  # Change to INFO or WARNING in production
        },
        'accounts.ldap_backend': {
            'handlers': ['console'],
            'level': 'INFO',
        },
    },
}

# ============================================================================
# QUICK START GUIDE
# ============================================================================
# 1. Configure your AD/LDAP server details above
# 2. Add to settings.py:
#    from netvault.ldap_settings import *
# 3. Add LDAP backend to AUTHENTICATION_BACKENDS in settings.py:
#    AUTHENTICATION_BACKENDS = [
#        'accounts.ldap_backend.NetVaultLDAPBackend',
#        'django.contrib.auth.backends.ModelBackend',
#    ]
# 4. Test connection:
#    python manage.py ldap_test <username>
# 5. Configure AD groups to role mapping in accounts/ldap_backend.py
# ============================================================================
