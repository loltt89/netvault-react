"""
LDAP Authentication Backend for Active Directory integration
"""
from django_auth_ldap.backend import LDAPBackend
from django.contrib.auth import get_user_model
import logging

logger = logging.getLogger(__name__)
User = get_user_model()


class NetVaultLDAPBackend(LDAPBackend):
    """
    Custom LDAP backend for NetVault
    Handles user creation and updates from Active Directory
    """

    def authenticate_ldap_user(self, ldap_user, password):
        """
        Authenticate user against LDAP and create/update local user
        """
        user = super().authenticate_ldap_user(ldap_user, password)

        if user:
            # Mark as LDAP user
            user.is_ldap_user = True
            user.ldap_dn = ldap_user.dn

            # Map LDAP groups to roles
            ldap_groups = ldap_user.group_names
            user.role = self._map_ldap_groups_to_role(ldap_groups)

            user.save()

            logger.info(f"LDAP user authenticated: {user.email} with role {user.role}")

        return user

    def get_user(self, user_id):
        """Get user by ID"""
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

    def _map_ldap_groups_to_role(self, ldap_groups):
        """
        Map LDAP/AD groups to NetVault roles

        Configure this mapping based on your AD groups:
        - CN=NetVault-Admins,OU=Groups,DC=example,DC=com -> administrator
        - CN=NetVault-Operators,OU=Groups,DC=example,DC=com -> operator
        - CN=NetVault-Auditors,OU=Groups,DC=example,DC=com -> auditor
        - Default -> viewer
        """
        if not ldap_groups:
            return 'viewer'

        # Convert to lowercase for case-insensitive matching
        groups_lower = [g.lower() for g in ldap_groups]

        # Check for admin groups
        admin_patterns = ['netvault-admins', 'netvault admins', 'domain admins', 'administrators']
        if any(pattern in group for pattern in admin_patterns for group in groups_lower):
            return 'administrator'

        # Check for operator groups
        operator_patterns = ['netvault-operators', 'netvault operators', 'network operators']
        if any(pattern in group for pattern in operator_patterns for group in groups_lower):
            return 'operator'

        # Check for auditor groups
        auditor_patterns = ['netvault-auditors', 'netvault auditors', 'security auditors']
        if any(pattern in group for pattern in auditor_patterns for group in groups_lower):
            return 'auditor'

        # Default role
        return 'viewer'


def populate_user_from_ldap(sender, user=None, ldap_user=None, **kwargs):
    """
    Signal handler to populate user fields from LDAP
    Called when user is created or updated from LDAP
    """
    if ldap_user:
        # Map LDAP attributes to user model
        user.first_name = ldap_user.attrs.get('givenName', [''])[0]
        user.last_name = ldap_user.attrs.get('sn', [''])[0]
        user.email = ldap_user.attrs.get('mail', [''])[0] or user.username

        # Additional fields
        user.is_ldap_user = True
        user.ldap_dn = ldap_user.dn

        logger.info(f"Populated user from LDAP: {user.email}")
