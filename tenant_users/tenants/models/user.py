from django.conf import settings
from django.contrib.auth.models import AbstractBaseUser
from django.db import models
from django.utils.translation import gettext_lazy as _

from tenant_users.permissions.models import PermissionsMixinFacade
from tenant_users.tenants.exceptions import DeleteError
from tenant_users.tenants.managers import UserProfileManager


# This cant be located in the users app otherwise it would get loaded into
# both the public schema and all tenant schemas. We want profiles only
# in the public schema alongside the TenantBase model
class UserProfile(AbstractBaseUser, PermissionsMixinFacade):
    """Authentication model for django-tenant-users stored in the public tenant schema.

    This class represents an authentication-only model that is centrally located in the public tenant schema,
    yet maintains a link to the UserTenantPermissions model for authorization. It enables a singular global
    user profile across all tenants while allowing permissions to be managed on a per-tenant basis. This design
    ensures a unified user identity across different tenants with distinct permission sets in each tenant context.

    Access to a user's permissions requires routing the request through the relevant tenant. The implementation
    necessitates using the ModelBackend for proper integration.

    Inherits:
        AbstractBaseUser: Django's base class for user models, providing core user authentication features.
        PermissionsMixinFacade: A facade to adapt Django's PermissionMixin for multi-tenant environments.
    """

    USERNAME_FIELD = "email"
    objects = UserProfileManager()

    tenants = models.ManyToManyField(
        settings.TENANT_MODEL,
        verbose_name=_("tenants"),
        blank=True,
        help_text=_("The tenants this user belongs to."),
        related_name="user_set",
    )

    email = models.EmailField(
        _("Email Address"),
        unique=True,
        db_index=True,
    )

    is_active = models.BooleanField(_("active"), default=True)

    # Tracks whether the user's email has been verified
    is_verified = models.BooleanField(_("verified"), default=False)

    class Meta:
        abstract = True

    def has_verified_email(self):
        return self.is_verified

    def delete(self, *args, force_drop: bool = False, **kwargs):
        if force_drop:
            super().delete(*args, **kwargs)
        else:
            raise DeleteError(
                "UserProfile.objects.delete_user() should be used.",
            )

    def __str__(self):
        return self.email

    def get_short_name(self):
        return self.email

    def get_full_name(self):
        """Return string representation."""
        return str(self)
