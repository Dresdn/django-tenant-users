from django.core.validators import EmailValidator
from django.db import models
from django.utils.translation import gettext_lazy as _

from tenant_users.tenants.models import AbstractBaseTenantUser

_NameFieldLength = 64


class TenantUser(AbstractBaseTenantUser):
    """Simple user model definition for testing."""

    USERNAME_FIELD = "email"

    email = models.EmailField(
        _("Email Address"),
        unique=True,
        db_index=True,
        blank=False,
        null=False,
        validators=[EmailValidator()],
    )

    name = models.CharField(max_length=_NameFieldLength, blank=True)

    # Tracks whether the user's email has been verified
    is_verified = models.BooleanField(_("verified"), default=False)
