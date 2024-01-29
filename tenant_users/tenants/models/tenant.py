import time

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import connection, models
from django.utils.translation import gettext_lazy as _
from django_tenants.models import TenantMixin
from django_tenants.utils import get_public_schema_name, get_tenant_model

from tenant_users.permissions.models import UserTenantPermissions
from tenant_users.tenants.exceptions import DeleteError, ExistsError
from tenant_users.tenants.signals import tenant_user_added, tenant_user_removed


def schema_required(func):
    def inner(self, *args, **options):
        tenant_schema = self.schema_name
        # Save current schema and restore it when we're done
        saved_schema = connection.schema_name
        # Set schema to this tenants schema to start building permissions
        # in that tenant
        connection.set_schema(tenant_schema)
        try:
            result = func(self, *args, **options)
        finally:
            # Even if an exception is raised we need to reset our schema state
            connection.set_schema(saved_schema)
        return result

    return inner


class TenantBase(TenantMixin):
    """Contains global data and settings for the tenant model."""

    slug = models.SlugField(_("Tenant URL Name"), blank=True)

    # The owner of the tenant. Only they can delete it. This can be changed,
    # but it can't be blank. There should always be an owner.
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
    )
    created = models.DateTimeField(auto_now_add=True)
    modified = models.DateTimeField(auto_now=True)

    # Schema will be automatically created and synced when it is saved
    auto_create_schema = True
    # Schema will be automatically deleted when related tenant is deleted
    auto_drop_schema = True

    def delete(self, *args, force_drop: bool = False, **kwargs):
        """Override deleting of Tenant object.

        Args:
            force_drop (bool): If True, forces the deletion of the object. Defaults to False.
            *args: Variable length argument list.
            **kwargs: Arbitrary keyword arguments.
        """
        if force_drop:
            super().delete(force_drop, *args, **kwargs)
        else:
            raise DeleteError(
                "Not supported -- delete_tenant() should be used.",
            )

    @schema_required
    def add_user(self, user_obj, *, is_superuser: bool = False, is_staff: bool = False):
        """Add user to tenant.

        Args:
            user_obj: The user object to be added to the tenant.
            is_superuser (bool): If True, assigns superuser privileges to the user. Defaults to False.
            is_staff (bool): If True, assigns staff status to the user. Defaults to False.
        """
        # User already is linked here..
        if self.user_set.filter(id=user_obj.pk).exists():
            raise ExistsError(
                f"User already added to tenant: {user_obj}",
            )

        # User not linked to this tenant, so we need to create
        # tenant permissions
        UserTenantPermissions.objects.create(
            profile=user_obj,
            is_staff=is_staff,
            is_superuser=is_superuser,
        )
        # Link user to tenant
        user_obj.tenants.add(self)

        tenant_user_added.send(
            sender=self.__class__,
            user=user_obj,
            tenant=self,
        )

    @schema_required
    def remove_user(self, user_obj):
        """Remove user from tenant."""
        # Test that user is already in the tenant
        self.user_set.get(pk=user_obj.pk)

        # Dont allow removing an owner from a tenant. This must be done
        # Through delete tenant or transfer_ownership
        if user_obj.pk == self.owner.pk:
            raise DeleteError(
                f"Cannot remove owner from tenant: {self.owner}",
            )

        user_tenant_perms = user_obj.usertenantpermissions
        # Remove all current groups from user..
        groups = user_tenant_perms.groups
        groups.clear()

        # Unlink from tenant
        UserTenantPermissions.objects.filter(pk=user_tenant_perms.pk).delete()
        user_obj.tenants.remove(self)

        tenant_user_removed.send(
            sender=self.__class__,
            user=user_obj,
            tenant=self,
        )

    def delete_tenant(self):
        """Mark tenant for deletion.

        We don't actually delete the tenant out of the database, but we
        associate them with a the public schema user and change their url
        to reflect their delete datetime and previous owner
        The caller should verify that the user deleting the tenant owns
        the tenant.
        """
        # Prevent public tenant schema from being deleted
        if self.schema_name == get_public_schema_name():
            raise ValueError("Cannot delete public tenant schema")

        for user_obj in self.user_set.all():
            # Don't delete owner at this point
            if user_obj.pk == self.owner.pk:
                continue
            self.remove_user(user_obj)

        # Seconds since epoch, time() returns a float, so we convert to
        # an int first to truncate the decimal portion
        time_string = str(int(time.time()))
        new_url = f"{time_string}-{self.owner.pk!s}-{self.domain_url}"
        self.domain_url = new_url
        # The schema generated each time (even with same url slug) will
        # be unique so we do not have to worry about a conflict with that

        # Set the owner to the system user (public schema owner)
        public_tenant = get_tenant_model().objects.get(
            schema_name=get_public_schema_name(),
        )

        old_owner = self.owner

        # Transfer ownership to system
        self.transfer_ownership(public_tenant.owner)

        # Remove old owner as a user if the owner still exists after
        # the transfer
        if self.user_set.filter(pk=user_obj.pk).exists():
            self.remove_user(old_owner)

    @schema_required
    def transfer_ownership(self, new_owner):
        old_owner = self.owner

        # Remove current owner superuser status but retain any assigned role(s)
        old_owner_tenant = old_owner.usertenantpermissions
        old_owner_tenant.is_superuser = False
        old_owner_tenant.save()

        self.owner = new_owner

        # If original has no permissions left, remove user from tenant
        if not old_owner_tenant.groups.exists():
            self.remove_user(old_owner)

        try:
            # Set new user as superuser in this tenant if user already exists
            user = self.user_set.get(pk=new_owner.pk)
            user_tenant = user.usertenantpermissions
            user_tenant.is_superuser = True
            user_tenant.save()
        except get_user_model().DoesNotExist:
            # New user is not a part of the system, add them as a user..
            self.add_user(new_owner, is_superuser=True)

        self.save()

    class Meta:
        abstract = True
