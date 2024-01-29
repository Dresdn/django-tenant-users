from django.contrib.auth import get_user_model
from django.contrib.auth.models import BaseUserManager
from django.db import connection
from django_tenants.utils import get_public_schema_name, get_tenant_model

from tenant_users.tenants.exceptions import DeleteError, ExistsError, SchemaError
from tenant_users.tenants.signals import tenant_user_created, tenant_user_deleted


class UserProfileManager(BaseUserManager):
    def _create_user(  # noqa: PLR0913
        self,
        email,
        password,
        is_staff,
        is_superuser,
        is_verified,
        **extra_fields,
    ):
        # Do some schema validation to protect against calling create user from
        # inside a tenant. Must create public tenant permissions during user
        # creation. This happens during assign role. This function cannot be
        # used until a public schema already exists
        UserModel = get_user_model()  # noqa: N806

        if connection.schema_name != get_public_schema_name():
            raise SchemaError(
                "Schema must be public for UserProfileManager user creation",
            )

        if not email:
            raise ValueError("Users must have an email address.")

        email = self.normalize_email(email)

        profile = UserModel.objects.filter(email=email).first()
        if profile and profile.is_active:
            raise ExistsError("User already exists!")

        # Profile might exist but not be active. If a profile does exist
        # all previous history logs will still be associated with the user,
        # but will not be accessible because the user won't be linked to
        # any tenants from the user's previous membership. There are two
        # exceptions to this. 1) The user gets re-invited to a tenant it
        # previously had access to (this is good thing IMO). 2) The public
        # schema if they had previous activity associated would be available
        if not profile:
            profile = UserModel()

        profile.email = email
        profile.is_active = True
        profile.is_verified = is_verified
        profile.set_password(password)
        for attr, value in extra_fields.items():
            setattr(profile, attr, value)
        profile.save()

        # Get public tenant tenant and link the user (no perms)
        public_tenant = get_tenant_model().objects.get(
            schema_name=get_public_schema_name(),
        )
        public_tenant.add_user(profile)

        # Public tenant permissions object was created when we assigned a
        # role to the user above, if we are a staff/superuser we set it here
        if is_staff or is_superuser:
            user_tenant = profile.usertenantpermissions
            user_tenant.is_staff = is_staff
            user_tenant.is_superuser = is_superuser
            user_tenant.save()

        tenant_user_created.send(sender=self.__class__, user=profile)

        return profile

    def create_user(
        self,
        email=None,
        password=None,
        *,
        is_staff: bool = False,
        **extra_fields,
    ):
        user = self._create_user(
            email,
            password,
            is_staff,
            is_superuser=False,
            is_verified=False,
            **extra_fields,
        )

        if not password:
            user.set_unusable_password()

        return user

    def create_superuser(self, password, email=None, **extra_fields):
        return self._create_user(
            email,
            password,
            is_staff=True,
            is_superuser=True,
            is_verified=True,
            **extra_fields,
        )

    def delete_user(self, user_obj):
        # Check to make sure we don't try to delete the public tenant owner
        # that would be bad....
        public_tenant = get_tenant_model().objects.get(
            schema_name=get_public_schema_name(),
        )
        if user_obj.pk == public_tenant.owner.pk:
            raise DeleteError("Cannot delete the public tenant owner!")

        # This includes the linked public tenant 'tenant'. It will delete the
        # Tenant permissions and unlink when user is deleted
        for tenant in user_obj.tenants.all():
            # If user owns the tenant, we call delete on the tenant
            # which will delete the user from the tenant as well
            if tenant.owner.pk == user_obj.pk:
                # Delete tenant will handle any other linked users to
                # that tenant
                tenant.delete_tenant()
            else:
                # Unlink user from all roles in any tenant it doesn't own
                tenant.remove_user(user_obj)

        # Set is_active, don't actually delete the object
        user_obj.is_active = False
        user_obj.save()

        tenant_user_deleted.send(sender=self.__class__, user=user_obj)
