from django.contrib.auth import get_user_model
from django.contrib.auth.models import BaseUserManager
from django.db import connection, transaction
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


class TenantUserManager(BaseUserManager):
    """Manages user creation and authentication in the django-tenant-users package.

    This manager is tailored for handling users in a multi-tenant setup, ensuring correct
    assignment and management of user permissions across different tenants. It provides
    customized methods for creating standard users and superusers.
    """

    @transaction.atomic
    def create_user(self, **user_fields):
        """Create and save a new user with the specified user fields.

        This method creates a user by extracting key attributes such as 'is_staff',
        'is_superuser', and 'password' from the user_fields. It handles password setting
        and marks it as unusable if not provided. The user is linked to the public tenant
        with appropriate permissions setup based on 'is_staff' and 'is_superuser' flags.

        Args:
        **user_fields: Arbitrary keyword arguments. Important fields are 'password'
                      (str, optional), 'is_staff' (bool, defaults to False), and
                      'is_superuser' (bool, defaults to False). Any additional fields
                      are passed directly to the user model.

        Returns:
        AbstractBaseTenantUser: The newly created user object.
        """
        # Extract and remove password, is_staff, and is_superuser from extra_fields to prevent
        # passing them to the model constructor.
        password = user_fields.pop("password", None)
        is_staff = user_fields.pop("is_staff", False)
        is_superuser = user_fields.pop("is_superuser", False)

        # User creation and attribute setting logic
        user = self.create(**user_fields)
        user.set_password(password)

        # Set an unusable password if none is provided
        if not password:
            user.set_unusable_password()

        user.is_active = user_fields.get("is_active", True)

        user.save()

        # Link the user to the public tenant and set permissions
        public_tenant = get_tenant_model().objects.get(
            schema_name=get_public_schema_name()
        )
        public_tenant.add_user(user, is_staff=is_staff, is_superuser=is_superuser)

        # Send signal after user creation
        tenant_user_created.send(sender=self.__class__, user=user)

        return user

    def create_superuser(self, **user_fields):
        """Create and save a superuser with the specified user fields.

        This method configures a new superuser with all necessary permissions (staff, superuser,
        and verified status) by setting default values suitable for a superuser. It utilizes
        the `create_user` method to handle the user creation process.

        Args:
        **user_fields: Arbitrary keyword arguments for superuser attributes. It's expected
                      to include 'USERNAME_FIELD' and 'password'. 'is_staff' and 'is_superuser'
                      are set to True by default.

        Returns:
        AbstractBaseTenantUser: The newly created superuser object.
        """
        user_fields.setdefault("is_staff", True)
        user_fields.setdefault("is_superuser", True)

        return self.create_user(**user_fields)

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
