from django.dispatch import Signal

# An existing user removed from a tenant
tenant_user_removed = Signal()

# An existing user added to a tenant
tenant_user_added = Signal()

# A new user is created
tenant_user_created = Signal()

# An existing user is deleted
tenant_user_deleted = Signal()
