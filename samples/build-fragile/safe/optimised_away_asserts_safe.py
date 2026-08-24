# The same two functions with the decision raised explicitly, so it survives an
# optimised interpreter.
#
# `assert` is kept for what it is for: a statement about program state that is
# allowed to vanish, because nothing about access control depends on it.


def delete_account(user, target_id):
    if not is_admin(user):
        raise PermissionError("admin required")
    return db_delete(target_id)


def transfer_ownership(user, tenant_id, new_owner):
    if not user.has_permission:
        raise PermissionError("permission required")
    assert isinstance(tenant_id, int)
    return db_set_owner(tenant_id, new_owner)
