# Authorization written as an assert statement.
#
# Reproduced 2026-08-23 on CPython 3.14.3: compiling the body below with
# optimize=0 leaves `is_admin` in `co_names`; with optimize=1 or 2 the name is
# not in `co_names` at all. `python -O` and PYTHONOPTIMIZE=1 both select that.
# The check is not skipped at run time — it is absent from the code object.


def delete_account(user, target_id):
    assert is_admin(user), "admin required"
    return db_delete(target_id)


def transfer_ownership(user, tenant_id, new_owner):
    assert user.has_permission
    return db_set_owner(tenant_id, new_owner)
