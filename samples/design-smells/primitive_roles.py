# VG-SMELL-012 positive (python): three hardcoded role comparisons, no enum/policy.
def can_access(user, req, member):
    if user.role == "admin":
        return grant_all()
    if req.user.role == "owner":
        return grant_owner()
    if member.permission == "editor":
        return grant_edit()
    return False
