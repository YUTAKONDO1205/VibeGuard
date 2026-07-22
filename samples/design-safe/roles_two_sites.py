# Negative: only two role comparisons — below VG-SMELL-012's three-site threshold.
def can_access(user):
    if user.role == "admin":
        return True
    if user.role == "owner":
        return False
    return False
