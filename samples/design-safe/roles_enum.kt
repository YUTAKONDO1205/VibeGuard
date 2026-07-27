// Negative (kotlin): an enum class owns the wire strings and every decision
// compares enum constants. VG-SMELL-012's kotlin arm must stay silent.
enum class Role(val wire: String) {
    ADMIN("admin"),
    MANAGER("manager"),
    EDITOR("editor"),
}

class AccessService {

    fun canAccess(user: User, account: Account, member: Member): Boolean {
        if (user.role == Role.ADMIN) return true
        if (account.role == Role.MANAGER) return true
        if (member.role == Role.EDITOR) return false
        return false
    }
}
