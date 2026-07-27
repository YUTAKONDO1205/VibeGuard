// VG-SMELL-012 positive (kotlin): three hardcoded role comparisons, no enum class,
// no sealed hierarchy, no const val table.
class AccessService {

    fun canAccess(user: User, account: Account, member: Member): Boolean {
        if (user.role == "admin") return true
        if (account.userType == "manager") return true
        if (member.permission == "editor") return true
        return false
    }
}
