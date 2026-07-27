// VG-SMELL-012 positive (java): the authorization decision is three hardcoded
// string comparisons — .equals in both directions plus equalsIgnoreCase — with no
// enum, no constant table and no policy annotation to aggregate them.
public class AccessService {

    public boolean canAccess(User user, Account account, Member member) {
        if (user.getRole().equals("admin")) {
            return true;
        }
        if ("owner".equals(account.getUserType())) {
            return true;
        }
        if (member.getPermission().equalsIgnoreCase("editor")) {
            return true;
        }
        return false;
    }
}
