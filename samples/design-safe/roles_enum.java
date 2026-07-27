// Negative (java): roles are an enum that owns its wire strings, and every
// decision compares enum constants. The literal "admin"/"owner"/"editor" strings
// still appear — inside the enum, where they belong — so this file is the standing
// proof that VG-SMELL-012's java arm keys on scattered comparisons and not on the
// mere presence of role literals.
public enum Role {
    ADMIN("admin"),
    OWNER("owner"),
    EDITOR("editor");

    private final String wire;

    Role(String wire) {
        this.wire = wire;
    }

    public String wire() {
        return wire;
    }

    public static boolean canAccess(User user, Account account, Member member) {
        if (user.getRole() == Role.ADMIN) {
            return true;
        }
        if (account.getRole() == Role.OWNER) {
            return true;
        }
        if (member.getRole() == Role.EDITOR) {
            return true;
        }
        return false;
    }
}
