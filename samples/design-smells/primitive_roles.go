// VG-SMELL-012 positive (go): three hardcoded role comparisons and no named role
// type, no const/iota enumeration. The struct tag below is deliberate — it puts a
// backtick raw string in the file, which is the shape a "skip every file with a
// backtick" design would have silenced (struct tags appear in nearly all real Go).
package access

type User struct {
	Name string `json:"name"`
	Role string `json:"role"`
}

func canAccess(u User, a Account, m Member) bool {
	if u.Role == "admin" {
		return true
	}
	if a.UserType == "manager" {
		return true
	}
	if m.Permission == "editor" {
		return true
	}
	return false
}
