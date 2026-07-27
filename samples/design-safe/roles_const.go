// Negative (go): a named role type plus a const block is the Go spelling of an
// enum. The wire strings live in that one table and every decision compares the
// constants, so VG-SMELL-012's go arm must stay silent.
package access

type Role string

const (
	RoleAdmin   Role = "admin"
	RoleManager Role = "manager"
	RoleEditor  Role = "editor"
)

type Account struct {
	Role Role `json:"role"`
}

func canAccess(a Account) bool {
	switch a.Role {
	case RoleAdmin:
		return true
	case RoleManager:
		return true
	case RoleEditor:
		return false
	}
	return false
}
