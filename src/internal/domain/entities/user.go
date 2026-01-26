package entities

import "time"

// User represents an authenticated user with MAC label
type User struct {
	Username  string
	Realm     string
	MACLabel  int
	Groups    []string
	ExpiresAt time.Time
	Metadata  map[string]string
}

// FullName returns the full username with realm
func (u *User) FullName() string {
	if u.Realm != "" {
		return u.Username + "@" + u.Realm
	}
	return u.Username
}

// IsExpired checks if the user's authentication has expired
func (u *User) IsExpired() bool {
	return time.Now().After(u.ExpiresAt)
}

// HasGroup checks if the user belongs to a specific group
func (u *User) HasGroup(group string) bool {
	for _, g := range u.Groups {
		if g == group {
			return true
		}
	}
	return false
}
