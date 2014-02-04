// Dumb little http server that mocks the REST api provided by drupal.org's
// git services.
package main

import (
	//"encoding/json"
	"github.com/codegangsta/martini"
	"net/http"
	//	"net/url"
)

type User struct {
	Username    string
	Fingerprint string
	Password    string
	HasRole     bool
}

var users = []*User{
	&User{"normal_git", "ABCDEFGHIJKLMN", "arglebargle", true},
}

func main() {
	m := martini.Classic()

	m.Get("/drupalorg/drupalorg-ssh-user-key", CheckFingerprintForUser)
	m.Get("/drupalorg/drupalorg-sshkey-check", VerifySshKey)

	m.Run()
}

func findUserByUsername(name string) *User {
	for _, user := range users {
		if user.Username == name {
			return user
		}
	}
	return nil
}

func findUserByFingerprint(name string) *User {
	for _, user := range users {
		if user.Fingerprint == name {
			return user
		}
	}
	return nil
}

func CheckFingerprintForUser(req *http.Request) (resp string) {
	q := req.URL.Query()
	resp = "false"

	u, ue := q["username"]
	f, fe := q["fingerprint"]

	if !ue || !fe {
		return
	}

	if user := findUserByUsername(u[0]); user != nil {
		if user.Fingerprint == f[0] {
			resp = "true"
		}
	}

	return
}

func VerifySshKey(req *http.Request) (resp string) {
	q := req.URL.Query()
	resp = "false"

	f, fe := q["fingerprint"]
	if !fe {
		return
	}

	if user := findUserByFingerprint(f[0]); user != nil {
		resp = "true"
	}

	return
}
