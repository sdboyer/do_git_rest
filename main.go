// Dumb little http server that mocks the REST api provided by drupal.org's
// git services.
package main

import (
	"encoding/json"
	"flag"
	"github.com/codegangsta/martini"
	"net/http"
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

var pushCtl string

func main() {
	m := martini.Classic()

	flag.StringVar(&pushCtl, "pushctl", "0", "Sets the pushctl state for the REST server.")
	flag.Parse()

	m.Get("/drupalorg/drupalorg-ssh-user-key", CheckFingerprintForUser)
	m.Get("/drupalorg/drupalorg-sshkey-check", VerifySshKey)
	m.Get("/drupalorg/drupalorg-vcs-auth-check-user-pass", CheckPasswordForUser)
	m.Get("/drupalorg/drupalorg-vcs-auth-fetch-user-hash", FetchUserPassHash)
	m.Get("/drupalorg/pushctl-state", func() string { return pushCtl })

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

func CheckPasswordForUser(req *http.Request) (resp string) {
	q := req.URL.Query()
	resp = "false"

	u, ue := q["username"]
	p, pe := q["password"]

	if !ue || !pe {
		return
	}

	if user := findUserByUsername(u[0]); user != nil {
		pass_len := len(user.Password)
		// TODO isn't as robust as the drupalorg checker; needs to look at
		// min length of 20. oh, and have proper hashed pws :(
		if len(p[0]) >= pass_len && p[0][0:pass_len] == user.Password {
			resp = "true"
		}
	}

	return
}

func FetchUserPassHash(req *http.Request) (resp string) {
	q := req.URL.Query()
	resp = "false"

	u, ue := q["username"]

	if !ue {
		return
	}

	if user := findUserByUsername(u[0]); user != nil {
		json, err := json.Marshal(user.Password)
		if err == nil {
			resp = string(json[:])
		}
	}

	return
}
