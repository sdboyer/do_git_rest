// Dumb little http server that mocks the REST api provided by drupal.org's
// git services.
package main

import (
	"encoding/json"
	"flag"
	"github.com/codegangsta/martini"
	"net/http"
)

const (
	DRUPALORG_GIT_AUTH_NO_ROLE = 1 << iota
	DRUPALORG_GIT_AUTH_ACCOUNT_SUSPENDED
	DRUPALORG_GIT_AUTH_NOT_CONSENTED
	DRUPALORG_GIT_AUTH_ACCOUNT_BLOCKED
)

type User struct {
	Username     string
	Fingerprints map[string]string
	Password     string
	Blocked      int
}

func (u *User) HasFingerprint(fingerprint string) bool {
	for _, fp := range u.Fingerprints {
		if fp == fingerprint {
			return true
		}
	}

	return false
}

type Project struct {
	RepoId            int
	RepoName          string
	ProjectId         int
	ProjectName       string
	Status            bool
	ProtectedTags     []string
	ProtectedBranches []string
	Users             []*User
}

type userdata struct {
	per_label     []string `json: per-label`
	branch_delete string   // stupid php, converting ints to strings from db
	pass          string
	global        int
	uid           string // ibid. string, but actually int
	access        string // string, but actually int
	name          string
	tag_delete    string // string, but actually int
	tag_create    string // string, but actually int
	branch_create string // string, but actually int
	ssh_keys      map[string]string
	tag_update    string // string, but actually int
	branch_update string // string, but actually int
	repo_id       string // string, but actually int
}

func defaultUserdata() *userdata {
	u := &userdata{
		per_label:     []string{},
		branch_delete: "0",
		global:        0, // TODO check what this is in reference to
		access:        "2",
		tag_delete:    "0",
		tag_create:    "0",
		branch_create: "0",
		tag_update:    "0",
		branch_update: "0",
	}
	return u
}

type project struct {
	project          string
	project_nid      string // string, but actually int
	repository_name  string
	repo_id          string // string, but actually int
	repo_group       int
	status           int
	protected_labels map[string][]string
	users            map[string]userdata
}

var users = map[string]*User{
	"normal": &User{
		Username: "normal_git",
		Fingerprints: map[string]string{
			"primary": "ABCDEFGHIJKLMN", // TODO make this real
		},
		Password: "arglebargle", // TODO make this real
		Blocked:  0,
	},
	"missing_role": &User{
		Username: "missing_role",
		Fingerprints: map[string]string{
			"primary": "ABCDEFGHIJKLMN", // TODO make this real
		},
		Password: "higgledypiggledy",
		Blocked:  DRUPALORG_GIT_AUTH_NO_ROLE,
	},
	"suspended": &User{
		Username: "suspended",
		Fingerprints: map[string]string{
			"primary": "ABCDEFGHIJKLMN", // TODO make this real
		},
		Password: "smellyface",
		Blocked:  DRUPALORG_GIT_AUTH_NO_ROLE | DRUPALORG_GIT_AUTH_ACCOUNT_SUSPENDED,
	},
	"not_consented": &User{
		Username: "not_consented",
		Fingerprints: map[string]string{
			"primary": "ABCDEFGHIJKLMN", // TODO make this real
		},
		Password: "downunder",
		Blocked:  DRUPALORG_GIT_AUTH_NO_ROLE | DRUPALORG_GIT_AUTH_NOT_CONSENTED,
	},
	"blocked": &User{
		Username: "not_consented",
		Fingerprints: map[string]string{
			"primary": "ABCDEFGHIJKLMN", // TODO make this real
		},
		Password: "waytobraybob",
		Blocked:  DRUPALORG_GIT_AUTH_ACCOUNT_BLOCKED,
	},
}

var projects = []*Project{
	&Project{
		RepoId:            1,
		RepoName:          "Repo 1",
		ProjectId:         1,
		ProjectName:       "Project 1",
		Status:            true,
		ProtectedTags:     []string{"7.x-1.0"},
		ProtectedBranches: []string{"7.x-1.x"},
		Users:             []*User{users["normal"]},
	},
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
	//m.Get("/drupalorg/vcs-auth-data", VcsAuthData)

	m.Run()
}

func findUserByUsername(name string) *User {
	if user, exists := users[name]; exists {
		return user
	}
	return nil
}

func findUserByFingerprint(fingerprint string) *User {
	for _, user := range users {
		for _, fp := range user.Fingerprints {
			if fp == fingerprint {
				return user
			}
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
		if user.HasFingerprint(f[0]) {
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
