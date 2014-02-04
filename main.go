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

type Project struct {
	RepoId            int
	RepoName          string
	ProjectId         int
	ProjectName       string
	Status            bool
	ProtectedTags     []string
	ProtectedBranches []string
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

var users = []*User{
	&User{"normal_git", "ABCDEFGHIJKLMN", "arglebargle", true},
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
