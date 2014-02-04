// Dumb little http server that mocks the REST api provided by drupal.org's
// git services.
package main

import (
	"encoding/json"
	"flag"
	"github.com/codegangsta/martini"
	"net/http"
	"strconv"
)

const (
	DRUPALORG_GIT_AUTH_NO_ROLE = 1 << iota
	DRUPALORG_GIT_AUTH_ACCOUNT_SUSPENDED
	DRUPALORG_GIT_AUTH_NOT_CONSENTED
	DRUPALORG_GIT_AUTH_ACCOUNT_BLOCKED
)

// ugh that this is a bitfield, there is no reason for it to be.
const (
	DRUPALORG_GIT_GATECTL_CORE = 1 << iota
	DRUPALORG_GIT_GATECTL_PROJECTS
	DRUPALORG_GIT_GATECTL_SANDBOXES
)

type User struct {
	Username     string
	Uid          int
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
	Status            int
	Type              int
	ProtectedTags     []string
	ProtectedBranches []string
	Users             []*User
}

func (p *Project) MarshalJSON() ([]byte, error) {
	mp := project{
		Project:         p.ProjectName,
		Project_nid:     strconv.Itoa(p.ProjectId),
		Repository_name: p.RepoName,
		Repo_id:         strconv.Itoa(p.RepoId),
		Repo_group:      p.Type,
		Status:          p.Status,
		Protected_labels: map[string][]string{
			"branches": p.ProtectedBranches,
			"tags":     p.ProtectedTags,
		},
		Users: make(map[string]*userdata),
	}

	for _, user := range p.Users {
		u := defaultUserdata()
		u.Pass = user.Password
		u.Global = user.Blocked
		u.Uid = strconv.Itoa(user.Uid)
		u.Name = user.Username
		u.Ssh_keys = user.Fingerprints
		mp.Users[user.Username] = u
	}

	return json.Marshal(mp)
}

type userdata struct {
	Per_label     []string          `json:"per-label"`
	Branch_delete string            `json:"branch_delete"` // stupid php, converting ints to strings from db
	Pass          string            `json:"pass"`
	Global        int               `json:"global"`
	Uid           string            `json:"uid"`    // ibid. string, but actually int
	Access        string            `json:"access"` // string, but actually int
	Name          string            `json:"name"`
	Tag_delete    string            `json:"tag_delete"`    // string, but actually int
	Tag_create    string            `json:"tag_create"`    // string, but actually int
	Branch_create string            `json:"branch_create"` // string, but actually int
	Ssh_keys      map[string]string `json:"ssh_keys"`
	Tag_update    string            `json:"tag_update"`    // string, but actually int
	Branch_update string            `json:"branch_update"` // string, but actually int
	Repo_id       string            `json:"repo_id"`       // string, but actually int
}

func defaultUserdata() *userdata {
	u := &userdata{
		Per_label:     []string{},
		Branch_delete: "0",
		Global:        0, // TODO check what this is in reference to
		Access:        "2",
		Tag_delete:    "0",
		Tag_create:    "0",
		Branch_create: "0",
		Tag_update:    "0",
		Branch_update: "0",
	}
	return u
}

type project struct {
	Project          string               `json:"project"`
	Project_nid      string               `json:"project_nid"` // string, but actually int
	Repository_name  string               `json:"repository_name"`
	Repo_id          string               `json:"repo_id"` // string, but actually int
	Repo_group       int                  `json:"repo_group"`
	Status           int                  `json:"status"`
	Protected_labels map[string][]string  `json:"protected_labels"`
	Users            map[string]*userdata `json:"users"`
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
		RepoName:          "repo1",
		ProjectId:         1,
		ProjectName:       "Project 1",
		Status:            1,
		Type:              DRUPALORG_GIT_GATECTL_PROJECTS,
		ProtectedTags:     []string{"7.x-1.0"},
		ProtectedBranches: []string{"7.x-1.x"},
		Users:             []*User{users["normal"], users["missing_role"]},
	},
}

var pushCtl string

func main() {
	BuildServer().Run()
}

func BuildServer() *martini.Martini {
	m := martini.New()
	m.Use(martini.Recovery())
	m.Use(martini.Logger())

	flag.StringVar(&pushCtl, "pushctl", "0", "Sets the pushctl state for the REST server.")
	flag.Parse()

	r := martini.NewRouter()
	r.Get("/drupalorg/drupalorg-ssh-user-key", CheckFingerprintForUser)
	r.Get("/drupalorg/drupalorg-sshkey-check", VerifySshKey)
	r.Get("/drupalorg/drupalorg-vcs-auth-check-user-pass", CheckPasswordForUser)
	r.Get("/drupalorg/drupalorg-vcs-auth-fetch-user-hash", FetchUserPassHash)
	r.Get("/drupalorg/pushctl-state", func() string { return pushCtl })
	r.Get("/drupalorg/vcs-auth-data", VcsAuthData)

	m.Action(r.Handle)

	return m
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

func findProjectByRepoName(name string) *Project {
	for _, project := range projects {
		if project.RepoName == name {
			return project
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

func VcsAuthData(req *http.Request) []byte {
	q := req.URL.Query()

	pi, pie := q["project_uri"]
	if !pie {
		return []byte{}
	}

	if project := findProjectByRepoName(pi[0]); project != nil {
		json, err := json.Marshal(project)
		if err != nil {
			panic("error encoding project json")
		}
		return json
	}

	return []byte{}
}
