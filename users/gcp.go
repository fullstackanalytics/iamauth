package users

import (
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"
	"text/template"
	"time"

	"golang.org/x/oauth2/google"
)

func init() {
	Register(NewGCPDriver, "gcp")
	Register(NewGCPDriver, "google")
	Register(NewGCPDriver, "google-http")

}

const (
	Endpoint = "https://cloudresourcemanager.googleapis.com"
	Scope    = "https://www.googleapis.com/auth/cloud-platform"
)

var (
	urlTmpl = template.Must(template.New("").Parse("{{.Endpoint}}/v1/projects/{{.Project}}:getIamPolicy"))
)

// the response body for Google cloud resource manager
type policy struct {
	Version  int `json:"version"`
	Bindings []binding
}

type binding struct {
	Role    string   `json:"role"`
	Members []member `json:"members"`
}

type member string

// Driver for GCP IAM HTTP api via cloudresourcemanager
// implementations of User Store for Google Cloud Platform
type GCPDriver struct {
	client *http.Client
	proj   string
}

// requires Project Authorization
func NewGCPDriver(proj string) (s Driver, err error) {

	client, err := google.DefaultClient(context.Background(), Scope)
	if err != nil {
		return
	}

	s = &GCPDriver{
		client: client,
		proj:   proj,
	}
	return
}

func (d *GCPDriver) GetIamUsers() (users []*UserRecord, err error) {
	now := time.Now()
	// query endpoint
	body, err := d.getPolicy()
	if err != nil {
		return
	}

	var p policy
	// unmarshal JSON response.
	if e := json.Unmarshal(body, &p); err != nil {
		err = e
		return
	}

	for _, binding := range p.Bindings {
		for _, member := range binding.Members {
			m := string(member)
			if strings.HasPrefix(m, "user:") {
				u := new(UserRecord)
				u.Role = binding.Role
				u.Email = strings.TrimPrefix(m, "user:")
				u.LastUpdated = now
				users = append(users, u)
			}
		}

	}

	return
}

func (d *GCPDriver) Project() string {
	return d.proj
}

func (d *GCPDriver) getPolicy() ([]byte, error) {
	var url bytes.Buffer
	if err := urlTmpl.Execute(&url, map[string]string{
		"Endpoint": Endpoint,
		"Project":  d.proj,
	}); err != nil {
		return nil, err
	}

	resp, err := d.client.Post(url.String(), "", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}
