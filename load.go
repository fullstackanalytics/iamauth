package iamauth

import (
	"encoding/gob"
	"fmt"
	"log"

	"github.com/gorilla/sessions"
	dot "github.com/joho/godotenv"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/fullstackanalytics/iamauth/users"
)

var (
	// the root domain URL with scheme
	Domain string

	// the callback Path for step2
	CallbackPath string

	// the type (Driver) of IAM to use. zero value ("") if not set. and the project
	IAMType, Project string

	// cookie store with iamauth session
	Store *sessions.CookieStore

	UserDb *users.UserStore

	// [private] the oauth config for connecting to google apps.
	conf *oauth2.Config
)

func Load() {

	// load the configuration file
	var cfg map[string]string
	cfg, err := dot.Read("iamauth.env")
	if err != nil {
		log.Fatal("unable to read iamauth.env")
	}

	// set public vars
	Domain = cfg["domain"]
	CallbackPath = cfg["path.callback"]
	IAMType = cfg["iam.type"]
	Project = cfg["iam.project"]

	// extract secrets
	key := cfg["key"]
	secret := cfg["secret"]

	// create Cookie store register generic map for serialization
	gob.Register(map[string]interface{}{})
	Store = sessions.NewCookieStore([]byte(randomString(32)))

	// set oauth2 configuration
	conf = &oauth2.Config{
		RedirectURL:  fmt.Sprintf("%s/%s", Domain, CallbackPath),
		ClientID:     key,
		ClientSecret: secret,
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.profile",
			"https://www.googleapis.com/auth/userinfo.email",
		},
		Endpoint: google.Endpoint,
	}

	if UsingIAM() {
		log.Printf("using %s IAM driver", IAMType)
		if UserDb, err = users.New(IAMType, Project); err != nil {
			log.Fatalln("unable to initialize IAM User store", err)
		}
		return
	}
	log.Printf("WARNING: not using IAM authentication")
}

func UsingIAM() bool {
	return (IAMType != "")
}
