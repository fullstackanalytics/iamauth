package iamauth

import (
	"encoding/gob"
	"fmt"
	"log"
	"os"

	"github.com/gorilla/sessions"
	//dot "github.com/joho/godotenv"
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
	Project, IAMType string

	// cookie store with iamauth session
	Store *sessions.CookieStore
	// iam auth database in memory
	UserDb *users.UserStore
	// [private] the oauth config for connecting to google apps.
	conf *oauth2.Config
)

func Load() {
	var err error

	// set public vars
	key := os.Getenv("GOOGLE_APP_KEY")
	secret := os.Getenv("GOOGLE_APP_SECRET")
	Domain = os.Getenv("IAMAUTH_DOMAIN")
	CallbackPath = os.Getenv("IAMAUTH_CALLBACK_PATH")
	IAMType = os.Getenv("IAMAUTH_USER_TYPE")
	Project = os.Getenv("IAMAUTH_USER_PROJECT")

	if (key == "") ||
		(secret == "") ||
		(Domain == "") ||
		(CallbackPath == "") ||
		(IAMType == "") ||
		(Project == "") {
		log.Fatal("missing necessary env variables for IAM auth")
	}

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
