package iamauth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/gorilla/sessions"
	dot "github.com/joho/godotenv"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var (
	Domain, CallbackPath string

	Store *sessions.CookieStore
	conf  *oauth2.Config
)

const SessionToken = "google-iam-auth"

func Load() {
	var cfg map[string]string
	cfg, err := dot.Read("iamauth.env")
	if err != nil {
		log.Fatal("unable to read iamauth.env")
	}

	key := cfg["key"]
	secret := cfg["secret"]
	Domain = cfg["domain"]
	CallbackPath = cfg["path.callback"]

	gob.Register(map[string]interface{}{})

	Store = sessions.NewCookieStore([]byte(randomString(32)))
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
}

func Login() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		// create new state with each login and store in session.
		state := randomString(64)
		session, err := Store.Get(r, SessionToken)
		if err != nil {
			// Ignore the initial session fetch error, as Get() always returns a session, even if empty.
			log.Println("error fetching session:", err)
		}
		session.Values["state"] = state
		session.Save(r, w)
		url := conf.AuthCodeURL(state)

		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	}
}

func Callback(nextPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state := r.FormValue("state")

		session, err := Store.Get(r, SessionToken)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if state != session.Values["state"] {
			log.Printf("invalid oauth state, expected '%s', got '%s'\n", session.Values["state"], state)
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}

		code := r.FormValue("code")
		token, err := conf.Exchange(oauth2.NoContext, code)
		if err != nil {
			fmt.Printf("Code exchange failed with '%s'\n", err)
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}

		// Getting now the userInfo
		client := conf.Client(oauth2.NoContext, token)
		resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		log.Println("able to get data")

		raw, err := ioutil.ReadAll(resp.Body)
		defer resp.Body.Close()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		var profile map[string]interface{}
		if err = json.Unmarshal(raw, &profile); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		session.Values["id_token"] = token.Extra("id_token")
		session.Values["access_token"] = token.AccessToken
		session.Values["profile"] = profile
		log.Println("the profile is", profile)
		err = session.Save(r, w)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Redirect to logged in page
		http.Redirect(w, r, nextPath, http.StatusSeeOther)
	}
}

func UserName(r *http.Request) (string, error) {
	session, err := Store.Get(r, SessionToken)
	if err != nil {
		return "", err
	}

	var profile map[string]interface{}
	var ok bool
	if profile, ok = session.Values["profile"].(map[string]interface{}); !ok {
		return "", fmt.Errorf("failed to retrieve profile")
	}

	var name string
	if name, ok = profile["given_name"].(string); !ok {
		return "", fmt.Errorf("failed to retrieve profile")
	}

	return name, nil
}

func randomString(length int) (str string) {
	b := make([]byte, length)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}
