package iamauth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"golang.org/x/oauth2"
)

const SessionToken = "google-iam-auth"

// creates handler for step 1 of Oauth flow.
func Step1() http.HandlerFunc {
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

// creates handler for step 2 of Oauth flow.
// optionally set roles for IAM based authentication.
func Step2(nextPath string, roles ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ok := authorize(w, r)
		if !ok {
			log.Println("error: unable to authorize")
			return
		}

		if UsingIAM() {
			_, err := UserDb.Reindex()
			if err != nil {
				log.Println("unable to reindex IAM users ", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			email, err := Email(r)
			if err != nil {
				log.Println("unable to fetch email: ", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if _, ok := UserDb.Search(email, roles...); !ok {
				log.Println("unable to search IAM users. email: ", email)
				http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
				return
			}
			session, err := Store.Get(r, SessionToken)
			if err != nil {
				log.Println("error fetching session:", err)
				http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
				return
			}
			session.Values["authenticated"] = "true"
			session.Save(r, w)

		}

		// Redirect to logged in page
		http.Redirect(w, r, nextPath, http.StatusSeeOther)
	}
}

func UserName(r *http.Request) (string, error) {
	return extract("given_name", r)
}

func Email(r *http.Request) (string, error) {
	return extract("email", r)
}

func PicURL(r *http.Request) (string, error) {
	return extract("picture", r)
}

func extract(key string, r *http.Request) (string, error) {
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
	if name, ok = profile[key].(string); !ok {
		return "", fmt.Errorf("failed to retrieve profile")
	}

	return name, nil
}

func authorize(w http.ResponseWriter, r *http.Request) (ok bool) {
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
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	ok = true
	return
}

func randomString(length int) (str string) {
	b := make([]byte, length)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}
