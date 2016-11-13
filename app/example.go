package main

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/fullstackanalytics/iamauth"
)

const homeHtml = `<html><body><a href="/login">Log in with Google</a></body></html>`
const userHtml = `<html><body><p>Hello %s</p><br/><a href="/logout">Logout</a></body></html>`

func main() {

	iamauth.Load()

	r := mux.NewRouter()

	r.HandleFunc("/", home)
	r.HandleFunc("/login", iamauth.Step1())
	r.HandleFunc("/callback", iamauth.Step2("/user"))
	r.HandleFunc("/user", iamauth.Protect(user))
	r.HandleFunc("/logout", iamauth.Disconnect)
	http.Handle("/", r)
	http.ListenAndServe(":8084", nil)
}

func home(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, homeHtml)
}

func user(w http.ResponseWriter, r *http.Request) {
	nm, err := iamauth.UserName(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Fprintf(w, userHtml, nm)
}
