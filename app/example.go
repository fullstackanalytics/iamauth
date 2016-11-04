package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/fullstackanalytics/iamauth"
)

const homeHtml = `<html><body><a href="/login">Log in with Google</a></body></html>`

func main() {

	store, err := iamauth.New("google", "exalted-tempo-129019")
	if err != nil {
		log.Fatalln("unable to connect.", err)
	}

	if _, err := store.Reindex(); err != nil {
		log.Fatalln("error retrieve IAM policy.", err)
	}

	matt, ok := store.Search("matt@fullstackanalytics.net")
	log.Println("search", matt, ok)

	iamauth.Load()

	r := mux.NewRouter()

	r.HandleFunc("/", home)
	r.HandleFunc("/login", iamauth.Login())
	r.HandleFunc("/callback", iamauth.Callback("/user"))
	r.HandleFunc("/user", iamauth.Protect(user))
	//r.PathPrefix("/public/").Handler(http.StripPrefix("/public/", http.FileServer(http.Dir("public/"))))
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
	fmt.Fprintf(w, "hello, %s", nm)
}
