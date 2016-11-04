package iamauth

import (
	"net/http"
)

func Protect(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		session, err := Store.Get(r, SessionToken)
		if err != nil {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		if _, ok := session.Values["profile"]; !ok {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		if _, ok := session.Values["authenticated"]; !ok && UsingIAM() {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		next(w, r)
	}
}
