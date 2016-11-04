# iamauth

`iamauth` provides Golang tools for implementing the server-side Oauth 2.0 _authorization_ flow for [Google Apps](https://developers.google.com/identity/protocols/OAuth2WebServer). For use with the Go Gorilla web toolkit.
It also includes tools for _authentication_ via IAM role-based access control.

Includes the following:
* config-driven handlers for the two-step flow 
* a cookie store for accessing Google user profile information
* a pluggable `UserStore` for IAM role-based authentication 
    * integration with GCP IAM users

## Install 

Install Go lib with example app
```
go get github.com/fullstackanalytics/iamauth...
cd $GOPATH/src/github.com/fullstackanalytics/iamauth && go install
```

## Usage

see example app in `app/`.
fill out the iamauth.env file per the template `iamauth.env` and save it to the `app/` directory
`go run example.go`


## Todo
* README
* Tests
