# iamauth

`iamauth` provides Golang tools for implementing the server-side Oauth 2.0 _authorization_ flow for [Google Apps](https://developers.google.com/identity/protocols/OAuth2WebServer). For use with the Go Gorilla web toolkit.
It also includes tools for _authentication_ via IAM role-based access control.

Includes the following:
* environment variable driven handlers for the two-step flow 
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

set the following variables:
```
#!/bin/bash

export GOOGLE_APP_KEY=<YOUR_GOOGLE_OAUTH_KEY>
export GOOGLE_APP_SECRET=<YOUR_GOOGLE_OATH_SECRET>
export IAMAUTH_DOMAIN=http://localhost:8084 # change this to your domain
export IAMAUTH_CALLBACK_PATH=callback # change this to your route. much match path
export IAMAUTH_USER_TYPE=gcp # see drivers
export IAMAUTH_USER_PROJECT=<YOUR_PROJECT> # GCP drivers supported for now
```

see example app in `app/`.
`go run example.go`


## Todo
* README
* Tests
