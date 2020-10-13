// +build !secrets

package main

var (
	GitHubClientID     string // use env var GITHUB_CLIENT_ID
	GitHubClientSecret string // use env var GITHUB_CLIENT_SECRET

	SessionsSecretKey []byte // use env var SESSIONS_SECRET_KEY
)
