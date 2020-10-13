// +build !secrets

package main

const (
	GitHubClientID     = "use env var GITHUB_CLIENT_ID"
	GitHubClientSecret = "use env var GITHUB_CLIENT_SECRET"

	SessionsSecretKey = "use env var SESSIONS_SECRET_KEY"
)
