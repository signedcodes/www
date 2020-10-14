package main

import "os"

func GitHubOauthClientID() string {
	if GitHubClientID == "" {
		return os.Getenv("GITHUB_CLIENT_ID")
	}
	return GitHubClientID
}

func GitHubOauthClientSecret() string {
	if GitHubClientSecret == "" {
		return os.Getenv("GITHUB_CLIENT_SECRET")
	}
	return GitHubClientSecret
}

func SessionsSecret() []byte {
	if len(SessionsSecretKey) == 0 {
		return []byte(os.Getenv("SESSION_SECRET_KEY"))
	}
	return []byte(SessionsSecretKey)
}

func CSRFSecret() []byte {
	if len(CSRFSecretKey) == 0 {
		return []byte(os.Getenv("CSRF_SECRET_KEY"))
	}
	return []byte(CSRFSecretKey)
}
