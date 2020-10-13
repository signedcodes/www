package main

import "os"

func GitHubOauthClientID() string {
	if *flagDev {
		return os.Getenv("GITHUB_CLIENT_ID")
	}
	return GitHubClientID
}

func GitHubOauthClientSecret() string {
	if *flagDev {
		return os.Getenv("GITHUB_CLIENT_SECRET")
	}
	return GitHubClientSecret
}

func SessionsSecret() []byte {
	if *flagDev {
		return os.Getenv("SESSION_SECRET_KEY")
	}
	return []byte(SessionsSecretKey)
}
