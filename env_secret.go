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

func AdminUsername() string {
	if len(AdminUser) == 0 {
		return os.Getenv("ADMIN_USERNAME")
	}
	return AdminUser
}

func AdminPassword() string {
	if len(AdminPass) == 0 {
		return os.Getenv("ADMIN_PASSWORD")
	}
	return AdminPass
}

func VolunteerUsername() string {
	if len(VolunteerUser) == 0 {
		return os.Getenv("VOLUNTEER_USERNAME")
	}
	return VolunteerUser
}

func VolunteerPassword() string {
	if len(VolunteerPass) == 0 {
		return os.Getenv("VOLUNTEER_PASSWORD")
	}
	return VolunteerPass
}
