package main

import "os"

func GitHubOauthClientID() string {
	s := GitHubClientID
	if *flagDev {
		s = GitHubDevClientID
	}
	if s == "" {
		return os.Getenv("GITHUB_CLIENT_ID")
	}
	return s
}

func GitHubOauthClientSecret() string {
	s := GitHubClientSecret
	if *flagDev {
		s = GitHubDevClientSecret
	}
	if s == "" {
		return os.Getenv("GITHUB_CLIENT_SECRET")
	}
	return s
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

func PushoverToken() string {
	if PushoverTok == "" {
		return os.Getenv("PUSHOVER_TOKEN")
	}
	return PushoverTok
}

func PushoverUserKey() string {
	if PushoverUser == "" {
		return os.Getenv("PUSHOVER_USER")
	}
	return PushoverUser
}
