package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"crawshaw.io/sqlite"
	"crawshaw.io/sqlite/sqlitex"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

var flagDev = flag.Bool("dev", false, "run as dev environment")

func main() {
	flag.Parse()
	dataDir := "/data/"
	if *flagDev {
		dataDir = "./data/"
	}
	err := os.MkdirAll(dataDir, 0777)
	checkFatal(err)

	srv := new(Server)
	srv.Sessions = sessions.NewFilesystemStore(dataDir+"sessions", SessionsSecret())
	srv.DBPool, err = sqlitex.Open(dataDir+"db.sqlite3", 0, 32)
	checkFatal(err)
	err = srv.createTables()
	checkFatal(err)

	// Pages:
	//   /: home page
	//   /josharian: auction page for person with GitHub handle josharian
	m := mux.NewRouter()
	m.HandleFunc("/", srv.HandleHome)
	m.HandleFunc("/volunteer", srv.HandleVolunteer)
	m.HandleFunc("/signup", srv.HandleSignUp)
	m.HandleFunc("/github-callback", srv.HandleGitHubCallback)
	m.PathPrefix("/").HandlerFunc(srv.HandleSigner)
	// TODO: https when not -dev
	addr := ":58347"
	log.Printf("listening on %v", addr)
	err = http.ListenAndServe(addr, m)
	checkFatal(err)
}

type Server struct {
	Sessions sessions.Store
	DBPool   *sqlitex.Pool
}

func (s *Server) HandleHome(w http.ResponseWriter, r *http.Request) {
	t := template.Must(template.ParseFiles("template/home.gohtml"))
	err := t.Execute(w, nil)
	checkLog(err)
}

func (s *Server) HandleSigner(w http.ResponseWriter, r *http.Request) {
	// Look whether that signer exists.
	// TODO: throw an in-memory cache in front of this
	const signerByLoginQuery = `select login, name, avatar from signer where login = ? limit 1;`
	var login, name, avatar string
	var found bool
	step := func(stmt *sqlite.Stmt) error {
		login = stmt.ColumnText(0)
		name = stmt.ColumnText(1)
		avatar = stmt.ColumnText(2)
		found = true
		return nil
	}
	conn := s.DBPool.Get(r.Context())
	if conn == nil {
		// remote hung up before we got a conn, no reason to continue
		return
	}
	defer s.DBPool.Put(conn)
	err := sqlitex.Exec(conn, signerByLoginQuery, step, strings.TrimPrefix(r.URL.Path, "/"))
	if err != nil {
		log.Printf("signer query failed: %v", err)
		http.Error(w, "failed to execute db lookup", http.StatusInternalServerError)
		return
	}
	if !found {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	// TODO: show as 404 if signer hasn't selected code, etc.

	// TODO: render page differently if that's the user that is signed in
	// session, err := s.Sessions.Get(r, "user")

	t := template.Must(template.ParseFiles("template/signer.gohtml"))
	dot := &struct {
		Login     string
		Name      string
		AvatarURL string
	}{
		Login:     login,
		Name:      name,
		AvatarURL: avatar,
	}
	err = t.Execute(w, dot)
	checkLog(err)
}

func (s *Server) HandleGitHubCallback(w http.ResponseWriter, r *http.Request) {
	// Extract code from query params.
	code := r.URL.Query().Get("code")

	// Retrieve access token.
	form := make(url.Values)
	form.Set("client_id", GitHubOauthClientID())
	form.Set("client_secret", GitHubOauthClientSecret())
	form.Set("code", code)
	form.Set("accept", "json")

	req, err := http.NewRequest("POST", "https://github.com/login/oauth/access_token", strings.NewReader(form.Encode()))
	checkLog(err)
	if err != nil {
		http.Error(w, "failed to construct GitHub request", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	checkLog(err)
	if err != nil {
		http.Error(w, "failed to communicate with GitHub", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	checkLog(err)
	if resp.StatusCode != 200 {
		log.Printf("bad GitHub access_token status code %d: %q", resp.StatusCode, body)
		http.Error(w, "failed to authenticate with GitHub", http.StatusInternalServerError)
		return
	}
	if err != nil {
		http.Error(w, "failed to read response from GitHub to retrieve access token", http.StatusInternalServerError)
		return
	}

	var accessTokenResponse struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	err = json.Unmarshal(body, &accessTokenResponse)
	checkLog(err)
	if err != nil {
		http.Error(w, "failed to retrieve access token from GitHub", http.StatusInternalServerError)
		return
	}
	if accessTokenResponse.TokenType != "bearer" {
		log.Printf("GitHub access token type %q", accessTokenResponse.TokenType)
		http.Error(w, "unexpected token type from GitHub", http.StatusInternalServerError)
		return
	}

	// Use access token to request user info (handle in particular)
	req, err = http.NewRequest("GET", "https://api.github.com/user", nil)
	checkLog(err)
	if err != nil {
		http.Error(w, "failed to construct GitHub user info request", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessTokenResponse.AccessToken)
	req.Header.Set("Accept", "application/json")

	resp, err = http.DefaultClient.Do(req)
	checkLog(err)
	if err != nil {
		http.Error(w, "failed to communicate with GitHub to retrieve user data", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	body, err = ioutil.ReadAll(resp.Body)
	checkLog(err)
	if resp.StatusCode != 200 {
		log.Printf("bad GitHub user status code %d: %q", resp.StatusCode, body)
		http.Error(w, "failed to get user info from GitHub", http.StatusInternalServerError)
		return
	}
	if err != nil {
		http.Error(w, "failed to read response from GitHub to retrieve user info", http.StatusInternalServerError)
		return
	}

	// Extract user's handle
	var userInfoResponse struct {
		Login     string `json:"login"`
		AvatarURL string `json:"avatar_url"`
		HTMLURL   string `json:"html_url"`
		Type      string `json:"type"`
		Name      string `json:"name"`
		CreatedAt string `json:"created_at"`
	}
	err = json.Unmarshal(body, &userInfoResponse)
	checkLog(err)
	if err != nil {
		http.Error(w, "failed to retrieve user info from GitHub", http.StatusInternalServerError)
		return
	}
	if userInfoResponse.Login == "" {
		log.Printf("no GitHub login: %#v", userInfoResponse)
		http.Error(w, "failed to retrieve user login from GitHub", http.StatusInternalServerError)
		return
	}
	if userInfoResponse.Type != "User" {
		// TODO: prettier error message
		fmt.Fprintln(w, "sorry, only GitHub users can participate")
		return
	}
	created, err := time.Parse(time.RFC3339, userInfoResponse.CreatedAt)
	checkLog(err)
	if err != nil {
		http.Error(w, "failed to parse user created_at from GitHub", http.StatusInternalServerError)
		return
	}
	if created.After(time.Date(2020, 10, 1, 0, 0, 0, 0, time.UTC)) {
		// TODO: prettier error message
		fmt.Fprintln(w, "sorry, only GitHub users created before Oct 1, 2020 can participate")
		return
	}

	// Make a DB entry
	conn := s.DBPool.Get(r.Context())
	if conn == nil {
		// remote hung up before we got a conn, oh well
		return
	}
	defer s.DBPool.Put(conn)

	const createSignerQuery = `insert into signer (login, name, avatar) values (?, ?, ?);`

	err = sqlitex.Exec(conn, createSignerQuery, nil, userInfoResponse.Login, userInfoResponse.Name, userInfoResponse.AvatarURL)
	var sqlerr sqlite.Error
	if errors.As(err, &sqlerr) && sqlerr.Code == sqlite.SQLITE_CONSTRAINT_UNIQUE {
		// Already exists; ignore.
	} else if err != nil {
		log.Printf("failed to insert signer %v into db: %v", userInfoResponse.Login, err)
		http.Error(w, "failed to insert signer into db", http.StatusInternalServerError)
		return
	}

	// Put login info into session so user can edit their own page
	session, err := s.Sessions.New(r, "user")
	session.Values["login"] = userInfoResponse.Login
	checkLog(err)
	err = session.Save(r, w)
	checkLog(err)

	http.Redirect(w, r, "/"+userInfoResponse.Login, http.StatusFound)
}

func (s *Server) HandleSignUp(w http.ResponseWriter, r *http.Request) {
	t := template.Must(template.ParseFiles("template/signup.gohtml"))
	dot := &struct {
		ClientID string
	}{
		ClientID: GitHubOauthClientID(),
	}
	err := t.Execute(w, dot)
	checkLog(err)
}

func (s *Server) HandleVolunteer(w http.ResponseWriter, r *http.Request) {
	t := template.Must(template.ParseFiles("template/volunteer.gohtml"))
	err := t.Execute(w, nil)
	checkLog(err)
}

func checkFatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func checkLog(err error) {
	if err != nil {
		// TODO: print a little stack trace
		log.Print(err)
	}
}
