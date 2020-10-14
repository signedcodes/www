package main

import (
	"crypto/rand"
	"encoding/hex"
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
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"crawshaw.io/sqlite"
	"crawshaw.io/sqlite/sqlitex"
	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

var flagDev = flag.Bool("dev", false, "run as dev environment")

var renderedDir string

func main() {
	flag.Parse()
	dataDir := "/data/"
	if *flagDev {
		dataDir = "./data/"
	}
	err := os.MkdirAll(dataDir, 0777)
	checkFatal(err)

	sessionsDir := dataDir + "sessions"
	err = os.MkdirAll(sessionsDir, 0777)
	checkFatal(err)

	renderedDir := dataDir + "rendered"
	err = os.MkdirAll(renderedDir, 0777)
	checkFatal(err)

	srv := new(Server)
	srv.Sessions = sessions.NewFilesystemStore(sessionsDir, SessionsSecret())
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
	m.HandleFunc("/unrendered", srv.HandleUnrendered) // TODO: throw behind a strong basic auth?
	m.HandleFunc("/donate/{login:[a-zA-Z0-9\\-]+}/{amount:[0-9]+", srv.HandleDonate)
	m.HandleFunc("/rendered/{login:[a-zA-Z0-9\\-]+}.{ext:(png|pdf)", srv.HandleRendered)
	m.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static/"))))
	m.PathPrefix("/").Methods("GET").HandlerFunc(srv.HandleSigner)
	m.PathPrefix("/").Methods("POST").HandlerFunc(srv.HandleSignerSubmit)
	// TODO: https when not -dev
	addr := ":58347"
	log.Printf("listening on %v", addr)

	CSRF := csrf.Protect(
		CSRFSecret(),
		csrf.Secure(!*flagDev),
		csrf.SameSite(csrf.SameSiteLaxMode),
	)
	handler := CSRF(m)
	err = http.ListenAndServe(addr, handler)
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

// Signer is a transient representation of a code signer from the DB.
type Signer struct {
	login, name, avatar, code, slug string
	donations                       int
	owner                           bool // owner reports whether this signer owns the loaded page
}

func (s *Signer) Amount() int {
	return (s.donations + 1) * 100
}

func (s *Server) lookUpSigner(r *http.Request, login string) (signer Signer, found bool, err error) {
	// TODO: throw an in-memory cache in front of this
	conn := s.DBPool.Get(r.Context())
	if conn == nil {
		err = errors.New("disconnected")
		// remote hung up before we got a conn, no reason to continue
		return
	}
	defer s.DBPool.Put(conn)

	const signerByLoginQuery = `select login, name, avatar, code, slug, donations from signer where login = ? limit 1;`
	step := func(stmt *sqlite.Stmt) error {
		signer.login = stmt.ColumnText(0)
		signer.name = stmt.ColumnText(1)
		signer.avatar = stmt.ColumnText(2)
		signer.code = stmt.ColumnText(3)
		signer.slug = stmt.ColumnText(4)
		signer.donations = stmt.ColumnInt(5)
		found = true
		return nil
	}
	err = sqlitex.Exec(conn, signerByLoginQuery, step, login)
	if err != nil {
		return
	}

	session, err := s.Sessions.Get(r, "user")
	checkLog(err)
	err = nil // don't fail on session errors
	signer.owner = session.Values["login"] == signer.login
	return
}

func (s *Server) HandleSignerSubmit(w http.ResponseWriter, r *http.Request) {
	// Signer just posted the form. Hurray!
	signer, found, err := s.lookUpSigner(r, strings.TrimPrefix(r.URL.Path, "/"))
	if err != nil {
		log.Printf("signer query failed: %v", err)
		http.Error(w, "failed to execute db lookup", http.StatusInternalServerError)
		return
	}
	if !found {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	// Check whether the signed in user owns this page.
	if !signer.owner {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	slug := strings.TrimSpace(r.PostFormValue("fundraise"))
	code := r.PostFormValue("code")

	conn := s.DBPool.Get(r.Context())
	if conn == nil {
		// request cancelled, give up
		return
	}
	defer s.DBPool.Put(conn)

	if signer.code == "" && code != "" {
		const updateCodeQuery = `update signer set code = ? where login = ?;`
		if err := sqlitex.Exec(conn, updateCodeQuery, nil, code, signer.login); err != nil {
			log.Printf("update code query failed: %v", err)
			http.Error(w, "failed to execute code db query", http.StatusInternalServerError)
			return
		}
		signer.code = code
	}
	if signer.slug == "" && slug != "" {
		const updateCodeQuery = `update signer set slug = ? where login = ?;`
		if err := sqlitex.Exec(conn, updateCodeQuery, nil, slug, signer.login); err != nil {
			log.Printf("update slug query failed: %v", err)
			http.Error(w, "failed to execute slug db query", http.StatusInternalServerError)
			return
		}
		signer.slug = slug
	}

	renderSignerPage(w, r, signer)
}

func (s *Server) HandleSigner(w http.ResponseWriter, r *http.Request) {
	// Look up whether that signer exists.
	signer, found, err := s.lookUpSigner(r, strings.TrimPrefix(r.URL.Path, "/"))
	if err != nil {
		log.Printf("signer query failed: %v", err)
		http.Error(w, "failed to execute db lookup", http.StatusInternalServerError)
		return
	}
	if !found {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	renderSignerPage(w, r, signer)
}

func renderSignerPage(w http.ResponseWriter, r *http.Request, signer Signer) {
	if !signer.owner && (signer.slug == "" || signer.code == "") {
		// Not the owner, and the owner hasn't configured their code and slug yet.
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	var fundraise *Fundraise
	if f, ok := FundraiseForSlug[signer.slug]; ok {
		fundraise = &f
	}

	var previewURL, renderedURL string
	previewPath := filepath.Join(renderedDir, signer.login+".png")
	fi, err := os.Stat(previewPath)
	if err == nil && fi.Mode().IsRegular() {
		previewURL = "/rendered/" + signer.login + ".png"
		renderedURL = "/rendered/" + signer.login + ".pdf"
	}

	t := template.Must(template.ParseFiles("template/signer.gohtml"))
	dot := &struct {
		Login       string
		Name        string
		AvatarURL   string
		Fundraise   *Fundraise
		Fundraises  []Fundraise
		Owner       bool
		Code        string
		Amount      int
		PreviewURL  string
		RenderedURL string
		CSRF        template.HTML
	}{
		Login:       signer.login,
		Name:        signer.name,
		AvatarURL:   signer.avatar,
		Owner:       signer.owner,
		Code:        signer.code,
		Amount:      signer.Amount(),
		Fundraise:   fundraise,
		Fundraises:  Fundraises,
		PreviewURL:  previewURL,
		RenderedURL: renderedURL,
		CSRF:        csrf.TemplateField(r),
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

func (s *Server) HandleRendered(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	path := filepath.Join(renderedDir, vars["login"]+"."+vars["ext"])
	http.ServeFile(w, r, path)
}

func (s *Server) HandleDonate(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	signer, found, err := s.lookUpSigner(r, vars["login"])
	if err != nil {
		log.Printf("signer query failed: %v", err)
		http.Error(w, "failed to execute db lookup", http.StatusInternalServerError)
		return
	}
	if !found {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	amount, err := strconv.Atoi(vars["amount"])
	if err != nil {
		log.Printf("bad amount %v: %v", vars["amount"], err)
		http.Error(w, "bad amount", http.StatusBadRequest)
		return
	}

	if signer.Amount() != amount {
		// The amount has changed between when the page rendered and now. Bummer.
		// TODO: render a page explaining what happened.
		// For the moment--speed speed speed--redirect back to the page,
		// which will reflect the new donation amount.
		// Hope the user will try again.
		http.Redirect(w, r, "/"+signer.login, http.StatusFound)
		return
	}

	conn := s.DBPool.Get(r.Context())
	if conn == nil {
		// user went away :(
		return
	}
	defer s.DBPool.Put(conn)

	buf := make([]byte, 16)
	_, err = rand.Reader.Read(buf)
	checkLog(err)
	if err != nil {
		// Very, very unlikely
		http.Error(w, "crypto/rand failed", http.StatusInternalServerError)
		return
	}
	opaque := hex.EncodeToString(buf)
	const createRefcodeQuery = `insert into refcode (opaque, login, amount) values (?, ?, ?);`

	err = sqlitex.Exec(conn, createRefcodeQuery, nil, opaque, signer.login, amount)
	if err != nil {
		log.Printf("failed to insert refcode %v into db: %v", signer.login, err)
		http.Error(w, "failed to insert refcode into db", http.StatusInternalServerError)
		return
	}

	params := make(url.Values)
	params.Set("refcode", opaque)
	params.Set("amount", vars["amount"])

	// Redirect to:
	url := "https://secure.actblue.com/donate/signed-codes-" + signer.slug + "?" + params.Encode()
	http.Redirect(w, r, url, http.StatusFound)
}

func (s *Server) HandleUnrendered(w http.ResponseWriter, r *http.Request) {
	// TODO: look up all signer entries, find ones with code but no renderings, display those
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
