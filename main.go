package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"crawshaw.io/sqlite"
	"crawshaw.io/sqlite/sqlitex"
	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/acme/autocert"
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

	renderedDir = dataDir + "rendered"
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
	m.HandleFunc("/help", srv.HandleHelp)
	m.HandleFunc("/signup", srv.HandleSignUp)
	m.HandleFunc("/github-callback", srv.HandleGitHubCallback)
	m.HandleFunc("/donate/{login:[a-zA-Z0-9\\-]+}/{id:[a-z0-9]+}", srv.HandleDonate)
	m.HandleFunc("/rendered/{id:[a-z0-9]+}.{ext:p..}", srv.HandleRendered)
	m.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static/"))))

	admin := m.PathPrefix("/admin/").Subrouter()
	admin.HandleFunc("/csv", srv.HandleAdminCSV)
	admin.Use(srv.authAdmin)

	volunteer := m.PathPrefix("/volunteer/").Subrouter()
	volunteer.HandleFunc("/unrendered", srv.HandleVolunteerUnrendered)
	volunteer.Use(srv.authVolunteer)

	m.PathPrefix("/").Methods("GET").HandlerFunc(srv.HandleSigner)
	m.PathPrefix("/").Methods("POST").HandlerFunc(srv.HandleSignerSubmit)

	CSRF := csrf.Protect(
		CSRFSecret(),
		csrf.Secure(!*flagDev),
		csrf.SameSite(csrf.SameSiteLaxMode),
	)
	handler := CSRF(m)

	if *flagDev {
		addr := ":58347"
		log.Printf("listening on %v", addr)
		err = http.ListenAndServe(addr, handler)
		checkFatal(err)
		return
	}

	// prod
	certsDir := dataDir + "certs"
	err = os.MkdirAll(certsDir, 0777)
	checkFatal(err)

	// Set up SSL cert using Let's Encrypt.
	certManager := &autocert.Manager{
		Prompt: autocert.AcceptTOS,
		HostPolicy: func(ctx context.Context, host string) error {
			if host == "signed.codes" {
				return nil // OK
			}
			return fmt.Errorf("autocert: got unrecognized host %q", host)
		},
		Cache: autocert.DirCache(certsDir),
		Email: "hello@signed.codes",
	}

	c := make(chan error, 2)

	// Create and start server.
	server := &http.Server{
		Handler:           handler,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       5 * time.Minute,
	}
	server.Addr = ":443"
	server.TLSConfig = &tls.Config{GetCertificate: certManager.GetCertificate}
	go func() {
		log.Printf("listening on %v", server.Addr)
		c <- server.ListenAndServeTLS("", "")
	}()

	redirect := func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://signed.codes"+r.URL.String(), http.StatusFound)
	}
	insecureServer := &http.Server{
		// Give autocert handler first crack at all requests
		// in order to handle Let's Encrypt auth callbacks.
		Handler:           certManager.HTTPHandler(http.HandlerFunc(redirect)),
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       5 * time.Minute,
		Addr:              ":80",
	}
	go func() {
		log.Printf("listening on %v", insecureServer.Addr)
		c <- insecureServer.ListenAndServe()
	}()

	for err = range c {
		checkFatal(err)
	}
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
	Login    string
	Name     string
	Email    string
	Avatar   string
	Link     string
	Owner    bool // owner reports whether this signer owns the loaded page
	Snippets []*Snippet
}

type Snippet struct {
	ID       string
	Code     string
	Comment  string
	Slug     string
	Quantity int
	Amount   int

	// filled in by populate
	PreviewURL  string
	RenderedURL string
	Available   int
}

func (s *Snippet) Fundraise() Fundraise {
	return FundraiseForSlug[s.Slug]
}

// populate populates other snippet fields
func (s *Snippet) populate(conn *sqlite.Conn) error {
	used := 0
	const refcodeBySnippetQuery = `select raised, created from refcode where snippet = ?;`
	step := func(stmt *sqlite.Stmt) error {
		raised := stmt.ColumnInt(0)
		if raised >= s.Amount {
			// Donation completed.
			used++
			return nil
		}
		created := stmt.ColumnText(1)
		then, err := time.Parse("2006-01-02 15:04:05", created)
		checkLog(err)
		if err != nil {
			return err
		}
		if time.Since(then) < 24*time.Hour {
			// Assume that I upload CSVs once every 24 hours.
			// So even though this refcode hasn't raised enough,
			// it might just be because I'm slow.
			used++
			return nil
		}
		// Been 24+ hours and refcode hasn't raised.
		// Assume it is unused.
		return nil
	}
	err := sqlitex.Exec(conn, refcodeBySnippetQuery, step, s.ID)
	if err != nil {
		return err
	}

	s.Available = s.Quantity - used

	previewPath := filepath.Join(renderedDir, s.ID+".png")
	fi, err := os.Stat(previewPath)
	if err == nil && fi.Mode().IsRegular() {
		s.PreviewURL = "/rendered/" + s.ID + ".png"
		s.RenderedURL = "/rendered/" + s.ID + ".pdf"
	}

	return nil
}

func (s *Server) lookUpSigner(r *http.Request, login string) (*Signer, bool, error) {
	// TODO: throw an in-memory cache in front of this
	conn := s.DBPool.Get(r.Context())
	if conn == nil {
		// remote hung up before we got a conn, no reason to continue
		return nil, false, errors.New("disconnected")
	}
	defer s.DBPool.Put(conn)

	signer := new(Signer)
	var found bool
	const signerByLoginQuery = `select login, name, email, avatar, link from signer where login = ? limit 1;`
	step := func(stmt *sqlite.Stmt) error {
		signer.Login = stmt.ColumnText(0)
		signer.Name = stmt.ColumnText(1)
		signer.Email = stmt.ColumnText(2)
		signer.Avatar = stmt.ColumnText(3)
		signer.Link = stmt.ColumnText(4)
		found = true
		return nil
	}
	err := sqlitex.Exec(conn, signerByLoginQuery, step, login)
	if err != nil {
		return nil, false, err
	}
	if !found {
		return nil, false, nil
	}

	const snippetsBySignerQuery = `select id, code, comment, slug, quantity, amount from snippet where signer = ?;`
	step = func(stmt *sqlite.Stmt) error {
		snippet := &Snippet{
			ID:       stmt.ColumnText(0),
			Code:     stmt.ColumnText(1),
			Comment:  stmt.ColumnText(2),
			Slug:     stmt.ColumnText(3),
			Quantity: stmt.ColumnInt(4),
			Amount:   stmt.ColumnInt(5),
		}
		err := snippet.populate(conn)
		if err != nil {
			return err
		}
		signer.Snippets = append(signer.Snippets, snippet)
		return nil
	}
	err = sqlitex.Exec(conn, snippetsBySignerQuery, step, signer.Login)
	if err != nil {
		return nil, false, err
	}

	session, err := s.Sessions.Get(r, "user")
	checkLog(err)
	signer.Owner = session.Values["login"] == signer.Login
	return signer, true, nil
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
	if !signer.Owner {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	amount, ok := toAmount(r.PostFormValue("amount"))
	if !ok {
		badRequest(w, nil, "could not parse amount %q", r.PostFormValue("amount"))
		return
	}
	if amount < 50 || amount > 2500 {
		badRequest(w, nil, "bad amount %q", r.PostFormValue("amount"))
		return
	}

	quantity, ok := toAmount(r.PostFormValue("quantity"))
	if !ok {
		badRequest(w, nil, "could not parse quantity %q", r.PostFormValue("quantity"))
		return
	}
	if quantity < 1 || quantity > 100 {
		badRequest(w, nil, "bad quantity %q", r.PostFormValue("quantity"))
		return
	}

	slug := r.PostFormValue("fundraise")
	if _, ok := FundraiseForSlug[slug]; !ok {
		badRequest(w, nil, "unrecognized donation recipient %v", slug)
		return
	}

	code := r.PostFormValue("code")
	if strings.TrimSpace(code) == "" {
		badRequest(w, nil, "empty code")
		return
	}

	comment := r.PostFormValue("comment")

	conn := s.DBPool.Get(r.Context())
	if conn == nil {
		// request cancelled, give up
		return
	}
	defer s.DBPool.Put(conn)

	id := generateOpaqueID()
	const insertSnippetQuery = `insert into snippet (id, signer, code, comment, slug, quantity, amount) values (?, ?, ?, ?, ?, ?, ?);`
	err = sqlitex.Exec(conn, insertSnippetQuery, nil, id, signer.Login, code, comment, slug, quantity, amount)
	if err != nil {
		log.Printf("insert snippet query failed: %v", err)
		http.Error(w, "failed to execute slug db query", http.StatusInternalServerError)
		return
	}

	snippet := &Snippet{
		ID:       id,
		Code:     code,
		Comment:  comment,
		Slug:     slug,
		Quantity: quantity,
		Amount:   amount,
	}
	err = snippet.populate(conn)
	if err != nil {
		internalServerError(w, err, "populate on insert snippet failed")
		return
	}
	signer.Snippets = append(signer.Snippets, snippet)

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

func renderSignerPage(w http.ResponseWriter, r *http.Request, signer *Signer) {
	if !signer.Owner && len(signer.Snippets) == 0 {
		// Not the owner, and the owner hasn't configured any snippets (yet?)
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	t := template.Must(template.ParseFiles("template/signer.gohtml"))
	dot := &struct {
		Signer          *Signer
		Fundraises      []Fundraise
		CSRF            template.HTML
		DefaultQuantity int
		Quantities      []int
		DefaultAmount   int
		Amounts         []int
		ClientID        string
	}{
		Signer:          signer,
		Fundraises:      Fundraises,
		CSRF:            csrf.TemplateField(r),
		DefaultQuantity: 10,
		Quantities:      []int{1, 5, 10, 100},
		DefaultAmount:   250,
		Amounts:         []int{50, 100, 250, 500, 1000, 2500},
		ClientID:        GitHubOauthClientID(),
	}
	err := t.Execute(w, dot)
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
		Email     string `json:"email"`
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

	const createSignerQuery = `insert into signer (login, name, email, avatar, link) values (?, ?, ?, ?, ?);`
	err = sqlitex.Exec(conn, createSignerQuery, nil,
		userInfoResponse.Login, userInfoResponse.Name, userInfoResponse.Email,
		userInfoResponse.AvatarURL, userInfoResponse.HTMLURL)
	var sqlerr sqlite.Error
	if errors.As(err, &sqlerr) && sqlerr.Code == sqlite.SQLITE_CONSTRAINT_PRIMARYKEY {
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

func (s *Server) HandleHelp(w http.ResponseWriter, r *http.Request) {
	t := template.Must(template.ParseFiles("template/help.gohtml"))
	err := t.Execute(w, nil)
	checkLog(err)
}

func (s *Server) HandleRendered(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	path := filepath.Join(renderedDir, vars["id"]+"."+vars["ext"])
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
		http.Error(w, "signer not found", http.StatusNotFound)
		return
	}

	// Find the snippet.
	var snippet *Snippet
	for _, s := range signer.Snippets {
		if s.ID == vars["id"] {
			snippet = s
			break
		}
	}

	if snippet == nil {
		http.Error(w, "snippet not found", http.StatusNotFound)
		return
	}

	if snippet.Available <= 0 {
		// There are none available. That changed between when the page rendered and now. Bummer.
		// TODO: render a page explaining what happened.
		// For the moment--speed speed speed--redirect back to the page,
		// which will reflect the new donation amount.
		// Hope the user will try again.
		http.Redirect(w, r, "/"+signer.Login, http.StatusFound)
		return
	}

	conn := s.DBPool.Get(r.Context())
	if conn == nil {
		// user went away :(
		return
	}
	defer s.DBPool.Put(conn)

	const createRefcodeQuery = `insert into refcode (id, login, snippet) values (?, ?, ?);`
	opaque := generateOpaqueID()
	err = sqlitex.Exec(conn, createRefcodeQuery, nil, opaque, signer.Login, snippet.ID)
	if err != nil {
		internalServerError(w, err, "failed to insert refcode for %v into db", signer.Login)
		return
	}

	params := make(url.Values)
	params.Set("refcode", opaque)
	params.Set("amount", strconv.Itoa(snippet.Amount))

	// Redirect to:
	url := "https://secure.actblue.com/donate/signed-codes-" + snippet.Slug + "?" + params.Encode()
	http.Redirect(w, r, url, http.StatusFound)
}

func (s *Server) HandleVolunteerUnrendered(w http.ResponseWriter, r *http.Request) {
	conn := s.DBPool.Get(r.Context())
	if conn == nil {
		// remote hung up?!
		return
	}
	defer s.DBPool.Put(conn)

	var unrendered []*Snippet
	const allSnippetsQuery = `select id, code, quantity from snippet;`
	step := func(stmt *sqlite.Stmt) error {
		snippet := &Snippet{
			ID:       stmt.ColumnText(0),
			Code:     stmt.ColumnText(1),
			Quantity: stmt.ColumnInt(2),
		}
		err := snippet.populate(conn)
		if err != nil {
			return err
		}
		if snippet.RenderedURL == "" {
			unrendered = append(unrendered, snippet)
		}
		return nil
	}
	err := sqlitex.Exec(conn, allSnippetsQuery, step)
	if err != nil {
		internalServerError(w, err, "all sinppet lookup failed")
		return
	}

	t := template.Must(template.ParseFiles("template/unrendered.gohtml"))
	dot := &struct {
		Unrendered []*Snippet
		CSRF       template.HTML
	}{
		Unrendered: unrendered,
		CSRF:       csrf.TemplateField(r),
	}
	err = t.Execute(w, dot)
	checkLog(err)
}

func (s *Server) HandleAdminCSV(w http.ResponseWriter, r *http.Request) {
	var msg string

	if r.Method == "POST" {
		r.ParseMultipartForm(10 << 20)
		ff, _, err := r.FormFile("file")
		if err != nil {
			badRequest(w, err, "upload failed: %v", err)
			return
		}

		type entry struct {
			amount int
			donor  string
		}
		entries := make(map[string]*entry)

		reader := csv.NewReader(ff)
		for first := true; ; first = false {
			record, err := reader.Read()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				badRequest(w, err, "csv parse failed: %v", err)
				return
			}
			if first {
				if !reflect.DeepEqual(record, csvheader) {
					log.Printf("csv header\n got=%q\nwant=%q", record, csvheader)
					badRequest(w, err, "csv bad header")
					return
				}
				continue
			}
			refcode := record[9]
			amount, ok := toAmount(record[2])
			if !ok {
				badRequest(w, nil, "csv amount=%q", record[2])
				return
			}
			donor := record[20]
			e := entries[refcode]
			if e == nil {
				e = new(entry)
				e.donor = donor
				e.amount = amount
				entries[refcode] = e
			} else {
				if e.donor != donor {
					badRequest(w, nil, "donor mismatch refcode=%q, %q != %q", refcode, e.donor, donor)
					return
				}
				e.amount += amount
			}
		}

		conn := s.DBPool.Get(r.Context())
		if conn == nil {
			// remote hung up?!
			return
		}
		defer s.DBPool.Put(conn)

		for refcode, e := range entries {
			const updateRefcodeQuery = `update refcode set raised = ?, donor = ? where id = ?;`
			err := sqlitex.Exec(conn, updateRefcodeQuery, nil, e.amount, e.donor, refcode)
			if err != nil {
				internalServerError(w, err, "update refcode failed on %v", refcode)
				return
			}
		}

		msg = fmt.Sprintf("updated %d entries", len(entries))
	}

	t := template.Must(template.ParseFiles("template/admin_csv.gohtml"))
	dot := &struct {
		Msg  string
		CSRF template.HTML
	}{
		Msg:  msg,
		CSRF: csrf.TemplateField(r),
	}
	err := t.Execute(w, dot)
	checkLog(err)
}

func (s *Server) authAdmin(next http.Handler) http.Handler {
	return s.basicAuth(next, AdminUsername(), AdminPassword())
}

func (s *Server) authVolunteer(next http.Handler) http.Handler {
	return s.basicAuth(next, VolunteerUsername(), VolunteerPassword())
}

func (s *Server) basicAuth(next http.Handler, wantUser, wantPass string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok {
			unauthorized(w, nil, "auth required")
			return
		}
		// TODO: rate limit, don't leak info via timing side channel, etc.
		if user != wantUser || pass != wantPass {
			unauthorized(w, nil, "bad auth")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func generateOpaqueID() string {
	buf := make([]byte, 16)
	_, err := rand.Reader.Read(buf)
	checkLog(err)
	if err != nil {
		// Very, very unlikely
		return ""
	}
	return hex.EncodeToString(buf)
}

func unauthorized(w http.ResponseWriter, err error, msg string, args ...interface{}) {
	w.Header().Set("WWW-Authenticate", `Basic realm="signed.codes admin"`)
	httpError(w, http.StatusUnauthorized, err, msg, args...)
}

func badRequest(w http.ResponseWriter, err error, msg string, args ...interface{}) {
	httpError(w, http.StatusBadRequest, err, msg, args...)
}

func internalServerError(w http.ResponseWriter, err error, msg string, args ...interface{}) {
	httpError(w, http.StatusInternalServerError, err, msg, args...)
}

func httpError(w http.ResponseWriter, code int, err error, msg string, args ...interface{}) {
	s := fmt.Sprintf(msg, args...)
	log.Printf("%s: %v", s, err)
	http.Error(w, s, code)
}

func toAmount(s string) (int, bool) {
	x, err := strconv.Atoi(s)
	if err == nil {
		return x, true
	}
	f, err := strconv.ParseFloat(s, 64)
	if err == nil && float64(int(f)) == f {
		return int(f), true
	}
	return 0, false
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
