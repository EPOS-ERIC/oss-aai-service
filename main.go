package main

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	webSessionCookie = "session_token"
	csrfCookie       = "csrf_token"
	webSessionTTL    = 24 * time.Hour
	accessTokenTTL   = 15 * time.Minute
	refreshTokenTTL  = 24 * time.Hour
)

type app struct {
	store     *localStore
	templates *template.Template
}

type viewData struct {
	Error     string
	User      *userRecord
	CSRFToken string
}

func main() {
	store, err := newLocalStore(filepath.Join("data", "auth.db"))
	if err != nil {
		log.Fatalf("init store: %v", err)
	}

	tmpl, err := template.ParseGlob("templates/*.tmpl")
	if err != nil {
		log.Fatalf("parse templates: %v", err)
	}

	a := &app{store: store, templates: tmpl}
	mux := http.NewServeMux()
	mux.HandleFunc("/", a.homeHandler)
	mux.HandleFunc("/register", a.registerHandler)
	mux.HandleFunc("/login", a.loginHandler)
	mux.HandleFunc("/logout", a.logoutHandler)
	mux.HandleFunc("/oauth/token", a.oauthTokenHandler)
	mux.HandleFunc("/oauth/validate", a.oauthValidateHandler)
	mux.HandleFunc("/oauth/revoke", a.oauthRevokeHandler)
	mux.HandleFunc("/oauth/userinfo", a.oauthUserInfoHandler)
	mux.HandleFunc("/oauth2/.well-known/openid-configuration", a.oidcDiscoveryHandler)
	mux.HandleFunc("/.well-known/openid-configuration", a.oidcDiscoveryHandler)
	mux.HandleFunc("/oauth2/token", a.oauthTokenHandler)
	mux.HandleFunc("/oauth2/introspect", a.oauthIntrospectHandler)
	mux.HandleFunc("/oauth2/revoke", a.oauthRevokeHandler)
	mux.HandleFunc("/oauth2/userinfo", a.oauthUserInfoHandler)
	mux.HandleFunc("/oauth2/jwk", a.oauthJWKSHandler)
	mux.HandleFunc("/oauth2-as/oauth2-authz", a.oauthAuthorizationHandler)
	mux.HandleFunc("/api/me", a.apiMeHandler)

	server := &http.Server{
		Addr:              ":8080",
		Handler:           loggingMiddleware(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Println("server started on http://localhost:8080")
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("listen: %v", err)
	}
}

func (a *app) homeHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	user, err := a.currentUserFromCookie(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	a.renderTemplate(w, r, "home.tmpl", viewData{User: &user})
}

func (a *app) registerHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.renderTemplate(w, r, "register.tmpl", viewData{})
	case http.MethodPost:
		if !a.validateCSRF(r) {
			http.Error(w, "invalid CSRF token", http.StatusForbidden)
			return
		}

		if err := r.ParseForm(); err != nil {
			a.renderTemplate(w, r, "register.tmpl", viewData{Error: "invalid form payload"})
			return
		}

		name := strings.TrimSpace(r.FormValue("name"))
		surname := strings.TrimSpace(r.FormValue("surname"))
		email := strings.TrimSpace(strings.ToLower(r.FormValue("email")))
		password := r.FormValue("password")

		if name == "" || surname == "" || email == "" || len(password) < 8 {
			a.renderTemplate(w, r, "register.tmpl", viewData{Error: "all fields are required and password must have at least 8 chars"})
			return
		}

		hash, err := hashPassword(password)
		if err != nil {
			a.renderTemplate(w, r, "register.tmpl", viewData{Error: "could not process password"})
			return
		}

		if _, err := a.store.createUser(name, surname, email, hash); err != nil {
			a.renderTemplate(w, r, "register.tmpl", viewData{Error: err.Error()})
			return
		}

		http.Redirect(w, r, "/login", http.StatusSeeOther)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *app) loginHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.renderTemplate(w, r, "login.tmpl", viewData{})
	case http.MethodPost:
		if !a.validateCSRF(r) {
			http.Error(w, "invalid CSRF token", http.StatusForbidden)
			return
		}

		if err := r.ParseForm(); err != nil {
			a.renderTemplate(w, r, "login.tmpl", viewData{Error: "invalid form payload"})
			return
		}

		email := strings.TrimSpace(strings.ToLower(r.FormValue("email")))
		password := r.FormValue("password")

		user, ok := a.store.getUserByEmail(email)
		if !ok || !checkPassword(password, user.PasswordHash) {
			a.renderTemplate(w, r, "login.tmpl", viewData{Error: "invalid credentials"})
			return
		}

		session, err := a.store.createSession(user.ID, sessionKindWeb, webSessionTTL)
		if err != nil {
			a.renderTemplate(w, r, "login.tmpl", viewData{Error: "unable to create session"})
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     webSessionCookie,
			Value:    session.Token,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Secure:   secureCookiesEnabled(r),
			Expires:  session.ExpiresAt,
		})

		http.Redirect(w, r, "/", http.StatusSeeOther)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *app) logoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !a.validateCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}

	cookie, err := r.Cookie(webSessionCookie)
	if err == nil {
		a.store.deleteSession(cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     webSessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   secureCookiesEnabled(r),
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (a *app) oauthTokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid form payload")
		return
	}

	clientID, clientSecret, ok := parseClientCredentials(r)
	if !ok || !a.store.validateOAuthClient(clientID, clientSecret) {
		w.Header().Set("WWW-Authenticate", `Basic realm="oauth2"`)
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}

	grantType := r.FormValue("grant_type")
	switch grantType {
	case "password":
		a.issuePasswordGrant(w, r)
	case "refresh_token":
		a.issueRefreshGrant(w, r)
	default:
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "supported grant types: password, refresh_token")
	}
}

func (a *app) issuePasswordGrant(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(strings.ToLower(r.FormValue("username")))
	password := r.FormValue("password")

	user, ok := a.store.getUserByEmail(username)
	if !ok || !checkPassword(password, user.PasswordHash) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "invalid resource owner credentials")
		return
	}

	access, err := a.store.createSession(user.ID, sessionKindOAuthAccess, accessTokenTTL)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to create access token")
		return
	}
	refresh, err := a.store.createSession(user.ID, sessionKindOAuthRefresh, refreshTokenTTL)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to create refresh token")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"token_type":    "Bearer",
		"access_token":  access.Token,
		"expires_in":    int(accessTokenTTL.Seconds()),
		"refresh_token": refresh.Token,
	})
}

func (a *app) issueRefreshGrant(w http.ResponseWriter, r *http.Request) {
	refreshToken := strings.TrimSpace(r.FormValue("refresh_token"))
	if refreshToken == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}

	refresh, ok := a.store.getSessionByToken(refreshToken)
	if !ok || refresh.Kind != sessionKindOAuthRefresh || refresh.ExpiresAt.Before(time.Now().UTC()) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token is invalid or expired")
		return
	}

	access, err := a.store.createSession(refresh.UserID, sessionKindOAuthAccess, accessTokenTTL)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to create access token")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"token_type":   "Bearer",
		"access_token": access.Token,
		"expires_in":   int(accessTokenTTL.Seconds()),
	})
}

func (a *app) oauthValidateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := bearerToken(r)
	if token == "" {
		token = strings.TrimSpace(r.URL.Query().Get("token"))
	}
	if token == "" {
		token = strings.TrimSpace(r.FormValue("token"))
	}

	session, ok := a.store.getSessionByToken(token)
	if !ok || session.Kind != sessionKindOAuthAccess || session.ExpiresAt.Before(time.Now().UTC()) {
		writeJSON(w, http.StatusOK, map[string]any{"active": false})
		return
	}

	user, ok := a.store.getUserByID(session.UserID)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"active": false})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"active":            true,
		"eduPersonUniqueId": user.ID,
		"firstname":         user.FirstName,
		"lastName":          user.LastName,
		"email":             user.Email,
		"exp":               session.ExpiresAt.Unix(),
	})
}

func (a *app) oauthIntrospectHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid form payload")
		return
	}

	clientID, clientSecret, ok := parseClientCredentials(r)
	if !ok || !a.store.validateOAuthClient(clientID, clientSecret) {
		w.Header().Set("WWW-Authenticate", `Basic realm="oauth2"`)
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}

	a.oauthValidateHandler(w, r)
}

func (a *app) oauthRevokeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid form payload")
		return
	}

	clientID, clientSecret, ok := parseClientCredentials(r)
	if !ok || !a.store.validateOAuthClient(clientID, clientSecret) {
		w.Header().Set("WWW-Authenticate", `Basic realm="oauth2"`)
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}

	token := strings.TrimSpace(r.FormValue("token"))
	if token != "" {
		a.store.deleteSession(token)
	}

	w.WriteHeader(http.StatusOK)
}

func (a *app) oauthUserInfoHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := bearerToken(r)
	session, ok := a.store.getSessionByToken(token)
	if !ok || session.Kind != sessionKindOAuthAccess || session.ExpiresAt.Before(time.Now().UTC()) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}

	user, ok := a.store.getUserByID(session.UserID)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"sub":               user.ID,
		"eduPersonUniqueId": user.ID,
		"name":              strings.TrimSpace(user.FirstName + " " + user.LastName),
		"given_name":        user.FirstName,
		"family_name":       user.LastName,
		"email":             user.Email,
		"email_verified":    true,
	})
}

func (a *app) oauthJWKSHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"keys": []any{}})
}

func (a *app) oauthAuthorizationHandler(w http.ResponseWriter, r *http.Request) {
	writeOAuthError(w, http.StatusBadRequest, "unsupported_response_type", "authorization code flow is not enabled in this service")
}

func (a *app) oidcDiscoveryHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	issuer := issuerURL(r)
	origin := originURL(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                origin + "/oauth2-as/oauth2-authz",
		"token_endpoint":                        issuer + "/token",
		"userinfo_endpoint":                     issuer + "/userinfo",
		"introspection_endpoint":                issuer + "/introspect",
		"revocation_endpoint":                   issuer + "/revoke",
		"jwks_uri":                              issuer + "/jwk",
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"response_types_supported":              []string{"token"},
		"response_modes_supported":              []string{"query", "fragment"},
		"grant_types_supported":                 []string{"password", "refresh_token"},
		"code_challenge_methods_supported":      []string{"plain", "S256"},
		"request_uri_parameter_supported":       false,
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"none"},
	})
}

func (a *app) apiMeHandler(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	session, ok := a.store.getSessionByToken(token)
	if !ok || session.Kind != sessionKindOAuthAccess || session.ExpiresAt.Before(time.Now().UTC()) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}

	user, ok := a.store.getUserByID(session.UserID)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"id":        user.ID,
		"firstName": user.FirstName,
		"lastName":  user.LastName,
		"email":     user.Email,
	})
}

func (a *app) currentUserFromCookie(r *http.Request) (userRecord, error) {
	cookie, err := r.Cookie(webSessionCookie)
	if err != nil {
		return userRecord{}, err
	}

	session, ok := a.store.getSessionByToken(cookie.Value)
	if !ok || session.Kind != sessionKindWeb || session.ExpiresAt.Before(time.Now().UTC()) {
		return userRecord{}, errors.New("invalid session")
	}

	user, ok := a.store.getUserByID(session.UserID)
	if !ok {
		return userRecord{}, errors.New("missing user")
	}

	return user, nil
}

func (a *app) renderTemplate(w http.ResponseWriter, r *http.Request, name string, data viewData) {
	token := a.ensureCSRFCookie(w, r)
	data.CSRFToken = token

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := a.templates.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, "template rendering error", http.StatusInternalServerError)
	}
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, map[string]string{
		"error":             code,
		"error_description": description,
	})
}

func bearerToken(r *http.Request) string {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if auth == "" {
		return ""
	}

	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return ""
	}

	return strings.TrimSpace(parts[1])
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

func parseClientCredentials(r *http.Request) (string, string, bool) {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(auth), "basic ") {
		raw := strings.TrimSpace(auth[6:])
		decoded, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return "", "", false
		}
		parts := strings.SplitN(string(decoded), ":", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" {
			return "", "", false
		}
		return strings.TrimSpace(parts[0]), parts[1], true
	}

	clientID := strings.TrimSpace(r.FormValue("client_id"))
	clientSecret := r.FormValue("client_secret")
	if clientID == "" || clientSecret == "" {
		return "", "", false
	}

	return clientID, clientSecret, true
}

func (a *app) ensureCSRFCookie(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(csrfCookie); err == nil && c.Value != "" {
		return c.Value
	}

	token := newToken()
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: false,
		SameSite: http.SameSiteLaxMode,
		Secure:   secureCookiesEnabled(r),
		Expires:  time.Now().UTC().Add(webSessionTTL),
	})

	return token
}

func (a *app) validateCSRF(r *http.Request) bool {
	if err := r.ParseForm(); err != nil {
		return false
	}

	formToken := strings.TrimSpace(r.FormValue("csrf_token"))
	cookie, err := r.Cookie(csrfCookie)
	if err != nil || cookie.Value == "" || formToken == "" {
		return false
	}

	if len(formToken) != len(cookie.Value) {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(formToken), []byte(cookie.Value)) == 1
}

func secureCookiesEnabled(r *http.Request) bool {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("APP_SECURE_COOKIES")), "true") {
		return true
	}
	return r.TLS != nil
}

func issuerURL(r *http.Request) string {
	if env := strings.TrimSpace(os.Getenv("OIDC_ISSUER")); env != "" {
		return strings.TrimRight(env, "/")
	}

	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); forwarded != "" {
		scheme = strings.ToLower(forwarded)
	}

	host := strings.TrimSpace(r.Host)
	if host == "" {
		host = "localhost:8080"
	}

	return scheme + "://" + host + "/oauth2"
}

func originURL(r *http.Request) string {
	issuer := issuerURL(r)
	return strings.TrimSuffix(issuer, "/oauth2")
}
