package main

import (
	"encoding/base64"
	"encoding/json"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

func TestHealthHandlerReturnsOKWhenStoreIsAvailable(t *testing.T) {
	a := newTestApp(t)
	req := httptest.NewRequest(http.MethodGet, "http://localhost:35000/healthz", nil)
	rr := httptest.NewRecorder()

	a.healthHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("unexpected status: got %d", rr.Code)
	}

	var payload map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal health response: %v", err)
	}
	if got := payload["status"]; got != "ok" {
		t.Fatalf("unexpected status payload: %q", got)
	}
}

func TestHealthHandlerReturnsServiceUnavailableWhenStoreIsClosed(t *testing.T) {
	a := newTestApp(t)
	if err := a.store.db.Close(); err != nil {
		t.Fatalf("close store db: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://localhost:35000/healthz", nil)
	rr := httptest.NewRecorder()

	a.healthHandler(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("unexpected status: got %d", rr.Code)
	}

	var payload map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal health response: %v", err)
	}
	if got := payload["status"]; got != "error" {
		t.Fatalf("unexpected status payload: %q", got)
	}
	if got := payload["error"]; got != "database unavailable" {
		t.Fatalf("unexpected error payload: %q", got)
	}
}

func TestHealthHandlerRejectsNonGETMethods(t *testing.T) {
	a := newTestApp(t)
	req := httptest.NewRequest(http.MethodPost, "http://localhost:35000/healthz", nil)
	rr := httptest.NewRecorder()

	a.healthHandler(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("unexpected status: got %d", rr.Code)
	}
}

func TestOIDCDiscoveryUsesIssuerAuthorizationEndpoint(t *testing.T) {
	a := newTestApp(t)
	req := httptest.NewRequest(http.MethodGet, "http://localhost:35000/oauth2/.well-known/openid-configuration", nil)
	rr := httptest.NewRecorder()

	a.oidcDiscoveryHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("unexpected status: got %d", rr.Code)
	}

	var payload map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal discovery document: %v", err)
	}

	if got := payload["authorization_endpoint"]; got != "http://localhost:35000/oauth2/authorize" {
		t.Fatalf("unexpected authorization endpoint: %v", got)
	}

	responseTypes, ok := payload["response_types_supported"].([]any)
	if !ok || len(responseTypes) != 1 || responseTypes[0] != "id_token token" {
		t.Fatalf("unexpected response_types_supported: %#v", payload["response_types_supported"])
	}
	if got := payload["id_token_signing_alg_values_supported"].([]any)[0]; got != "RS256" {
		t.Fatalf("unexpected signing algorithm: %v", got)
	}
}

func TestOAuthAuthorizationHandlerRedirectsToLoginWhenSessionMissing(t *testing.T) {
	a := newTestApp(t)
	req := httptest.NewRequest(http.MethodGet, authURL("http://localhost:35000/oauth2/authorize", map[string]string{
		"response_type": "id_token token",
		"client_id":     "eposICS",
		"redirect_uri":  "http://localhost:34000/last-page-redirect",
		"scope":         "openid profile single-logout",
		"state":         "state-123",
		"nonce":         "nonce-123",
	}), nil)
	rr := httptest.NewRecorder()

	a.oauthAuthorizationHandler(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("unexpected status: got %d", rr.Code)
	}

	location := rr.Header().Get("Location")
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse redirect location: %v", err)
	}
	if parsed.Path != "/login" {
		t.Fatalf("unexpected login redirect path: %s", parsed.Path)
	}
	if got := parsed.Query().Get("continue"); got != req.URL.RequestURI() {
		t.Fatalf("unexpected continue query: %q", got)
	}
}

func TestOAuthAuthorizationHandlerIssuesImplicitTokensForLoggedInUser(t *testing.T) {
	a := newTestApp(t)
	user, ok := a.store.getUserByEmail("admin@admin.org")
	if !ok {
		t.Fatal("seeded admin user not found")
	}
	webSession, err := a.store.createSession(user.ID, sessionKindWeb, webSessionTTL)
	if err != nil {
		t.Fatalf("create web session: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, authURL("http://localhost:35000/oauth2/authorize", map[string]string{
		"response_type": "id_token token",
		"client_id":     "eposICS",
		"redirect_uri":  "http://localhost:34000/last-page-redirect",
		"scope":         "openid profile single-logout",
		"state":         "state-123",
		"nonce":         "nonce-123",
	}), nil)
	req.AddCookie(&http.Cookie{Name: webSessionCookie, Value: webSession.Token})
	rr := httptest.NewRecorder()

	a.oauthAuthorizationHandler(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("unexpected status: got %d", rr.Code)
	}

	location := rr.Header().Get("Location")
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse redirect location: %v", err)
	}
	if got := parsed.String(); !strings.HasPrefix(got, "http://localhost:34000/last-page-redirect#") {
		t.Fatalf("unexpected redirect target: %s", got)
	}

	fragment, err := url.ParseQuery(parsed.Fragment)
	if err != nil {
		t.Fatalf("parse fragment: %v", err)
	}
	if fragment.Get("access_token") == "" {
		t.Fatal("missing access_token")
	}
	if fragment.Get("token_type") != "Bearer" {
		t.Fatalf("unexpected token_type: %q", fragment.Get("token_type"))
	}
	if fragment.Get("state") != "state-123" {
		t.Fatalf("unexpected state: %q", fragment.Get("state"))
	}

	idToken := fragment.Get("id_token")
	claims := decodeJWTClaims(t, idToken)
	if got := claims["iss"]; got != "http://localhost:35000/oauth2" {
		t.Fatalf("unexpected iss claim: %v", got)
	}
	if got := claims["aud"]; got != "eposICS" {
		t.Fatalf("unexpected aud claim: %v", got)
	}
	if got := claims["sub"]; got != user.ID {
		t.Fatalf("unexpected sub claim: %v", got)
	}
	if got := claims["nonce"]; got != "nonce-123" {
		t.Fatalf("unexpected nonce claim: %v", got)
	}
	if got := claims["email"]; got != user.Email {
		t.Fatalf("unexpected email claim: %v", got)
	}
}

func TestOAuthAuthorizationHandlerPromptNoneReturnsLoginRequired(t *testing.T) {
	a := newTestApp(t)
	req := httptest.NewRequest(http.MethodGet, authURL("http://localhost:35000/oauth2/authorize", map[string]string{
		"response_type": "id_token token",
		"client_id":     "eposICS",
		"redirect_uri":  "http://localhost:34000/silent-token-refresh.html",
		"scope":         "openid profile single-logout",
		"state":         "state-123",
		"nonce":         "nonce-123",
		"prompt":        "none",
	}), nil)
	rr := httptest.NewRecorder()

	a.oauthAuthorizationHandler(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("unexpected status: got %d", rr.Code)
	}

	parsed, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect location: %v", err)
	}
	fragment, err := url.ParseQuery(parsed.Fragment)
	if err != nil {
		t.Fatalf("parse fragment: %v", err)
	}
	if got := fragment.Get("error"); got != "login_required" {
		t.Fatalf("unexpected error: %q", got)
	}
	if got := fragment.Get("state"); got != "state-123" {
		t.Fatalf("unexpected state: %q", got)
	}
}

func TestOAuthRevokeHandlerAcceptsPublicClientBearerRevoke(t *testing.T) {
	a := newTestApp(t)
	user, ok := a.store.getUserByEmail("admin@admin.org")
	if !ok {
		t.Fatal("seeded admin user not found")
	}
	access, err := a.store.createSession(user.ID, sessionKindOAuthAccess, accessTokenTTL)
	if err != nil {
		t.Fatalf("create access session: %v", err)
	}

	form := url.Values{}
	form.Set("client_id", "eposICS")
	form.Set("token", access.Token)
	req := httptest.NewRequest(http.MethodPost, "http://localhost:35000/oauth2/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Authorization", "Bearer "+access.Token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	a.oauthRevokeHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("unexpected status: got %d body=%s", rr.Code, rr.Body.String())
	}
	if _, ok := a.store.getSessionByToken(access.Token); ok {
		t.Fatal("access token still exists after revoke")
	}
}

func TestNewLocalStoreSeedsInitialAdminUserFromEnvironment(t *testing.T) {
	t.Setenv("INITIAL_ADMIN_NAME", "Platform")
	t.Setenv("INITIAL_ADMIN_SURNAME", "Owner")
	t.Setenv("INITIAL_ADMIN_EMAIL", "root@example.org")
	t.Setenv("INITIAL_ADMIN_PASSWORD", "super-secret-password")

	store, err := newLocalStore(filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() {
		_ = store.db.Close()
	})

	user, ok := store.getUserByEmail("root@example.org")
	if !ok {
		t.Fatal("seeded admin user not found")
	}
	if user.FirstName != "Platform" {
		t.Fatalf("unexpected first name: %q", user.FirstName)
	}
	if user.LastName != "Owner" {
		t.Fatalf("unexpected surname: %q", user.LastName)
	}
	if user.Email != "root@example.org" {
		t.Fatalf("unexpected email: %q", user.Email)
	}
	if !checkPassword("super-secret-password", user.PasswordHash) {
		t.Fatal("seeded admin password hash does not match env password")
	}
}

func newTestApp(t *testing.T) *app {
	t.Helper()

	store, err := newLocalStore(filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() {
		_ = store.db.Close()
	})

	templates, err := template.ParseGlob("templates/*.tmpl")
	if err != nil {
		t.Fatalf("parse templates: %v", err)
	}

	oidcSigner, err := newOIDCSigner(store)
	if err != nil {
		t.Fatalf("create oidc signer: %v", err)
	}

	return &app{store: store, templates: templates, oidc: oidcSigner}
}

func authURL(base string, params map[string]string) string {
	values := url.Values{}
	for key, value := range params {
		values.Set(key, value)
	}
	return base + "?" + values.Encode()
}

func decodeJWTClaims(t *testing.T, token string) map[string]any {
	t.Helper()

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("unexpected JWT format: %q", token)
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode JWT payload: %v", err)
	}

	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal JWT claims: %v", err)
	}

	return claims
}
