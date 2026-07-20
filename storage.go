package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const (
	sessionKindWeb              = "web"
	sessionKindOAuthAccess      = "oauth_access"
	sessionKindOAuthRefresh     = "oauth_refresh"
	defaultInitialAdminName     = "Admin"
	defaultInitialAdminSurname  = "Admin"
	defaultInitialAdminEmail    = "admin@admin.org"
	defaultInitialAdminPassword = "adminadmin"
)

type initialAdminSeedConfig struct {
	Name     string
	Surname  string
	Email    string
	Password string
}

type userRecord struct {
	ID           string    `json:"id"`
	FirstName    string    `json:"firstName"`
	LastName     string    `json:"lastName"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"password_hash"`
	CreatedAt    time.Time `json:"created_at"`
}

type sessionRecord struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Kind      string    `json:"kind"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

type oauthClientRecord struct {
	ClientID             string
	ClientSecretHash     string
	IsPublic             bool
	RedirectURIs         []string
	AllowedScopes        []string
	AllowedResponseTypes []string
	CreatedAt            time.Time
}

type dbState struct {
	_ int
}

type localStore struct {
	mu   sync.RWMutex
	path string
	db   *sql.DB
}

func newLocalStore(path string) (*localStore, error) {
	dir := filepath.Dir(path)
	if err := ensureDir(dir); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	store := &localStore{path: path, db: db}
	if err := store.loadOrInit(); err != nil {
		_ = db.Close()
		return nil, err
	}

	return store, nil
}

func (s *localStore) ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

func (s *localStore) createUser(name, surname, email, passwordHash string) (userRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.getUserByEmailLocked(email); ok {
		return userRecord{}, errors.New("user already exists")
	}

	user := userRecord{
		ID:           newID(),
		FirstName:    name,
		LastName:     surname,
		Email:        strings.ToLower(email),
		PasswordHash: passwordHash,
		CreatedAt:    time.Now().UTC(),
	}

	_, err := s.db.Exec(`
		INSERT INTO users(id, name, surname, email, password_hash, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, user.ID, user.FirstName, user.LastName, user.Email, user.PasswordHash, user.CreatedAt.Unix())
	if err != nil {
		return userRecord{}, err
	}

	return user, nil
}

func (s *localStore) getUserByEmail(email string) (userRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.getUserByEmailLocked(email)
}

func (s *localStore) getUserByEmailLocked(email string) (userRecord, bool) {
	row := s.db.QueryRow(`
		SELECT id, name, surname, email, password_hash, created_at
		FROM users WHERE email = ?
	`, strings.ToLower(strings.TrimSpace(email)))

	var user userRecord
	var createdAt int64
	if err := row.Scan(&user.ID, &user.FirstName, &user.LastName, &user.Email, &user.PasswordHash, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return userRecord{}, false
		}
		return userRecord{}, false
	}

	user.CreatedAt = time.Unix(createdAt, 0).UTC()
	return user, true
}

func (s *localStore) getUserByID(id string) (userRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	row := s.db.QueryRow(`
		SELECT id, name, surname, email, password_hash, created_at
		FROM users WHERE id = ?
	`, id)

	var user userRecord
	var createdAt int64
	if err := row.Scan(&user.ID, &user.FirstName, &user.LastName, &user.Email, &user.PasswordHash, &createdAt); err != nil {
		return userRecord{}, false
	}

	user.CreatedAt = time.Unix(createdAt, 0).UTC()
	return user, true
}

func (s *localStore) createSession(userID, kind string, ttl time.Duration) (sessionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	session := sessionRecord{
		ID:        newID(),
		UserID:    userID,
		Kind:      kind,
		Token:     newToken(),
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
	}

	_, err := s.db.Exec(`
		INSERT INTO sessions(id, user_id, kind, token, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, session.ID, session.UserID, session.Kind, session.Token, session.ExpiresAt.Unix(), session.CreatedAt.Unix())
	if err != nil {
		return sessionRecord{}, err
	}

	s.pruneExpiredSessionsLocked(now)

	return session, nil
}

func (s *localStore) getSessionByToken(token string) (sessionRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	row := s.db.QueryRow(`
		SELECT id, user_id, kind, token, expires_at, created_at
		FROM sessions WHERE token = ?
	`, token)

	var session sessionRecord
	var expiresAt, createdAt int64
	if err := row.Scan(&session.ID, &session.UserID, &session.Kind, &session.Token, &expiresAt, &createdAt); err != nil {
		return sessionRecord{}, false
	}

	session.ExpiresAt = time.Unix(expiresAt, 0).UTC()
	session.CreatedAt = time.Unix(createdAt, 0).UTC()
	return session, true
}

func (s *localStore) deleteSession(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, _ = s.db.Exec(`DELETE FROM sessions WHERE token = ?`, token)
}

func (s *localStore) loadOrInit() error {
	if _, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			surname TEXT NOT NULL,
			email TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			created_at INTEGER NOT NULL
		)
	`); err != nil {
		return fmt.Errorf("create users table: %w", err)
	}

	if _, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS sessions (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			kind TEXT NOT NULL,
			token TEXT NOT NULL UNIQUE,
			expires_at INTEGER NOT NULL,
			created_at INTEGER NOT NULL
		)
	`); err != nil {
		return fmt.Errorf("create sessions table: %w", err)
	}

	if _, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS oauth_clients (
			client_id TEXT PRIMARY KEY,
			client_secret_hash TEXT NOT NULL,
			is_public INTEGER NOT NULL DEFAULT 0,
			redirect_uris_json TEXT NOT NULL DEFAULT '[]',
			allowed_scopes_json TEXT NOT NULL DEFAULT '[]',
			allowed_response_types_json TEXT NOT NULL DEFAULT '[]',
			created_at INTEGER NOT NULL
		)
	`); err != nil {
		return fmt.Errorf("create oauth_clients table: %w", err)
	}

	if err := s.ensureOAuthClientSchema(); err != nil {
		return fmt.Errorf("migrate oauth_clients table: %w", err)
	}

	if _, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS app_meta (
			meta_key TEXT PRIMARY KEY,
			meta_value TEXT NOT NULL
		)
	`); err != nil {
		return fmt.Errorf("create app_meta table: %w", err)
	}

	if err := s.seedOAuthClients(); err != nil {
		return fmt.Errorf("seed oauth clients: %w", err)
	}

	if err := s.seedInitialAdminUser(); err != nil {
		return fmt.Errorf("seed initial admin user: %w", err)
	}

	return nil
}

func (s *localStore) ensureOAuthClientSchema() error {
	columns := []struct {
		name       string
		definition string
	}{
		{name: "is_public", definition: "is_public INTEGER NOT NULL DEFAULT 0"},
		{name: "redirect_uris_json", definition: "redirect_uris_json TEXT NOT NULL DEFAULT '[]'"},
		{name: "allowed_scopes_json", definition: "allowed_scopes_json TEXT NOT NULL DEFAULT '[]'"},
		{name: "allowed_response_types_json", definition: "allowed_response_types_json TEXT NOT NULL DEFAULT '[]'"},
	}

	for _, column := range columns {
		if err := s.ensureTableColumn("oauth_clients", column.name, column.definition); err != nil {
			return err
		}
	}

	return nil
}

func (s *localStore) ensureTableColumn(table, name, definition string) error {
	rows, err := s.db.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var (
			cid        int
			columnName string
			columnType string
			notNull    int
			defaultVal sql.NullString
			pk         int
		)
		if err := rows.Scan(&cid, &columnName, &columnType, &notNull, &defaultVal, &pk); err != nil {
			return err
		}
		if columnName == name {
			return nil
		}
	}

	if err := rows.Err(); err != nil {
		return err
	}

	_, err = s.db.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s", table, definition))
	return err
}

func (s *localStore) seedOAuthClients() error {
	secretHash, err := hashPassword("dev-secret")
	if err != nil {
		return fmt.Errorf("hash default client secret: %w", err)
	}

	if err := s.seedOAuthClient(oauthClientRecord{
		ClientID:         "local-dev-client",
		ClientSecretHash: secretHash,
		AllowedScopes:    []string{"openid", "profile", "email"},
		CreatedAt:        time.Now().UTC(),
	}); err != nil {
		return err
	}

	redirectURIs, err := defaultOAuthRedirectURIs()
	if err != nil {
		return err
	}

	if err := s.seedOAuthClient(oauthClientRecord{
		ClientID:             "eposICS",
		IsPublic:             true,
		RedirectURIs:         redirectURIs,
		AllowedScopes:        []string{"openid", "profile", "email", "single-logout"},
		AllowedResponseTypes: []string{"id_token token"},
		CreatedAt:            time.Now().UTC(),
	}); err != nil {
		return err
	}

	return s.addOAuthClientRedirectURIs("eposICS", redirectURIs)
}

func (s *localStore) seedOAuthClient(client oauthClientRecord) error {
	redirectURIsJSON, err := marshalStringList(client.RedirectURIs)
	if err != nil {
		return err
	}
	scopesJSON, err := marshalStringList(client.AllowedScopes)
	if err != nil {
		return err
	}
	responseTypesJSON, err := marshalStringList(client.AllowedResponseTypes)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(`
		INSERT OR IGNORE INTO oauth_clients(
			client_id,
			client_secret_hash,
			is_public,
			redirect_uris_json,
			allowed_scopes_json,
			allowed_response_types_json,
			created_at
		)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, client.ClientID, client.ClientSecretHash, boolToInt(client.IsPublic), redirectURIsJSON, scopesJSON, responseTypesJSON, client.CreatedAt.Unix())
	return err
}

func (s *localStore) addOAuthClientRedirectURIs(clientID string, redirectURIs []string) error {
	client, ok := s.getOAuthClient(clientID)
	if !ok {
		return fmt.Errorf("oauth client %q not found", clientID)
	}

	known := make(map[string]struct{}, len(client.RedirectURIs))
	for _, redirectURI := range client.RedirectURIs {
		known[redirectURI] = struct{}{}
	}

	updated := false
	for _, redirectURI := range redirectURIs {
		if _, ok := known[redirectURI]; ok {
			continue
		}

		client.RedirectURIs = append(client.RedirectURIs, redirectURI)
		known[redirectURI] = struct{}{}
		updated = true
	}

	if !updated {
		return nil
	}

	redirectURIsJSON, err := marshalStringList(client.RedirectURIs)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(
		`UPDATE oauth_clients SET redirect_uris_json = ? WHERE client_id = ?`,
		redirectURIsJSON,
		clientID,
	)
	return err
}

func loadInitialAdminSeedConfig() initialAdminSeedConfig {
	password := os.Getenv("INITIAL_ADMIN_PASSWORD")
	if strings.TrimSpace(password) == "" {
		password = defaultInitialAdminPassword
	}

	return initialAdminSeedConfig{
		Name:     trimmedEnvOrDefault(defaultInitialAdminName, "INITIAL_ADMIN_NAME"),
		Surname:  trimmedEnvOrDefault(defaultInitialAdminSurname, "INITIAL_ADMIN_SURNAME"),
		Email:    strings.ToLower(trimmedEnvOrDefault(defaultInitialAdminEmail, "INITIAL_ADMIN_EMAIL")),
		Password: password,
	}
}

func trimmedEnvOrDefault(defaultValue string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			return value
		}
	}
	return defaultValue
}

func (s *localStore) seedInitialAdminUser() error {
	row := s.db.QueryRow(`SELECT meta_value FROM app_meta WHERE meta_key = ?`, "initial_admin_seeded")
	var marker string
	if err := row.Scan(&marker); err == nil {
		return nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}

	admin := loadInitialAdminSeedConfig()

	hash, err := hashPassword(admin.Password)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(`
		INSERT OR IGNORE INTO users(id, name, surname, email, password_hash, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, newID(), admin.Name, admin.Surname, admin.Email, hash, time.Now().UTC().Unix())
	if err != nil {
		return err
	}

	_, err = s.db.Exec(`
		INSERT INTO app_meta(meta_key, meta_value)
		VALUES (?, ?)
	`, "initial_admin_seeded", "true")
	if err != nil {
		return err
	}

	return nil
}

func (s *localStore) pruneExpiredSessionsLocked(now time.Time) {
	_, _ = s.db.Exec(`DELETE FROM sessions WHERE expires_at < ?`, now.Unix())
}

func (s *localStore) getOAuthClient(clientID string) (oauthClientRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.getOAuthClientLocked(clientID)
}

func (s *localStore) getOAuthClientLocked(clientID string) (oauthClientRecord, bool) {
	row := s.db.QueryRow(`
		SELECT client_id, client_secret_hash, is_public, redirect_uris_json, allowed_scopes_json, allowed_response_types_json, created_at
		FROM oauth_clients
		WHERE client_id = ?
	`, strings.TrimSpace(clientID))

	var (
		client            oauthClientRecord
		isPublic          int
		redirectURIsJSON  string
		scopesJSON        string
		responseTypesJSON string
		createdAt         int64
	)
	if err := row.Scan(&client.ClientID, &client.ClientSecretHash, &isPublic, &redirectURIsJSON, &scopesJSON, &responseTypesJSON, &createdAt); err != nil {
		return oauthClientRecord{}, false
	}

	client.IsPublic = isPublic == 1
	client.RedirectURIs = unmarshalStringList(redirectURIsJSON)
	client.AllowedScopes = unmarshalStringList(scopesJSON)
	client.AllowedResponseTypes = unmarshalStringList(responseTypesJSON)
	client.CreatedAt = time.Unix(createdAt, 0).UTC()

	return client, true
}

func (s *localStore) validateOAuthClient(clientID, clientSecret string) bool {
	client, ok := s.getOAuthClient(clientID)
	if !ok || client.IsPublic || strings.TrimSpace(clientSecret) == "" {
		return false
	}

	return checkPassword(clientSecret, client.ClientSecretHash)
}

func (s *localStore) getAppMeta(key string) (string, bool, error) {
	row := s.db.QueryRow(`SELECT meta_value FROM app_meta WHERE meta_key = ?`, key)
	var value string
	if err := row.Scan(&value); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", false, nil
		}
		return "", false, err
	}

	return value, true, nil
}

func (s *localStore) setAppMeta(key, value string) error {
	_, err := s.db.Exec(`
		INSERT INTO app_meta(meta_key, meta_value)
		VALUES (?, ?)
		ON CONFLICT(meta_key) DO UPDATE SET meta_value = excluded.meta_value
	`, key, value)
	return err
}

func ensureDir(path string) error {
	if err := os.MkdirAll(path, 0o755); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	return nil
}

func newID() string {
	return newToken()
}

func newToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand is unavailable")
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func defaultOAuthRedirectURIs() ([]string, error) {
	redirectURIs := []string{
		"http://localhost:34000/last-page-redirect",
		"http://localhost:34000/silent-token-refresh.html",
		"http://localhost:4200/testpath/last-page-redirect",
		"http://localhost:4200/testpath/silent-token-refresh.html",
		"http://localhost:32000/last-page-redirect",
		"http://localhost:32000/silent-token-refresh.html",
	}

	for _, envName := range []string{"PLATFORM_URL", "BACKOFFICE_URL"} {
		baseURL := strings.TrimSpace(os.Getenv(envName))
		if baseURL == "" {
			continue
		}

		configuredRedirectURIs, err := redirectURIsForBaseURL(envName, baseURL)
		if err != nil {
			return nil, err
		}
		for _, redirectURI := range configuredRedirectURIs {
			if !containsString(redirectURIs, redirectURI) {
				redirectURIs = append(redirectURIs, redirectURI)
			}
		}
	}

	return redirectURIs, nil
}

func redirectURIsForBaseURL(envName, baseURL string) ([]string, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid %s: %w", envName, err)
	}
	if (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, fmt.Errorf("invalid %s: must be an absolute http(s) URL", envName)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("invalid %s: query and fragment are not allowed", envName)
	}

	baseURL = strings.TrimRight(baseURL, "/")
	return []string{
		baseURL + "/last-page-redirect",
		baseURL + "/silent-token-refresh.html",
	}, nil
}

func marshalStringList(values []string) (string, error) {
	if len(values) == 0 {
		return "[]", nil
	}

	encoded, err := json.Marshal(values)
	if err != nil {
		return "", err
	}

	return string(encoded), nil
}

func unmarshalStringList(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}

	var values []string
	if err := json.Unmarshal([]byte(value), &values); err != nil {
		return nil
	}

	return values
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
