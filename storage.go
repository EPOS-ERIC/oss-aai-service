package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const (
	sessionKindWeb          = "web"
	sessionKindOAuthAccess  = "oauth_access"
	sessionKindOAuthRefresh = "oauth_refresh"
)

type userRecord struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Surname      string    `json:"surname"`
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

func (s *localStore) createUser(name, surname, email, passwordHash string) (userRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.getUserByEmailLocked(email); ok {
		return userRecord{}, errors.New("user already exists")
	}

	user := userRecord{
		ID:           newID(),
		Name:         name,
		Surname:      surname,
		Email:        strings.ToLower(email),
		PasswordHash: passwordHash,
		CreatedAt:    time.Now().UTC(),
	}

	_, err := s.db.Exec(`
		INSERT INTO users(id, name, surname, email, password_hash, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, user.ID, user.Name, user.Surname, user.Email, user.PasswordHash, user.CreatedAt.Unix())
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
	if err := row.Scan(&user.ID, &user.Name, &user.Surname, &user.Email, &user.PasswordHash, &createdAt); err != nil {
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
	if err := row.Scan(&user.ID, &user.Name, &user.Surname, &user.Email, &user.PasswordHash, &createdAt); err != nil {
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
			created_at INTEGER NOT NULL
		)
	`); err != nil {
		return fmt.Errorf("create oauth_clients table: %w", err)
	}

	if _, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS app_meta (
			meta_key TEXT PRIMARY KEY,
			meta_value TEXT NOT NULL
		)
	`); err != nil {
		return fmt.Errorf("create app_meta table: %w", err)
	}

	hash, err := hashPassword("dev-secret")
	if err != nil {
		return fmt.Errorf("hash default client secret: %w", err)
	}

	if _, err := s.db.Exec(`
		INSERT OR IGNORE INTO oauth_clients(client_id, client_secret_hash, created_at)
		VALUES (?, ?, ?)
	`, "local-dev-client", hash, time.Now().UTC().Unix()); err != nil {
		return fmt.Errorf("seed oauth client: %w", err)
	}

	if err := s.seedInitialAdminUser(); err != nil {
		return fmt.Errorf("seed initial admin user: %w", err)
	}

	return nil
}

func (s *localStore) seedInitialAdminUser() error {
	row := s.db.QueryRow(`SELECT meta_value FROM app_meta WHERE meta_key = ?`, "initial_admin_seeded")
	var marker string
	if err := row.Scan(&marker); err == nil {
		return nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}

	password := strings.TrimSpace(os.Getenv("INITIAL_ADMIN_PASSWORD"))
	if password == "" {
		password = "adminadmin"
	}

	hash, err := hashPassword(password)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(`
		INSERT OR IGNORE INTO users(id, name, surname, email, password_hash, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, newID(), "Admin", "Admin", "admin@admin.org", hash, time.Now().UTC().Unix())
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

func (s *localStore) validateOAuthClient(clientID, clientSecret string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	row := s.db.QueryRow(`SELECT client_secret_hash FROM oauth_clients WHERE client_id = ?`, strings.TrimSpace(clientID))
	var hash string
	if err := row.Scan(&hash); err != nil {
		return false
	}

	return checkPassword(clientSecret, hash)
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
