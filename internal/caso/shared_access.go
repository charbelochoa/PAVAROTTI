package caso

import (
	"context"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	SharedReader      = "lector"
	SharedAnalyst     = "analista"
	MaxPasswordBytes  = 1024
	sharedSessionLife = 8 * time.Hour
	passwordRounds    = 600000
)

var (
	ErrSharedPostgres    = errors.New("el acceso compartido requiere PostgreSQL")
	ErrSharedAccount     = errors.New("verifica el nombre de usuario y el rol del expediente")
	ErrSharedPassword    = errors.New("la contraseña requiere al menos 12 caracteres y admite hasta 1024 bytes")
	ErrSharedCredentials = errors.New("usuario o contraseña incorrectos para este expediente")
	ErrSharedSession     = errors.New("inicia sesión en este expediente")
	usernamePattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)
)

type SharedAccount struct {
	Name string `json:"name"`
	Role string `json:"role"`
}

func (s *Store) SharedCase() string { return s.expediente }

func migrateSharedAccess(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS pavarotti_case_members (
		expediente TEXT NOT NULL,
		username TEXT NOT NULL,
		role TEXT NOT NULL CHECK (role IN ('lector', 'analista')),
		salt BYTEA NOT NULL CHECK (octet_length(salt) = 16),
		password_hash BYTEA NOT NULL CHECK (octet_length(password_hash) = 32),
		PRIMARY KEY (expediente, username)
	)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS pavarotti_case_sessions (
		expediente TEXT NOT NULL,
		username TEXT NOT NULL,
		token_hash TEXT NOT NULL,
		expires_at TIMESTAMPTZ NOT NULL,
		PRIMARY KEY (expediente, token_hash),
		FOREIGN KEY (expediente, username) REFERENCES pavarotti_case_members (expediente, username) ON DELETE CASCADE
	)`); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS pavarotti_case_sessions_member
		ON pavarotti_case_sessions (expediente, username)`)
	return err
}

func (s *Store) SaveSharedAccount(ctx context.Context, name, role, password string) (SharedAccount, error) {
	if s.db == nil {
		return SharedAccount{}, ErrSharedPostgres
	}
	name = canonicalUsername(name)
	if !usernamePattern.MatchString(name) || !validSharedRole(role) {
		return SharedAccount{}, ErrSharedAccount
	}
	if !validSharedPassword(password) {
		return SharedAccount{}, ErrSharedPassword
	}
	salt := make([]byte, 16)
	rand.Read(salt)
	digest, err := passwordDigest(password, salt)
	if err != nil {
		return SharedAccount{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SharedAccount{}, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO pavarotti_case_members (expediente, username, role, salt, password_hash)
		VALUES ($1, $2, $3, $4, $5) ON CONFLICT (expediente, username) DO UPDATE SET
		role = excluded.role, salt = excluded.salt, password_hash = excluded.password_hash`, s.expediente, name, role, salt, digest); err != nil {
		return SharedAccount{}, err
	}
	if err := revokeMemberSessions(ctx, tx, s.expediente, name); err != nil {
		return SharedAccount{}, err
	}
	if err := tx.Commit(); err != nil {
		return SharedAccount{}, err
	}
	return SharedAccount{Name: name, Role: role}, nil
}

func (s *Store) ChangeSharedRole(ctx context.Context, name, role string) (SharedAccount, error) {
	if s.db == nil {
		return SharedAccount{}, ErrSharedPostgres
	}
	name = canonicalUsername(name)
	if !usernamePattern.MatchString(name) || !validSharedRole(role) {
		return SharedAccount{}, ErrSharedAccount
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SharedAccount{}, err
	}
	defer tx.Rollback()
	var updated string
	err = tx.QueryRowContext(ctx, `UPDATE pavarotti_case_members SET role = $3 WHERE expediente = $1 AND username = $2
		RETURNING username`, s.expediente, name, role).Scan(&updated)
	if errors.Is(err, sql.ErrNoRows) {
		return SharedAccount{}, ErrNotFound
	}
	if err != nil {
		return SharedAccount{}, err
	}
	if err := revokeMemberSessions(ctx, tx, s.expediente, name); err != nil {
		return SharedAccount{}, err
	}
	if err := tx.Commit(); err != nil {
		return SharedAccount{}, err
	}
	return SharedAccount{Name: updated, Role: role}, nil
}

func (s *Store) RevokeSharedAccount(ctx context.Context, name string) error {
	if s.db == nil {
		return ErrSharedPostgres
	}
	name = canonicalUsername(name)
	if !usernamePattern.MatchString(name) {
		return ErrSharedAccount
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	var removed string
	err := s.db.QueryRowContext(ctx, `DELETE FROM pavarotti_case_members WHERE expediente = $1 AND username = $2
		RETURNING username`, s.expediente, name).Scan(&removed)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

func (s *Store) SharedAccounts(ctx context.Context) ([]SharedAccount, error) {
	if s.db == nil {
		return nil, ErrSharedPostgres
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, `SELECT username, role FROM pavarotti_case_members
		WHERE expediente = $1 ORDER BY username`, s.expediente)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	accounts := make([]SharedAccount, 0)
	for rows.Next() {
		var account SharedAccount
		if err := rows.Scan(&account.Name, &account.Role); err != nil {
			return nil, err
		}
		accounts = append(accounts, account)
	}
	return accounts, rows.Err()
}

func revokeMemberSessions(ctx context.Context, tx *sql.Tx, expediente, name string) error {
	_, err := tx.ExecContext(ctx, `DELETE FROM pavarotti_case_sessions WHERE expediente = $1 AND username = $2`, expediente, name)
	return err
}

func (s *Store) OpenSharedSession(ctx context.Context, name, password string) (string, time.Time, error) {
	if s.db == nil {
		return "", time.Time{}, ErrSharedPostgres
	}
	name = canonicalUsername(name)
	if !usernamePattern.MatchString(name) || !validSharedPassword(password) {
		return "", time.Time{}, ErrSharedCredentials
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	salt, stored := make([]byte, 16), make([]byte, 32)
	err := s.db.QueryRowContext(ctx, `SELECT salt, password_hash FROM pavarotti_case_members
		WHERE expediente = $1 AND username = $2`, s.expediente, name).Scan(&salt, &stored)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", time.Time{}, err
	}
	digest, hashErr := passwordDigest(password, salt)
	if hashErr != nil {
		return "", time.Time{}, hashErr
	}
	if subtle.ConstantTimeCompare(digest, stored) != 1 || err != nil {
		return "", time.Time{}, ErrSharedCredentials
	}
	return s.insertSharedSession(ctx, name, stored)
}

func (s *Store) insertSharedSession(ctx context.Context, name string, verified []byte) (string, time.Time, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", time.Time{}, err
	}
	defer tx.Rollback()
	var current []byte
	err = tx.QueryRowContext(ctx, `SELECT password_hash FROM pavarotti_case_members
		WHERE expediente = $1 AND username = $2 FOR SHARE`, s.expediente, name).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		return "", time.Time{}, ErrSharedCredentials
	}
	if err != nil {
		return "", time.Time{}, err
	}
	if subtle.ConstantTimeCompare(verified, current) != 1 {
		return "", time.Time{}, ErrSharedCredentials
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM pavarotti_case_sessions
		WHERE expediente = $1 AND username = $2 AND expires_at <= clock_timestamp()`, s.expediente, name); err != nil {
		return "", time.Time{}, err
	}
	var random [32]byte
	rand.Read(random[:])
	token := base64.RawURLEncoding.EncodeToString(random[:])
	var expires time.Time
	err = tx.QueryRowContext(ctx, `INSERT INTO pavarotti_case_sessions (expediente, username, token_hash, expires_at)
		VALUES ($1, $2, $3, clock_timestamp() + $4::bigint * interval '1 second') RETURNING expires_at`,
		s.expediente, name, Hash([]byte(token)), int64(sharedSessionLife/time.Second)).Scan(&expires)
	if err != nil {
		return "", time.Time{}, err
	}
	if err := tx.Commit(); err != nil {
		return "", time.Time{}, err
	}
	return token, expires, nil
}

func (s *Store) SharedSession(ctx context.Context, token string) (SharedAccount, error) {
	if s.db == nil {
		return SharedAccount{}, ErrSharedPostgres
	}
	if !validSharedToken(token) {
		return SharedAccount{}, ErrSharedSession
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	var account SharedAccount
	err := s.db.QueryRowContext(ctx, `SELECT m.username, m.role FROM pavarotti_case_sessions s
		JOIN pavarotti_case_members m ON m.expediente = s.expediente AND m.username = s.username
		WHERE s.expediente = $1 AND s.token_hash = $2 AND s.expires_at > clock_timestamp()`,
		s.expediente, Hash([]byte(token))).Scan(&account.Name, &account.Role)
	if errors.Is(err, sql.ErrNoRows) {
		return SharedAccount{}, ErrSharedSession
	}
	return account, err
}

func (s *Store) CloseSharedSession(ctx context.Context, token string) error {
	if s.db == nil {
		return ErrSharedPostgres
	}
	if !validSharedToken(token) {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	_, err := s.db.ExecContext(ctx, `DELETE FROM pavarotti_case_sessions WHERE expediente = $1 AND token_hash = $2`,
		s.expediente, Hash([]byte(token)))
	return err
}

func canonicalUsername(value string) string { return strings.ToLower(strings.TrimSpace(value)) }
func validSharedRole(value string) bool     { return value == SharedReader || value == SharedAnalyst }
func validSharedPassword(value string) bool {
	return len(value) <= MaxPasswordBytes && utf8.ValidString(value) && utf8.RuneCountInString(value) >= 12
}
func passwordDigest(password string, salt []byte) ([]byte, error) {
	return pbkdf2.Key(sha256.New, password, salt, passwordRounds, 32)
}
func validSharedToken(token string) bool {
	if len(token) != 43 {
		return false
	}
	data, err := base64.RawURLEncoding.Strict().DecodeString(token)
	return err == nil && len(data) == 32
}
