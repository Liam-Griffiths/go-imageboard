package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// AdminUser represents an admin user
type AdminUser struct {
	ID           int       `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"` // Don't include in JSON output
	CreatedAt    time.Time `json:"created_at"`
}

// Session represents a user session
type Session struct {
	Token     string    `json:"token"`
	UserID    int       `json:"user_id"`
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Errors
var (
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrSessionNotFound    = errors.New("session not found")
	ErrSessionExpired     = errors.New("session expired")
)

// CreateAdminUser creates a new admin user
func CreateAdminUser(username, password string) (AdminUser, error) {
	// Hash the password
	passwordHash := hashPassword(password)

	// Insert into database
	var user AdminUser
	err := db.QueryRow(`
		INSERT INTO admin_users (username, password_hash, created_at)
		VALUES ($1, $2, NOW())
		RETURNING id, username, password_hash, created_at
	`, username, passwordHash).Scan(&user.ID, &user.Username, &user.PasswordHash, &user.CreatedAt)

	return user, err
}

// GetAdminUserByUsername retrieves an admin user by username
func GetAdminUserByUsername(username string) (AdminUser, error) {
	var user AdminUser
	err := db.QueryRow(`
		SELECT id, username, password_hash, created_at
		FROM admin_users
		WHERE username = $1
	`, username).Scan(&user.ID, &user.Username, &user.PasswordHash, &user.CreatedAt)

	return user, err
}

// AuthenticateUser authenticates a user with username and password
func AuthenticateUser(username, password string) (AdminUser, error) {
	user, err := GetAdminUserByUsername(username)
	if err != nil {
		return AdminUser{}, ErrInvalidCredentials
	}

	// Check password
	if !verifyPassword(password, user.PasswordHash) {
		return AdminUser{}, ErrInvalidCredentials
	}

	return user, nil
}

// CreateSession creates a new session for a user
func CreateSession(userID int, username string) (Session, error) {
	// Generate random token
	token, err := generateRandomToken(32)
	if err != nil {
		return Session{}, err
	}

	// Create session with 24-hour expiration
	now := time.Now()
	expiresAt := now.Add(24 * time.Hour)

	session := Session{
		Token:     token,
		UserID:    userID,
		Username:  username,
		CreatedAt: now,
		ExpiresAt: expiresAt,
	}

	// Store session in Redis
	sessionKey := "session:" + token
	err = rdb.HSet(ctx, sessionKey, map[string]interface{}{
		"user_id":    userID,
		"username":   username,
		"created_at": now.Unix(),
		"expires_at": expiresAt.Unix(),
	}).Err()

	if err != nil {
		return Session{}, err
	}

	// Set expiration on the Redis key
	err = rdb.Expire(ctx, sessionKey, 24*time.Hour).Err()
	if err != nil {
		return Session{}, err
	}

	return session, nil
}

// GetSession retrieves a session by token
func GetSession(token string) (Session, error) {
	sessionKey := "session:" + token

	// Check if session exists
	exists, err := rdb.Exists(ctx, sessionKey).Result()
	if err != nil {
		return Session{}, err
	}

	if exists == 0 {
		return Session{}, ErrSessionNotFound
	}

	// Get session data
	data, err := rdb.HGetAll(ctx, sessionKey).Result()
	if err != nil {
		return Session{}, err
	}

	// Parse session data
	userID := 0
	if id, ok := data["user_id"]; ok {
		userID, _ = parseInt(id)
	}

	username := ""
	if name, ok := data["username"]; ok {
		username = name
	}

	createdAt := time.Now()
	if created, ok := data["created_at"]; ok {
		timestamp, _ := parseInt(created)
		createdAt = time.Unix(int64(timestamp), 0)
	}

	expiresAt := time.Now()
	if expires, ok := data["expires_at"]; ok {
		timestamp, _ := parseInt(expires)
		expiresAt = time.Unix(int64(timestamp), 0)
	}

	// Check if session is expired
	if time.Now().After(expiresAt) {
		// Delete expired session
		rdb.Del(ctx, sessionKey)
		return Session{}, ErrSessionExpired
	}

	session := Session{
		Token:     token,
		UserID:    userID,
		Username:  username,
		CreatedAt: createdAt,
		ExpiresAt: expiresAt,
	}

	return session, nil
}

// DeleteSession deletes a session
func DeleteSession(token string) error {
	sessionKey := "session:" + token
	return rdb.Del(ctx, sessionKey).Err()
}

// SetSessionCookie sets a session cookie
func SetSessionCookie(w http.ResponseWriter, session Session) {
	cookie := http.Cookie{
		Name:     "session",
		Value:    session.Token,
		Path:     "/",
		HttpOnly: true,
		Expires:  session.ExpiresAt,
	}
	http.SetCookie(w, &cookie)
}

// ClearSessionCookie clears the session cookie
func ClearSessionCookie(w http.ResponseWriter) {
	cookie := http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	}
	http.SetCookie(w, &cookie)
}

// GetUserFromRequest gets the user from the request's session cookie
func GetUserFromRequest(r *http.Request) (AdminUser, error) {
	// Get session cookie
	cookie, err := r.Cookie("session")
	if err != nil {
		return AdminUser{}, err
	}

	// Get session
	session, err := GetSession(cookie.Value)
	if err != nil {
		return AdminUser{}, err
	}

	// Get user
	user := AdminUser{
		ID:        session.UserID,
		Username:  session.Username,
		CreatedAt: time.Time{}, // We don't have this info from the session
	}

	return user, nil
}

// RequireAuth is middleware that requires authentication
func RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get user from request
		_, err := GetUserFromRequest(r)
		if err != nil {
			// Redirect to login page
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// User is authenticated, proceed
		next(w, r)
	}
}

// Helper functions

// hashPassword hashes a password using SHA-256
func hashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}

// verifyPassword verifies a password against a hash
func verifyPassword(password, hash string) bool {
	return hashPassword(password) == hash
}

// generateRandomToken generates a random token
func generateRandomToken(length int) (string, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// parseInt parses a string to an int
func parseInt(s string) (int, error) {
	var i int
	_, err := fmt.Sscanf(s, "%d", &i)
	return i, err
}
