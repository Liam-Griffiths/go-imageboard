package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"time"

	_ "github.com/lib/pq"
)

var db *sql.DB

// Board represents an imageboard board
type Board struct {
	ID          int       `json:"id"`
	Slug        string    `json:"slug"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	ThreadCount int       `json:"thread_count"`
}

// InitDB initializes the PostgreSQL connection
func InitDB() error {
	// Get connection details from environment or use defaults
	dbHost := os.Getenv("DB_HOST")
	if dbHost == "" {
		dbHost = "localhost"
	}

	dbPort := os.Getenv("DB_PORT")
	if dbPort == "" {
		dbPort = "5432"
	}

	dbUser := os.Getenv("DB_USER")
	if dbUser == "" {
		dbUser = "imageboard"
	}

	dbPassword := os.Getenv("DB_PASSWORD")
	if dbPassword == "" {
		dbPassword = "imageboard"
	}

	dbName := os.Getenv("DB_NAME")
	if dbName == "" {
		dbName = "imageboard"
	}

	// Build connection string
	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		dbHost, dbPort, dbUser, dbPassword, dbName)

	// Connect to the database
	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		return err
	}

	// Test the connection
	err = db.Ping()
	if err != nil {
		return err
	}

	// Create tables if they don't exist
	err = createTables()
	if err != nil {
		return err
	}

	log.Println("Connected to PostgreSQL database successfully")
	return nil
}

// createTables ensures all required tables exist
func createTables() error {
	// Create boards table
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS boards (
			id SERIAL PRIMARY KEY,
			slug VARCHAR(50) UNIQUE NOT NULL,
			name VARCHAR(100) NOT NULL,
			description TEXT,
			created_at TIMESTAMP NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMP NOT NULL DEFAULT NOW()
		)
	`)

	if err != nil {
		return err
	}

	// Create threads table reference for PostgreSQL
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS threads (
			id SERIAL PRIMARY KEY,
			board_id INTEGER NOT NULL REFERENCES boards(id),
			created_at TIMESTAMP NOT NULL DEFAULT NOW()
		)
	`)

	if err != nil {
		return err
	}

	// Create admin user table (for future use)
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS admin_users (
			id SERIAL PRIMARY KEY,
			username VARCHAR(50) UNIQUE NOT NULL,
			password_hash VARCHAR(255) NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT NOW()
		)
	`)

	return err
}

// GetAllBoards returns all boards
func GetAllBoards() ([]Board, error) {
	rows, err := db.Query(`
		SELECT id, slug, name, description, created_at, updated_at 
		FROM boards 
		ORDER BY name
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var boards []Board
	for rows.Next() {
		var b Board
		err := rows.Scan(&b.ID, &b.Slug, &b.Name, &b.Description, &b.CreatedAt, &b.UpdatedAt)
		if err != nil {
			return nil, err
		}

		// Get thread count for each board
		err = db.QueryRow("SELECT COUNT(*) FROM threads WHERE board_id = $1", b.ID).Scan(&b.ThreadCount)
		if err != nil {
			// If this fails, just set thread count to 0
			b.ThreadCount = 0
		}

		boards = append(boards, b)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return boards, nil
}

// GetBoardBySlug returns a board by its slug
func GetBoardBySlug(slug string) (Board, error) {
	var b Board
	err := db.QueryRow(`
		SELECT id, slug, name, description, created_at, updated_at 
		FROM boards 
		WHERE slug = $1
	`, slug).Scan(&b.ID, &b.Slug, &b.Name, &b.Description, &b.CreatedAt, &b.UpdatedAt)

	if err != nil {
		return Board{}, err
	}

	// Get thread count
	err = db.QueryRow("SELECT COUNT(*) FROM threads WHERE board_id = $1", b.ID).Scan(&b.ThreadCount)
	if err != nil {
		b.ThreadCount = 0
	}

	return b, nil
}

// GetBoardByID returns a board by its ID
func GetBoardByID(id int) (Board, error) {
	var b Board
	err := db.QueryRow(`
		SELECT id, slug, name, description, created_at, updated_at 
		FROM boards 
		WHERE id = $1
	`, id).Scan(&b.ID, &b.Slug, &b.Name, &b.Description, &b.CreatedAt, &b.UpdatedAt)

	if err != nil {
		return Board{}, err
	}

	// Get thread count
	err = db.QueryRow("SELECT COUNT(*) FROM threads WHERE board_id = $1", b.ID).Scan(&b.ThreadCount)
	if err != nil {
		b.ThreadCount = 0
	}

	return b, nil
}

// CreateBoard creates a new board
func CreateBoard(slug, name, description string) (Board, error) {
	var b Board
	err := db.QueryRow(`
		INSERT INTO boards (slug, name, description, created_at, updated_at)
		VALUES ($1, $2, $3, NOW(), NOW())
		RETURNING id, slug, name, description, created_at, updated_at
	`, slug, name, description).Scan(&b.ID, &b.Slug, &b.Name, &b.Description, &b.CreatedAt, &b.UpdatedAt)

	return b, err
}

// UpdateBoard updates an existing board
func UpdateBoard(id int, name, description string) error {
	_, err := db.Exec(`
		UPDATE boards 
		SET name = $1, description = $2, updated_at = NOW()
		WHERE id = $3
	`, name, description, id)

	return err
}

// DeleteBoard deletes a board
func DeleteBoard(id int) error {
	_, err := db.Exec("DELETE FROM boards WHERE id = $1", id)
	return err
}
