package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var templates map[string]*template.Template

// InitTemplates parses and loads all templates
func InitTemplates() {
	templates = make(map[string]*template.Template)

	// Define our template functions
	funcMap := template.FuncMap{
		"formatTime": func(t time.Time) string {
			return t.Format("2006-01-02 15:04:05")
		},
		"truncate": func(s string, length int) string {
			if len(s) <= length {
				return s
			}
			return s[:length] + "..."
		},
	}

	// Parse templates with the base layout
	templates["home"] = template.Must(template.New("base").Funcs(funcMap).ParseFiles(
		"templates/base.html",
		"templates/home.html",
	))

	templates["board"] = template.Must(template.New("base").Funcs(funcMap).ParseFiles(
		"templates/base.html",
		"templates/board.html",
	))

	templates["catalog"] = template.Must(template.New("base").Funcs(funcMap).ParseFiles(
		"templates/base.html",
		"templates/catalog.html",
	))

	templates["thread"] = template.Must(template.New("base").Funcs(funcMap).ParseFiles(
		"templates/base.html",
		"templates/thread.html",
	))

	templates["admin"] = template.Must(template.New("base").Funcs(funcMap).ParseFiles(
		"templates/base.html",
		"templates/admin.html",
	))

	templates["admin_boards"] = template.Must(template.New("base").Funcs(funcMap).ParseFiles(
		"templates/base.html",
		"templates/admin_boards.html",
	))
}

// RenderTemplate renders a template with given data
func RenderTemplate(w http.ResponseWriter, name string, data interface{}) {
	tmpl, ok := templates[name]
	if !ok {
		http.Error(w, "Template not found", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err := tmpl.ExecuteTemplate(w, "base", data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// HomeHandler handles the home page (list of boards)
func HomeHandler(w http.ResponseWriter, r *http.Request) {
	// Only handle the root path
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	// Get all boards
	boards, err := GetAllBoards()
	if err != nil {
		http.Error(w, "Failed to load boards", http.StatusInternalServerError)
		return
	}

	// Render the home page
	data := map[string]interface{}{
		"Title":  "Imageboard",
		"Boards": boards,
	}

	RenderTemplate(w, "home", data)
}

// BoardHandler handles displaying a board's threads
func BoardHandler(w http.ResponseWriter, r *http.Request) {
	// Get board slug from the URL
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 2 || parts[1] == "" {
		http.NotFound(w, r)
		return
	}

	slug := parts[1]

	// Get board data
	board, err := GetBoardBySlug(slug)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	// Get recent threads for this board
	threads, err := GetBoardThreads(board.ID, 20)
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	// Render the board page
	data := map[string]interface{}{
		"Title":   board.Name,
		"Board":   board,
		"Threads": threads,
	}

	RenderTemplate(w, "board", data)
}

// CatalogHandler handles displaying a board's threads in catalog view
func CatalogHandler(w http.ResponseWriter, r *http.Request) {
	// Get board slug from the URL
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 3 || parts[1] == "" {
		http.NotFound(w, r)
		return
	}

	slug := parts[1]

	// Get board data
	board, err := GetBoardBySlug(slug)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	// Get all threads for this board
	threads, err := GetBoardThreads(board.ID, 100) // Get more threads for catalog view
	if err != nil {
		http.Error(w, "Failed to load threads", http.StatusInternalServerError)
		return
	}

	// Get the first post for each thread
	type CatalogItem struct {
		Thread    Thread
		FirstPost Post
	}

	var catalogItems []CatalogItem
	for _, thread := range threads {
		firstPost, err := GetThreadFirstPost(thread.ID)
		if err == nil {
			catalogItems = append(catalogItems, CatalogItem{
				Thread:    thread,
				FirstPost: firstPost,
			})
		}
	}

	// Render the catalog page
	data := map[string]interface{}{
		"Title":        board.Name + " - Catalog",
		"Board":        board,
		"CatalogItems": catalogItems,
	}

	RenderTemplate(w, "catalog", data)
}

// ThreadHandler handles displaying a thread and its posts
func ThreadHandler(w http.ResponseWriter, r *http.Request) {
	// Get board slug and thread ID from the URL
	// Format: /board-slug/thread/123
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 || parts[2] != "thread" {
		// Check if this is the legacy format
		if parts[1] == "thread" {
			// Handle old format: /thread?id=123
			threadIDStr := r.URL.Query().Get("id")
			if threadIDStr == "" {
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			}

			threadID, err := strconv.Atoi(threadIDStr)
			if err != nil {
				http.Error(w, "Invalid thread ID", http.StatusBadRequest)
				return
			}

			// Get thread data to determine the board
			thread, _, err := GetThread(threadID)
			if err != nil {
				http.Error(w, "Thread not found", http.StatusNotFound)
				return
			}

			// Get board slug for redirect
			board, err := GetBoardByID(thread.BoardID)
			if err == nil {
				// Redirect to new URL format
				http.Redirect(w, r, "/"+board.Slug+"/thread/"+threadIDStr, http.StatusMovedPermanently)
				return
			}
		}

		http.NotFound(w, r)
		return
	}

	boardSlug := parts[1]
	threadIDStr := parts[3]

	threadID, err := strconv.Atoi(threadIDStr)
	if err != nil {
		http.Error(w, "Invalid thread ID", http.StatusBadRequest)
		return
	}

	// Get thread data and posts
	thread, posts, err := GetThread(threadID)
	if err != nil {
		http.Error(w, "Thread not found", http.StatusNotFound)
		return
	}

	// Get board data
	board, err := GetBoardByID(thread.BoardID)
	if err != nil {
		http.Error(w, "Board not found", http.StatusNotFound)
		return
	}

	// Verify board slug matches, otherwise redirect
	if boardSlug != board.Slug {
		http.Redirect(w, r, "/"+board.Slug+"/thread/"+threadIDStr, http.StatusMovedPermanently)
		return
	}

	// Render thread page
	data := map[string]interface{}{
		"Title":  thread.Title,
		"Board":  board,
		"Thread": thread,
		"Posts":  posts,
	}

	RenderTemplate(w, "thread", data)
}

// NewThreadHandler handles creating a new thread
func NewThreadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse form data
	err := r.ParseMultipartForm(10 << 20) // 10 MB max memory
	if err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}

	// Get form values
	boardIDStr := r.FormValue("board_id")
	title := r.FormValue("title")
	content := r.FormValue("content")

	boardID, err := strconv.Atoi(boardIDStr)
	if err != nil {
		http.Error(w, "Invalid board ID", http.StatusBadRequest)
		return
	}

	// Simple validation
	if title == "" || content == "" {
		http.Error(w, "Title and content are required", http.StatusBadRequest)
		return
	}

	// Handle file upload
	imagePath := ""
	file, handler, err := r.FormFile("image")
	if err == nil && handler != nil {
		defer file.Close()

		// Read file data
		buffer := make([]byte, handler.Size)
		_, err := file.Read(buffer)
		if err != nil {
			http.Error(w, "Error reading uploaded file", http.StatusInternalServerError)
			return
		}

		// Store in Redis
		filename := fmt.Sprintf("%d_%s", time.Now().UnixNano(), handler.Filename)
		err = StoreImage(filename, buffer)
		if err != nil {
			http.Error(w, "Error storing image", http.StatusInternalServerError)
			return
		}

		imagePath = filename
	}

	// Create the thread
	thread, err := CreateThread(boardID, title, content, imagePath)
	if err != nil {
		http.Error(w, "Error creating thread", http.StatusInternalServerError)
		return
	}

	// Get board slug for redirect
	board, err := GetBoardByID(boardID)
	if err != nil {
		http.Error(w, "Board not found", http.StatusInternalServerError)
		return
	}

	// Redirect to the new thread
	http.Redirect(w, r, "/"+board.Slug+"/thread/"+strconv.Itoa(thread.ID), http.StatusSeeOther)
}

// NewPostHandler handles creating a new post in a thread
func NewPostHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse form data
	err := r.ParseMultipartForm(10 << 20) // 10 MB max memory
	if err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}

	// Get thread ID and content
	threadIDStr := r.FormValue("thread_id")
	content := r.FormValue("content")

	threadID, err := strconv.Atoi(threadIDStr)
	if err != nil {
		http.Error(w, "Invalid thread ID", http.StatusBadRequest)
		return
	}

	// Simple validation
	if content == "" {
		http.Error(w, "Content is required", http.StatusBadRequest)
		return
	}

	// Handle file upload
	imagePath := ""
	file, handler, err := r.FormFile("image")
	if err == nil && handler != nil {
		defer file.Close()

		// Read file data
		buffer := make([]byte, handler.Size)
		_, err := file.Read(buffer)
		if err != nil {
			http.Error(w, "Error reading uploaded file", http.StatusInternalServerError)
			return
		}

		// Store in Redis
		filename := fmt.Sprintf("%d_%s", time.Now().UnixNano(), handler.Filename)
		err = StoreImage(filename, buffer)
		if err != nil {
			http.Error(w, "Error storing image", http.StatusInternalServerError)
			return
		}

		imagePath = filename
	}

	// Create the post
	_, err = CreatePost(threadID, content, imagePath)
	if err != nil {
		http.Error(w, "Error creating post", http.StatusInternalServerError)
		return
	}

	// Get thread to determine board for redirect
	thread, _, err := GetThread(threadID)
	if err != nil {
		http.Error(w, "Thread not found", http.StatusInternalServerError)
		return
	}

	// Get board slug for redirect
	board, err := GetBoardByID(thread.BoardID)
	if err != nil {
		http.Error(w, "Board not found", http.StatusInternalServerError)
		return
	}

	// Redirect back to the thread
	http.Redirect(w, r, "/"+board.Slug+"/thread/"+threadIDStr, http.StatusSeeOther)
}

// WipeRedisHandler clears all data from Redis
func WipeRedisHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Flush all data from Redis
	err := rdb.FlushAll(ctx).Err()
	if err != nil {
		http.Error(w, "Failed to wipe Redis: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Reset thread counts in PostgreSQL
	_, err = db.Exec("UPDATE boards SET thread_count = 0")
	if err != nil {
		log.Printf("Error resetting thread counts: %v", err)
	}

	// Log the wipe action
	log.Println("⚠️ Redis database has been wiped")

	// Redirect back to home page
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// Admin handlers
// AdminHomeHandler displays the admin dashboard
func AdminHomeHandler(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"Title": "Admin Dashboard",
	}

	RenderTemplate(w, "admin", data)
}

// AdminBoardsHandler displays the board management page
func AdminBoardsHandler(w http.ResponseWriter, r *http.Request) {
	// Get all boards
	boards, err := GetAllBoards()
	if err != nil {
		http.Error(w, "Failed to load boards", http.StatusInternalServerError)
		return
	}

	data := map[string]interface{}{
		"Title":  "Board Management",
		"Boards": boards,
	}

	RenderTemplate(w, "admin_boards", data)
}

// AdminCreateBoardHandler creates a new board
func AdminCreateBoardHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse form
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}

	slug := r.FormValue("slug")
	name := r.FormValue("name")
	description := r.FormValue("description")

	// Simple validation
	if slug == "" || name == "" {
		http.Error(w, "Slug and name are required", http.StatusBadRequest)
		return
	}

	// Create the board
	_, err = CreateBoard(slug, name, description)
	if err != nil {
		http.Error(w, "Error creating board: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Redirect back to board management
	http.Redirect(w, r, "/admin/boards", http.StatusSeeOther)
}

// AdminUpdateBoardHandler updates an existing board
func AdminUpdateBoardHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse form
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}

	boardIDStr := r.FormValue("board_id")
	name := r.FormValue("name")
	description := r.FormValue("description")

	boardID, err := strconv.Atoi(boardIDStr)
	if err != nil {
		http.Error(w, "Invalid board ID", http.StatusBadRequest)
		return
	}

	// Update the board
	err = UpdateBoard(boardID, name, description)
	if err != nil {
		http.Error(w, "Error updating board: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Redirect back to board management
	http.Redirect(w, r, "/admin/boards", http.StatusSeeOther)
}

// AdminDeleteBoardHandler deletes a board
func AdminDeleteBoardHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse form
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}

	boardIDStr := r.FormValue("board_id")
	boardID, err := strconv.Atoi(boardIDStr)
	if err != nil {
		http.Error(w, "Invalid board ID", http.StatusBadRequest)
		return
	}

	// Delete the board
	err = DeleteBoard(boardID)
	if err != nil {
		http.Error(w, "Error deleting board: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Redirect back to board management
	http.Redirect(w, r, "/admin/boards", http.StatusSeeOther)
}
