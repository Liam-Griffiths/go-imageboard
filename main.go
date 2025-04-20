package main

import (
	"log"
	"net/http"
	"os"
	"strings"
)

// createDefaultAdminUser creates a default admin user if none exists
func createDefaultAdminUser() {
	// Check if any admin users exist
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM admin_users").Scan(&count)
	if err != nil {
		log.Printf("Error checking admin users: %v", err)
		return
	}

	// If no admin users exist, create a default one
	if count == 0 {
		_, err := CreateAdminUser("admin", "admin123")
		if err != nil {
			log.Printf("Error creating default admin user: %v", err)
			return
		}
		log.Println("Created default admin user: admin / admin123")
	}
}

func main() {
	// Load environment variables from .env file
	LoadEnv()

	// Initialize PostgreSQL connection
	err := InitDB()
	if err != nil {
		log.Fatalf("Failed to connect to PostgreSQL: %v", err)
	}

	// Initialize Redis connection
	err = InitRedis()
	if err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}

	// Create default admin user
	createDefaultAdminUser()

	// Initialize templates
	InitTemplates()

	// Ensure uploads directory exists
	os.MkdirAll("uploads", 0755)

	// Set up static file server
	fs := http.FileServer(http.Dir("static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	// Set up image handler
	http.HandleFunc("/images/", ImageHandler)

	// Auth routes
	http.HandleFunc("/login", LoginHandler)
	http.HandleFunc("/logout", LogoutHandler)

	// Admin routes
	http.HandleFunc("/admin", AdminHomeHandler)
	http.HandleFunc("/admin/boards", AdminBoardsHandler)
	http.HandleFunc("/admin/create-board", AdminCreateBoardHandler)
	http.HandleFunc("/admin/update-board", AdminUpdateBoardHandler)
	http.HandleFunc("/admin/delete-board", AdminDeleteBoardHandler)
	http.HandleFunc("/admin/delete-thread", AdminDeleteThreadHandler)
	http.HandleFunc("/admin/delete-post", AdminDeletePostHandler)
	http.HandleFunc("/admin/wipe-redis", WipeRedisHandler)

	// Captcha route
	http.HandleFunc("/captcha", CaptchaHandler)

	// Post creation routes
	http.HandleFunc("/new-thread", NewThreadHandler)
	http.HandleFunc("/new-post", NewPostHandler)

	// Home and board routes - this must be last as it handles path-based routing
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Root path shows home page
		if r.URL.Path == "/" {
			HomeHandler(w, r)
			return
		}

		// Split the path
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) == 0 {
			http.NotFound(w, r)
			return
		}

		boardSlug := parts[0]

		// Handle legacy routes
		if boardSlug == "thread" {
			ThreadHandler(w, r)
			return
		}

		// Handle catalog view
		if len(parts) >= 2 && parts[1] == "catalog" {
			CatalogHandler(w, r)
			return
		}

		// Handle thread view
		if len(parts) >= 3 && parts[1] == "thread" {
			ThreadHandler(w, r)
			return
		}

		// Handle board view (default)
		BoardHandler(w, r)
	})

	// Start HTTP server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Server starting on http://localhost:%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
