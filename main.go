package main

import (
	"log"
	"net/http"
	"os"
	"strings"
)

func main() {
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

	// Initialize templates
	InitTemplates()

	// Ensure uploads directory exists
	os.MkdirAll("uploads", 0755)

	// Set up static file server
	fs := http.FileServer(http.Dir("static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	// Set up image handler
	http.HandleFunc("/images/", ImageHandler)

	// Admin routes
	http.HandleFunc("/admin", AdminHomeHandler)
	http.HandleFunc("/admin/boards", AdminBoardsHandler)
	http.HandleFunc("/admin/create-board", AdminCreateBoardHandler)
	http.HandleFunc("/admin/update-board", AdminUpdateBoardHandler)
	http.HandleFunc("/admin/delete-board", AdminDeleteBoardHandler)
	http.HandleFunc("/admin/wipe-redis", WipeRedisHandler)

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
