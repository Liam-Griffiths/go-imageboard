package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
)

var (
	rdb *redis.Client
	ctx = context.Background()
)

// Thread represents an imageboard thread
type Thread struct {
	ID        int       `json:"id"`
	BoardID   int       `json:"board_id"`
	Title     string    `json:"title"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	PostCount int       `json:"post_count"`
}

// Post represents a post within a thread
type Post struct {
	ID        int       `json:"id"`
	ThreadID  int       `json:"thread_id"`
	Content   string    `json:"content"`
	ImagePath string    `json:"image_path,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// InitRedis initializes the Redis connection
func InitRedis() error {
	// Get Redis address from environment variable or use default
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "localhost:6379"
	}

	rdb = redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Password: "", // no password by default
		DB:       0,  // use default DB
	})

	// Check connection
	_, err := rdb.Ping(ctx).Result()
	return err
}

// GetNextID returns the next available ID for a given sequence
func GetNextID(key string) (int, error) {
	id, err := rdb.Incr(ctx, key).Result()
	return int(id), err
}

// CreateThread creates a new thread and initial post
func CreateThread(boardID int, title, content, imagePath string) (Thread, error) {
	// Get next thread ID
	threadID, err := GetNextID("global:nextThreadID")
	if err != nil {
		return Thread{}, err
	}

	now := time.Now()
	thread := Thread{
		ID:        threadID,
		BoardID:   boardID,
		Title:     title,
		CreatedAt: now,
		UpdatedAt: now,
		PostCount: 1, // Initial post
	}

	// Save thread data
	threadKey := fmt.Sprintf("thread:%d", threadID)
	threadJSON, _ := json.Marshal(thread)
	err = rdb.Set(ctx, threadKey, threadJSON, 0).Err()
	if err != nil {
		return Thread{}, err
	}

	// Add to board's thread index
	boardThreadsKey := fmt.Sprintf("board:%d:threads", boardID)
	err = rdb.ZAdd(ctx, boardThreadsKey, &redis.Z{
		Score:  float64(now.Unix()),
		Member: threadID,
	}).Err()
	if err != nil {
		return Thread{}, err
	}

	// Add to global thread index (for legacy compatibility)
	err = rdb.ZAdd(ctx, "threads:by_time", &redis.Z{
		Score:  float64(now.Unix()),
		Member: threadID,
	}).Err()
	if err != nil {
		return Thread{}, err
	}

	// Insert the thread into PostgreSQL for reference
	_, err = db.Exec("INSERT INTO threads (id, board_id, created_at) VALUES ($1, $2, $3)",
		threadID, boardID, now)
	if err != nil {
		// Log error but don't fail the thread creation
		fmt.Printf("Error inserting thread reference into PostgreSQL: %v\n", err)
	}

	// Create initial post
	_, err = CreatePost(threadID, content, imagePath)
	if err != nil {
		return Thread{}, err
	}

	// Update thread count in Postgres
	err = IncrementBoardThreadCount(boardID)
	if err != nil {
		// Log error but don't fail the thread creation
		fmt.Printf("Error incrementing board thread count: %v\n", err)
	}

	return thread, nil
}

// CreatePost adds a new post to an existing thread
func CreatePost(threadID int, content string, imagePath string) (Post, error) {
	// Check if thread exists
	threadKey := fmt.Sprintf("thread:%d", threadID)
	exists, err := rdb.Exists(ctx, threadKey).Result()
	if err != nil {
		return Post{}, err
	}
	if exists == 0 {
		return Post{}, fmt.Errorf("thread %d not found", threadID)
	}

	// Get next post ID
	postID, err := GetNextID("global:nextPostID")
	if err != nil {
		return Post{}, err
	}

	now := time.Now()
	post := Post{
		ID:        postID,
		ThreadID:  threadID,
		Content:   content,
		ImagePath: imagePath,
		CreatedAt: now,
	}

	// Save post data
	postKey := fmt.Sprintf("post:%d", postID)
	postJSON, _ := json.Marshal(post)
	err = rdb.Set(ctx, postKey, postJSON, 0).Err()
	if err != nil {
		return Post{}, err
	}

	// Add to thread's posts list
	postsKey := fmt.Sprintf("thread:%d:posts", threadID)
	err = rdb.RPush(ctx, postsKey, postID).Err()
	if err != nil {
		return Post{}, err
	}

	// Update thread's updated_at time and post count
	var thread Thread
	threadData, err := rdb.Get(ctx, threadKey).Result()
	if err != nil {
		return Post{}, err
	}

	err = json.Unmarshal([]byte(threadData), &thread)
	if err != nil {
		return Post{}, err
	}

	thread.UpdatedAt = now
	thread.PostCount++

	threadJSON, _ := json.Marshal(thread)
	err = rdb.Set(ctx, threadKey, threadJSON, 0).Err()
	if err != nil {
		return Post{}, err
	}

	// Update thread ranking in the board's sorted set
	boardThreadsKey := fmt.Sprintf("board:%d:threads", thread.BoardID)
	err = rdb.ZAdd(ctx, boardThreadsKey, &redis.Z{
		Score:  float64(now.Unix()),
		Member: threadID,
	}).Err()
	if err != nil {
		return Post{}, err
	}

	// Update thread ranking in the global sorted set (for legacy compatibility)
	err = rdb.ZAdd(ctx, "threads:by_time", &redis.Z{
		Score:  float64(now.Unix()),
		Member: threadID,
	}).Err()

	return post, err
}

// GetThread retrieves a thread and all its posts
func GetThread(threadID int) (Thread, []Post, error) {
	var thread Thread
	var posts []Post

	// Get thread data
	threadKey := fmt.Sprintf("thread:%d", threadID)
	threadData, err := rdb.Get(ctx, threadKey).Result()
	if err != nil {
		return thread, nil, err
	}

	err = json.Unmarshal([]byte(threadData), &thread)
	if err != nil {
		return thread, nil, err
	}

	// Get post IDs for this thread
	postsKey := fmt.Sprintf("thread:%d:posts", threadID)
	postIDs, err := rdb.LRange(ctx, postsKey, 0, -1).Result()
	if err != nil {
		return thread, nil, err
	}

	// Get each post
	for _, postIDStr := range postIDs {
		postID, _ := strconv.Atoi(postIDStr)
		postKey := fmt.Sprintf("post:%d", postID)

		postData, err := rdb.Get(ctx, postKey).Result()
		if err != nil {
			continue // Skip posts that can't be retrieved
		}

		var post Post
		err = json.Unmarshal([]byte(postData), &post)
		if err != nil {
			continue
		}

		posts = append(posts, post)
	}

	return thread, posts, nil
}

// GetBoardThreads retrieves the most recently updated threads for a specific board
func GetBoardThreads(boardID int, limit int) ([]Thread, error) {
	var threads []Thread

	// Get board's thread IDs
	boardThreadsKey := fmt.Sprintf("board:%d:threads", boardID)
	threadIDs, err := rdb.ZRevRange(ctx, boardThreadsKey, 0, int64(limit-1)).Result()
	if err != nil {
		return nil, err
	}

	// Get each thread
	for _, threadIDStr := range threadIDs {
		threadID, _ := strconv.Atoi(threadIDStr)
		threadKey := fmt.Sprintf("thread:%d", threadID)

		threadData, err := rdb.Get(ctx, threadKey).Result()
		if err != nil {
			continue
		}

		var thread Thread
		err = json.Unmarshal([]byte(threadData), &thread)
		if err != nil {
			continue
		}

		threads = append(threads, thread)
	}

	return threads, nil
}

// GetRecentThreads retrieves the most recently updated threads (across all boards)
func GetRecentThreads(limit int) ([]Thread, error) {
	var threads []Thread

	// Get recent thread IDs
	threadIDs, err := rdb.ZRevRange(ctx, "threads:by_time", 0, int64(limit-1)).Result()
	if err != nil {
		return nil, err
	}

	// Get each thread
	for _, threadIDStr := range threadIDs {
		threadID, _ := strconv.Atoi(threadIDStr)
		threadKey := fmt.Sprintf("thread:%d", threadID)

		threadData, err := rdb.Get(ctx, threadKey).Result()
		if err != nil {
			continue
		}

		var thread Thread
		err = json.Unmarshal([]byte(threadData), &thread)
		if err != nil {
			continue
		}

		threads = append(threads, thread)
	}

	return threads, nil
}

// StoreImage saves an image to Redis
func StoreImage(filename string, data []byte) error {
	imageKey := fmt.Sprintf("image:%s", filename)
	return rdb.Set(ctx, imageKey, data, 0).Err()
}

// GetImage retrieves an image from Redis
func GetImage(filename string) ([]byte, error) {
	imageKey := fmt.Sprintf("image:%s", filename)
	return rdb.Get(ctx, imageKey).Bytes()
}

// ImageHandler serves images from Redis
func ImageHandler(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Path[len("/images/"):]

	if filename == "" {
		http.Error(w, "Image not found", http.StatusNotFound)
		return
	}

	data, err := GetImage(filename)
	if err != nil {
		http.Error(w, "Image not found", http.StatusNotFound)
		return
	}

	// Set appropriate content type based on file extension
	contentType := "image/jpeg" // Default
	if strings.HasSuffix(filename, ".png") {
		contentType = "image/png"
	} else if strings.HasSuffix(filename, ".gif") {
		contentType = "image/gif"
	}

	w.Header().Set("Content-Type", contentType)
	w.Write(data)
}

// IncrementBoardThreadCount increments the thread count for a board in PostgreSQL
func IncrementBoardThreadCount(boardID int) error {
	// Check if the board exists first
	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM boards WHERE id = $1)", boardID).Scan(&exists)
	if err != nil {
		return err
	}

	if !exists {
		return fmt.Errorf("board with ID %d does not exist", boardID)
	}

	// Update the board's thread count
	_, err = db.Exec("UPDATE boards SET thread_count = thread_count + 1, updated_at = NOW() WHERE id = $1", boardID)
	return err
}

// GetThreadFirstPost retrieves the first post of a thread
func GetThreadFirstPost(threadID int) (Post, error) {
	var post Post

	// Get post IDs for this thread
	postsKey := fmt.Sprintf("thread:%d:posts", threadID)
	postIDs, err := rdb.LRange(ctx, postsKey, 0, 0).Result() // Just get the first one
	if err != nil || len(postIDs) == 0 {
		return post, fmt.Errorf("first post not found for thread %d", threadID)
	}

	postID, _ := strconv.Atoi(postIDs[0])
	postKey := fmt.Sprintf("post:%d", postID)

	postData, err := rdb.Get(ctx, postKey).Result()
	if err != nil {
		return post, err
	}

	err = json.Unmarshal([]byte(postData), &post)
	return post, err
}
