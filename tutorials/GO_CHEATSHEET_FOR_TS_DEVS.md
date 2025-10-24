# Go Cheat Sheet for TypeScript Developers

A practical guide for TypeScript/Node.js developers learning Go, with special focus on code organization.

---

## Table of Contents

1. [Code Organization & Imports](#code-organization--imports) ⭐
2. [Basic Syntax](#basic-syntax)
3. [Types & Interfaces](#types--interfaces)
4. [Functions](#functions)
5. [Error Handling](#error-handling)
6. [Async/Concurrency](#asyncconcurrency)
7. [Common Patterns](#common-patterns)
8. [Package Management](#package-management)

---

## Code Organization & Imports ⭐

### TypeScript vs Go: The Big Picture

| Aspect | TypeScript | Go |
|--------|-----------|-----|
| **Module System** | ES6 modules (import/export) | Package-based |
| **File Organization** | One file = one module | One directory = one package |
| **Exports** | Explicit (`export`) | Capitalized = public |
| **Imports** | Import specific items | Import entire package |
| **Circular Deps** | Allowed (be careful!) | **Not allowed** |

### How Go Packages Work

**Key Concept:** In Go, **all files in the same directory MUST have the same `package` name** and they share the same namespace.

#### Example 1: Single Package (Current Approach)

Your current imageboard structure:
```
go-imageboard/
├── main.go           // package main
├── handlers.go       // package main
├── models.go         // package main
├── db.go            // package main
└── auth.go          // package main
```

**All files use `package main`:**

```go
// main.go
package main

func main() {
    // Can directly call functions from handlers.go, models.go, etc.
    InitDB()           // from db.go
    InitRedis()        // from models.go
    LoginHandler(...)  // from handlers.go
}
```

**No imports needed between files in the same package!** They all share the same namespace.

#### Example 2: Multi-Package Structure (Recommended for Larger Apps)

```
go-imageboard/
├── main.go
├── go.mod
├── handlers/
│   ├── thread.go      // package handlers
│   ├── board.go       // package handlers
│   └── admin.go       // package handlers
├── models/
│   ├── thread.go      // package models
│   ├── post.go        // package models
│   └── board.go       // package models
├── db/
│   ├── postgres.go    // package db
│   └── redis.go       // package db
└── auth/
    ├── session.go     // package auth
    └── middleware.go  // package auth
```

### How to Use Code from Different Packages

#### Step 1: Create a Package

**File: `models/thread.go`**
```go
package models

import "time"

// Thread represents a thread (capitalized = exported/public)
type Thread struct {
    ID        int       // Exported field (public)
    Title     string    // Exported field
    createdBy string    // Unexported field (private to package)
}

// CreateThread is an exported function (public)
func CreateThread(title string) Thread {
    return Thread{
        ID:        generateID(), // Can call unexported function in same package
        Title:     title,
        createdBy: "system",
    }
}

// generateID is unexported (private to this package)
func generateID() int {
    return int(time.Now().Unix())
}
```

**File: `models/post.go`** (same package, different file)
```go
package models

// Post represents a post
type Post struct {
    ID       int
    ThreadID int
    Content  string
}

// CreatePost can access Thread and generateID() even though
// they're in thread.go - same package!
func CreatePost(threadID int, content string) Post {
    return Post{
        ID:       generateID(), // Works! Same package
        ThreadID: threadID,
        Content:  content,
    }
}
```

#### Step 2: Import and Use

**File: `main.go`**
```go
package main

import (
    "fmt"
    "yourmodule/models"  // Import path based on go.mod
)

func main() {
    // Use exported functions (capitalized)
    thread := models.CreateThread("Hello World")
    post := models.CreatePost(thread.ID, "First post!")

    fmt.Println(thread.Title) // ✅ Works - Title is exported
    // fmt.Println(thread.createdBy) // ❌ Error - createdBy is unexported
}
```

### Import Path Rules

Your `go.mod` file defines the module name:
```go
module github.com/yourusername/go-imageboard

go 1.21
```

**Import paths are relative to module root:**

| File Location | Package Declaration | Import Path |
|--------------|-------------------|-------------|
| `models/thread.go` | `package models` | `github.com/yourusername/go-imageboard/models` |
| `handlers/thread.go` | `package handlers` | `github.com/yourusername/go-imageboard/handlers` |
| `db/postgres.go` | `package db` | `github.com/yourusername/go-imageboard/db` |

### Reorganizing Your Imageboard: Step-by-Step

#### Current Structure (Single Package)
```go
// All in package main
main.go
handlers.go
models.go
db.go
```

#### Refactored Structure (Multi-Package)

**Step 1: Create directory structure**
```bash
mkdir -p {models,handlers,db,auth,middleware}
```

**Step 2: Move code to packages**

**`models/thread.go`:**
```go
package models

import (
    "time"
    "github.com/yourusername/go-imageboard/db" // Import db package
)

type Thread struct {
    ID        int       `json:"id"`
    BoardID   int       `json:"board_id"`
    Title     string    `json:"title"`
    CreatedAt time.Time `json:"created_at"`
}

// CreateThread creates a new thread
func CreateThread(boardID int, title string) (Thread, error) {
    thread := Thread{
        BoardID:   boardID,
        Title:     title,
        CreatedAt: time.Now(),
    }

    // Use db package
    err := db.Insert("threads", thread)
    return thread, err
}
```

**`handlers/thread.go`:**
```go
package handlers

import (
    "net/http"
    "github.com/yourusername/go-imageboard/models" // Import models
)

// NewThreadHandler handles new thread creation
func NewThreadHandler(w http.ResponseWriter, r *http.Request) {
    title := r.FormValue("title")
    boardID := 1

    // Use models package
    thread, err := models.CreateThread(boardID, title)
    if err != nil {
        http.Error(w, err.Error(), 500)
        return
    }

    // ...
}
```

**`main.go`:**
```go
package main

import (
    "net/http"
    "github.com/yourusername/go-imageboard/handlers"
    "github.com/yourusername/go-imageboard/db"
)

func main() {
    // Initialize
    db.Init()

    // Register handlers from handlers package
    http.HandleFunc("/new-thread", handlers.NewThreadHandler)

    http.ListenAndServe(":8080", nil)
}
```

### Sharing Data Between Packages

#### ❌ Problem: Can't access unexported variables

```go
// db/postgres.go
package db

var connection *sql.DB // Unexported - only visible in db package

// main.go
package main

import "yourmodule/db"

func main() {
    db.connection.Query(...) // ❌ Error: connection is unexported
}
```

#### ✅ Solution 1: Export a Getter Function

```go
// db/postgres.go
package db

var connection *sql.DB // Keep private

// GetDB returns the database connection (exported)
func GetDB() *sql.DB {
    return connection
}

// main.go
package main

import "yourmodule/db"

func main() {
    db.GetDB().Query(...) // ✅ Works!
}
```

#### ✅ Solution 2: Export the Variable

```go
// db/postgres.go
package db

var DB *sql.DB // Exported (capitalized)

func Init() {
    DB = sql.Open(...)
}

// main.go
package main

import "yourmodule/db"

func main() {
    db.Init()
    db.DB.Query(...) // ✅ Works!
}
```

### TypeScript Comparison

#### TypeScript (ES6 Modules)
```typescript
// models/thread.ts
export interface Thread {
    id: number;
    title: string;
}

export function createThread(title: string): Thread {
    return { id: 1, title };
}

// Private - not exported
function generateID(): number {
    return Date.now();
}

// main.ts
import { Thread, createThread } from './models/thread';
// import { generateID } from './models/thread'; // ❌ Error - not exported

const thread = createThread("Hello");
```

#### Go Equivalent
```go
// models/thread.go
package models

type Thread struct {
    ID    int
    Title string
}

func CreateThread(title string) Thread {
    return Thread{ID: 1, Title: title}
}

// private - unexported
func generateID() int {
    return int(time.Now().Unix())
}

// main.go
package main

import "yourmodule/models"

func main() {
    thread := models.CreateThread("Hello")
}
```

### Common Patterns

#### Pattern 1: Internal Package (Go 1.4+)

Create an `internal/` directory - code inside can only be imported by parent and siblings:

```
go-imageboard/
├── internal/
│   └── helpers/
│       └── utils.go    // package helpers
├── handlers/
│   └── thread.go       // ✅ Can import ../internal/helpers
└── main.go             // ✅ Can import ./internal/helpers

some-other-project/
└── main.go             // ❌ Cannot import go-imageboard/internal/helpers
```

#### Pattern 2: Init Functions

Each package can have an `init()` function that runs automatically:

```go
// db/postgres.go
package db

var DB *sql.DB

func init() {
    // Runs automatically when package is imported
    fmt.Println("db package initialized")
}

func Init() {
    // Explicit initialization
    DB = sql.Open(...)
}
```

#### Pattern 3: Shared Types

Create a `types/` package for shared types:

```go
// types/user.go
package types

type User struct {
    ID       int
    Username string
}

// handlers/auth.go
package handlers

import "yourmodule/types"

func GetUser() types.User {
    return types.User{ID: 1, Username: "admin"}
}

// models/session.go
package models

import "yourmodule/types"

func CreateSession(user types.User) { ... }
```

---

## Basic Syntax

### Variables

```typescript
// TypeScript
let name: string = "John";
const age: number = 30;
var isActive: boolean = true;

// Type inference
let auto = "inferred"; // string
```

```go
// Go
var name string = "John"
const age = 30
var isActive bool = true

// Short declaration (only inside functions)
auto := "inferred" // string

// Multiple declarations
var (
    x int = 1
    y int = 2
)
```

### Functions

```typescript
// TypeScript
function greet(name: string): string {
    return `Hello, ${name}`;
}

const add = (a: number, b: number): number => {
    return a + b;
};
```

```go
// Go
func greet(name string) string {
    return fmt.Sprintf("Hello, %s", name)
}

// Multiple return values (common in Go)
func divide(a, b int) (int, error) {
    if b == 0 {
        return 0, errors.New("division by zero")
    }
    return a / b, nil
}
```

### Arrays & Slices

```typescript
// TypeScript
const numbers: number[] = [1, 2, 3];
numbers.push(4);

const users: User[] = [];
```

```go
// Go
// Array (fixed size)
var numbers [3]int = [3]int{1, 2, 3}

// Slice (dynamic - like TS arrays)
var users []User = []User{}
users = append(users, User{ID: 1})

// Make slice with capacity
numbers := make([]int, 0, 10) // length 0, capacity 10
```

### Objects & Structs

```typescript
// TypeScript
interface User {
    id: number;
    name: string;
    email?: string; // Optional
}

const user: User = {
    id: 1,
    name: "John"
};
```

```go
// Go
type User struct {
    ID    int
    Name  string
    Email *string // Pointer = optional
}

user := User{
    ID:   1,
    Name: "John",
}

// With optional email
email := "john@example.com"
user2 := User{
    ID:    2,
    Name:  "Jane",
    Email: &email,
}
```

### Loops

```typescript
// TypeScript
// For loop
for (let i = 0; i < 10; i++) {
    console.log(i);
}

// For...of
for (const item of items) {
    console.log(item);
}

// While
while (condition) {
    // ...
}
```

```go
// Go (only "for", no while)
// Classic for
for i := 0; i < 10; i++ {
    fmt.Println(i)
}

// Range (like for...of)
for index, item := range items {
    fmt.Println(index, item)
}

// Just values
for _, item := range items {
    fmt.Println(item)
}

// While equivalent
for condition {
    // ...
}

// Infinite loop
for {
    // ...
    if done {
        break
    }
}
```

---

## Types & Interfaces

### Interfaces

```typescript
// TypeScript
interface Writer {
    write(data: string): void;
}

class FileWriter implements Writer {
    write(data: string): void {
        // ...
    }
}
```

```go
// Go (implicit implementation)
type Writer interface {
    Write(data string) error
}

type FileWriter struct {
    path string
}

// No "implements" keyword needed!
// FileWriter implements Writer automatically
func (fw FileWriter) Write(data string) error {
    // ...
    return nil
}
```

### Type Assertions

```typescript
// TypeScript
const value: any = "hello";
const str = value as string;

if (typeof value === "string") {
    // ...
}
```

```go
// Go
var value interface{} = "hello"

// Type assertion
str := value.(string)

// Safe type assertion
str, ok := value.(string)
if ok {
    // value is a string
}

// Type switch
switch v := value.(type) {
case string:
    fmt.Println("String:", v)
case int:
    fmt.Println("Int:", v)
default:
    fmt.Println("Unknown type")
}
```

### Generics (Go 1.18+)

```typescript
// TypeScript
function first<T>(arr: T[]): T {
    return arr[0];
}

const num = first<number>([1, 2, 3]);
```

```go
// Go 1.18+
func First[T any](arr []T) T {
    return arr[0]
}

num := First([]int{1, 2, 3})

// With constraints
func Sum[T int | float64](a, b T) T {
    return a + b
}
```

---

## Error Handling

### The Go Way

```typescript
// TypeScript (exceptions)
try {
    const data = readFile("file.txt");
    processData(data);
} catch (error) {
    console.error("Error:", error);
}
```

```go
// Go (explicit error handling)
data, err := readFile("file.txt")
if err != nil {
    log.Printf("Error: %v", err)
    return
}

err = processData(data)
if err != nil {
    return err
}
```

### Creating Errors

```typescript
// TypeScript
throw new Error("Something went wrong");
```

```go
// Go
import "errors"

// Simple error
return errors.New("something went wrong")

// Formatted error
return fmt.Errorf("user %d not found", userID)

// Custom error type
type NotFoundError struct {
    Resource string
}

func (e NotFoundError) Error() string {
    return fmt.Sprintf("%s not found", e.Resource)
}

return NotFoundError{Resource: "User"}
```

---

## Async/Concurrency

### Promises vs Goroutines

```typescript
// TypeScript (Promises)
async function fetchUser(id: number): Promise<User> {
    const response = await fetch(`/api/users/${id}`);
    return await response.json();
}

// Promise.all
const [user1, user2] = await Promise.all([
    fetchUser(1),
    fetchUser(2)
]);
```

```go
// Go (Goroutines + Channels)
func fetchUser(id int, ch chan<- User) {
    // Fetch user...
    ch <- user
}

// Concurrent execution
ch := make(chan User, 2)

go fetchUser(1, ch) // Start goroutine
go fetchUser(2, ch) // Start another

user1 := <-ch // Receive from channel
user2 := <-ch // Receive from channel

// Or use WaitGroup
var wg sync.WaitGroup
wg.Add(2)

go func() {
    defer wg.Done()
    fetchUser(1, ch)
}()

go func() {
    defer wg.Done()
    fetchUser(2, ch)
}()

wg.Wait() // Wait for all goroutines
```

### setTimeout vs time.After

```typescript
// TypeScript
setTimeout(() => {
    console.log("Delayed");
}, 1000);
```

```go
// Go
time.Sleep(1 * time.Second)
fmt.Println("Delayed")

// Or with goroutine
go func() {
    time.Sleep(1 * time.Second)
    fmt.Println("Delayed")
}()

// Or with channel
select {
case <-time.After(1 * time.Second):
    fmt.Println("Timeout")
}
```

---

## Common Patterns

### Nullable/Optional Values

```typescript
// TypeScript
let name: string | null = null;
const email?: string;

// Nullish coalescing
const displayName = name ?? "Guest";
```

```go
// Go (use pointers for nullable)
var name *string = nil

email := "test@example.com"
var nullableEmail *string = &email

// Check for nil
if name != nil {
    fmt.Println(*name) // Dereference
} else {
    fmt.Println("Guest")
}
```

### Destructuring

```typescript
// TypeScript
const { id, name } = user;
const [first, second] = array;
```

```go
// Go (no destructuring, but multiple assignment)
id := user.ID
name := user.Name

// Multiple assignment
first, second := array[0], array[1]

// From function returns
user, err := getUser(1)
```

### Default Parameters

```typescript
// TypeScript
function greet(name: string = "Guest"): string {
    return `Hello, ${name}`;
}
```

```go
// Go (no default params, use options pattern)
type GreetOptions struct {
    Name string
}

func Greet(opts *GreetOptions) string {
    name := "Guest"
    if opts != nil && opts.Name != "" {
        name = opts.Name
    }
    return fmt.Sprintf("Hello, %s", name)
}

// Usage
Greet(nil) // "Hello, Guest"
Greet(&GreetOptions{Name: "John"}) // "Hello, John"

// Or functional options
type Option func(*GreetOptions)

func WithName(name string) Option {
    return func(o *GreetOptions) {
        o.Name = name
    }
}

func Greet(opts ...Option) string {
    config := &GreetOptions{Name: "Guest"}
    for _, opt := range opts {
        opt(config)
    }
    return fmt.Sprintf("Hello, %s", config.Name)
}

// Usage
Greet() // "Hello, Guest"
Greet(WithName("John")) // "Hello, John"
```

---

## Package Management

### npm vs go modules

```bash
# TypeScript/npm
npm init
npm install express
npm install --save-dev @types/node

# package.json
{
  "dependencies": {
    "express": "^4.18.0"
  }
}
```

```bash
# Go
go mod init github.com/username/project
go get github.com/gorilla/mux
go get -u github.com/lib/pq  # -u = update

# go.mod (auto-generated)
module github.com/username/project

go 1.21

require (
    github.com/gorilla/mux v1.8.0
)
```

### Common Commands

| Task | npm | Go |
|------|-----|-----|
| Initialize | `npm init` | `go mod init <module>` |
| Install package | `npm install <pkg>` | `go get <pkg>` |
| Install all deps | `npm install` | `go mod download` |
| Update deps | `npm update` | `go get -u ./...` |
| Remove unused | `npm prune` | `go mod tidy` |
| Run script | `npm run dev` | `go run .` |
| Build | `npm run build` | `go build` |
| Test | `npm test` | `go test ./...` |

---

## Quick Reference Card

```
┌─────────────────────────────────────────────────────────┐
│              TypeScript → Go Quick Guide                │
├─────────────────────────────────────────────────────────┤
│ let/const         →  var / := (inside functions)       │
│ interface         →  type (struct or interface)         │
│ class             →  struct + methods                   │
│ async/await       →  goroutines + channels             │
│ Promise           →  channel                            │
│ try/catch         →  if err != nil                     │
│ null/undefined    →  nil                                │
│ export            →  Capital letter (public)            │
│ import {...}      →  import "package"                  │
│ any               →  interface{} or any (Go 1.18+)     │
│ Array<T>          →  []T (slice)                       │
│ [T, U]            →  struct{First T; Second U}         │
│ Record<K,V>       →  map[K]V                           │
│ typeof            →  reflect.TypeOf (avoid!)           │
│ this              →  receiver (implicit parameter)     │
│ ...rest           →  ...args                           │
└─────────────────────────────────────────────────────────┘
```

---

## Pro Tips

1. **Use `gofmt`** - Auto-format code (like Prettier):
   ```bash
   gofmt -w .
   ```

2. **Use `golangci-lint`** - Comprehensive linter (like ESLint):
   ```bash
   golangci-lint run
   ```

3. **Avoid `interface{}`** - Use concrete types when possible

4. **Accept interfaces, return structs** - Design principle

5. **Prefer composition over inheritance** - No classes, use embedding:
   ```go
   type Animal struct {
       Name string
   }

   type Dog struct {
       Animal // Embedded struct (like extending)
       Breed string
   }

   dog := Dog{
       Animal: Animal{Name: "Buddy"},
       Breed:  "Golden Retriever",
   }
   fmt.Println(dog.Name) // Access embedded field directly
   ```

6. **Use context.Context for cancellation**:
   ```go
   ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
   defer cancel()

   result, err := doSomethingWithContext(ctx)
   ```

7. **Defer is your friend** - Like `finally` but cleaner:
   ```go
   file, err := os.Open("file.txt")
   if err != nil {
       return err
   }
   defer file.Close() // Runs when function returns

   // Work with file...
   ```

---

## Resources

- [Go by Example](https://gobyexample.com/) - Practical examples
- [Effective Go](https://go.dev/doc/effective_go) - Official style guide
- [Go Playground](https://play.golang.org/) - Online REPL
- [Go Module Reference](https://go.dev/ref/mod) - Module documentation

---

**Happy Gophering! 🐹**
