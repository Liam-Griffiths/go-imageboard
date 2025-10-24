# Go Concurrency Guide for Node.js Developers

A comprehensive guide to Go's concurrency model (goroutines, channels, mutexes) compared to Node.js promises and async patterns.

---

## Table of Contents

1. [Fundamental Differences](#fundamental-differences)
2. [Goroutines vs Promises](#goroutines-vs-promises)
3. [Channels - Go's Communication Primitive](#channels)
4. [Select Statement - Like Promise.race](#select-statement)
5. [Mutexes - Protecting Shared Data](#mutexes)
6. [WaitGroups - Like Promise.all](#waitgroups)
7. [Real-World Examples](#real-world-examples)
8. [Common Patterns](#common-patterns)
9. [Pitfalls & Best Practices](#pitfalls--best-practices)

---

## Fundamental Differences

### Node.js Concurrency Model

```
┌─────────────────────────────────────────────┐
│         Node.js (Event Loop)                │
├─────────────────────────────────────────────┤
│ • Single-threaded event loop                │
│ • Non-blocking I/O with callbacks           │
│ • Promises for async operations             │
│ • async/await syntactic sugar               │
│ • Everything runs on ONE thread             │
└─────────────────────────────────────────────┘
```

**Node.js Example:**
```javascript
// All runs on single thread, but non-blocking
async function fetchUsers() {
    const user1 = await fetch('/api/users/1'); // Pauses here
    const user2 = await fetch('/api/users/2'); // Then pauses here
    return [user1, user2];
}
// Total time: ~200ms (sequential)
```

### Go Concurrency Model

```
┌─────────────────────────────────────────────┐
│         Go (CSP - Communicating            │
│         Sequential Processes)               │
├─────────────────────────────────────────────┤
│ • Multiple goroutines (lightweight threads) │
│ • True parallelism on multiple cores        │
│ • Channels for communication                │
│ • Synchronous by default (no callbacks)     │
│ • Can run on MULTIPLE threads               │
└─────────────────────────────────────────────┘
```

**Go Example:**
```go
// Runs on multiple goroutines (can use multiple CPU cores)
func fetchUsers() ([]User, error) {
    ch := make(chan User, 2)

    go func() { ch <- fetchUser(1) }() // Start goroutine
    go func() { ch <- fetchUser(2) }() // Start another

    user1 := <-ch // Receive from channel
    user2 := <-ch // Receive from channel

    return []User{user1, user2}, nil
}
// Total time: ~100ms (parallel!)
```

### Key Difference: Concurrency vs Parallelism

**Node.js:**
- **Concurrent** but NOT parallel
- One task at a time, switches between tasks when waiting for I/O
- Like a chef cooking multiple dishes, but can only stir one pot at a time

**Go:**
- **Concurrent AND parallel**
- Multiple tasks running simultaneously on different CPU cores
- Like multiple chefs each cooking their own dish at the same time

---

## Goroutines vs Promises

### Example 1: Basic Async Operation

#### Node.js (Promise)
```javascript
// Returns a Promise that resolves later
function fetchUser(id) {
    return new Promise((resolve, reject) => {
        setTimeout(() => {
            resolve({ id, name: `User ${id}` });
        }, 100);
    });
}

// Usage
fetchUser(1).then(user => {
    console.log(user);
});

// Or with async/await
async function main() {
    const user = await fetchUser(1);
    console.log(user);
}
```

#### Go (Goroutine + Channel)
```go
// Goroutines don't return values - they communicate via channels
func fetchUser(id int, ch chan<- User) {
    time.Sleep(100 * time.Millisecond)
    ch <- User{ID: id, Name: fmt.Sprintf("User %d", id)}
}

// Usage
func main() {
    ch := make(chan User)

    go fetchUser(1, ch) // Start goroutine (non-blocking)

    user := <-ch // Wait for result (blocking)
    fmt.Println(user)
}
```

### Example 2: Multiple Parallel Operations

#### Node.js (Promise.all)
```javascript
// Start all promises concurrently, wait for all to finish
async function getAllUsers() {
    const promises = [
        fetchUser(1),
        fetchUser(2),
        fetchUser(3),
    ];

    const users = await Promise.all(promises);
    console.log('All users:', users);
}

// Time: ~100ms (all run concurrently in event loop)
```

#### Go (Multiple Goroutines + Channel)
```go
func getAllUsers() []User {
    ch := make(chan User, 3) // Buffered channel

    // Start all goroutines
    go fetchUser(1, ch)
    go fetchUser(2, ch)
    go fetchUser(3, ch)

    // Collect results
    users := make([]User, 3)
    for i := 0; i < 3; i++ {
        users[i] = <-ch
    }

    return users
}

// Time: ~100ms (all run in parallel on different cores)
```

**Key Insight:**
- **Node.js Promise.all**: Concurrent but on single thread (multiplexing)
- **Go goroutines**: Truly parallel across multiple CPU cores

---

## Channels

Channels are Go's primary way to communicate between goroutines. Think of them as **type-safe queues** that goroutines can send and receive data through.

### The Problem: How Do Goroutines Return Values?

In Node.js, functions return Promises. In Go, goroutines **don't return anything** - they're fire-and-forget!

```go
// ❌ This doesn't work - goroutines don't return values
func fetchUser(id int) User {
    // ...
}

result := go fetchUser(1) // ❌ Syntax error!
```

**Solution: Use channels to communicate**

```go
// ✅ This works - communicate via channel
func fetchUser(id int, ch chan<- User) {
    user := User{ID: id, Name: "John"}
    ch <- user // Send to channel
}

ch := make(chan User)
go fetchUser(1, ch)
user := <-ch // Receive from channel
```

### Channel Basics

```go
// Create channel
ch := make(chan string)

// Send to channel (blocks until someone receives)
ch <- "hello"

// Receive from channel (blocks until someone sends)
message := <-ch

// Buffered channel (doesn't block until buffer is full)
ch := make(chan string, 10) // Buffer of 10

// Close channel (no more sends allowed)
close(ch)

// Check if channel is closed
value, ok := <-ch
if !ok {
    // Channel is closed
}
```

### Practical Example: Image Upload Service

#### Node.js Version
```javascript
// Upload 5 images sequentially
async function uploadImages(images) {
    const results = [];

    for (const image of images) {
        const url = await uploadToBunnyCDN(image);
        results.push(url);
    }

    return results;
}
// Time: 5 × 1000ms = 5 seconds

// Upload in parallel with Promise.all
async function uploadImagesParallel(images) {
    const promises = images.map(img => uploadToBunnyCDN(img));
    return await Promise.all(promises);
}
// Time: ~1 second (all at once, but on single thread)
```

#### Go Version
```go
// Upload 5 images in parallel
func uploadImages(images []Image) []string {
    ch := make(chan string, len(images))

    // Start goroutine for each upload
    for _, img := range images {
        go func(image Image) {
            url := uploadToBunnyCDN(image)
            ch <- url
        }(img) // Pass img as parameter (important!)
    }

    // Collect results
    results := make([]string, len(images))
    for i := 0; i < len(images); i++ {
        results[i] = <-ch
    }

    return results
}
// Time: ~1 second (truly parallel on multiple cores)
```

### Channel Patterns

#### Pattern 1: Pipeline

```javascript
// Node.js - chaining promises
fetch('/api/users')
    .then(response => response.json())
    .then(users => filterActiveUsers(users))
    .then(activeUsers => saveToDatabase(activeUsers))
    .catch(error => console.error(error));
```

```go
// Go - channel pipeline
func pipeline() {
    // Stage 1: Fetch users
    usersCh := make(chan []User)
    go func() {
        users := fetchUsers()
        usersCh <- users
    }()

    // Stage 2: Filter active users
    activeCh := make(chan []User)
    go func() {
        users := <-usersCh
        active := filterActiveUsers(users)
        activeCh <- active
    }()

    // Stage 3: Save to database
    go func() {
        active := <-activeCh
        saveToDatabase(active)
    }()
}
```

#### Pattern 2: Fan-Out, Fan-In

Process multiple items concurrently, then collect results.

```go
func processImages(images []string) []ProcessedImage {
    // Fan-out: Start worker goroutines
    resultCh := make(chan ProcessedImage, len(images))

    for _, img := range images {
        go func(imagePath string) {
            processed := processImage(imagePath) // Heavy operation
            resultCh <- processed
        }(img)
    }

    // Fan-in: Collect all results
    results := make([]ProcessedImage, len(images))
    for i := 0; i < len(images); i++ {
        results[i] = <-resultCh
    }

    return results
}
```

---

## Select Statement

The `select` statement is like **Promise.race()** - it waits on multiple channel operations and proceeds with whichever happens first.

### Node.js: Promise.race
```javascript
const timeout = new Promise((_, reject) =>
    setTimeout(() => reject('Timeout!'), 5000)
);

const fetchData = fetch('/api/data');

try {
    const result = await Promise.race([fetchData, timeout]);
    console.log(result);
} catch (error) {
    console.error(error); // "Timeout!" if fetch takes > 5s
}
```

### Go: Select
```go
func fetchWithTimeout() (Data, error) {
    dataCh := make(chan Data)

    // Start fetch in goroutine
    go func() {
        data := fetchData()
        dataCh <- data
    }()

    // Wait for either data or timeout
    select {
    case data := <-dataCh:
        return data, nil
    case <-time.After(5 * time.Second):
        return Data{}, errors.New("timeout")
    }
}
```

### Select with Multiple Channels

```go
func worker() {
    dataCh := make(chan Data)
    errorCh := make(chan error)
    quitCh := make(chan bool)

    go doWork(dataCh, errorCh)

    for {
        select {
        case data := <-dataCh:
            fmt.Println("Received data:", data)

        case err := <-errorCh:
            fmt.Println("Error:", err)
            return

        case <-quitCh:
            fmt.Println("Quitting...")
            return

        case <-time.After(30 * time.Second):
            fmt.Println("No activity for 30s")
        }
    }
}
```

### Practical Example: Rate Limiter

```go
// Allow 5 requests per second
func rateLimiter() {
    ticker := time.NewTicker(200 * time.Millisecond) // 5 per second
    defer ticker.Stop()

    requests := make(chan int)

    for i := 1; i <= 20; i++ {
        requests <- i
    }
    close(requests)

    for req := range requests {
        <-ticker.C // Wait for next tick
        fmt.Println("Processing request", req)
    }
}
```

---

## Mutexes

Mutexes protect shared data from race conditions when multiple goroutines access it.

### The Problem: Race Conditions

```go
// ❌ DANGER: Race condition!
var counter int = 0

func increment() {
    for i := 0; i < 1000; i++ {
        counter++ // Not atomic! Can be corrupted
    }
}

func main() {
    go increment()
    go increment()
    go increment()

    time.Sleep(1 * time.Second)
    fmt.Println(counter) // Expected: 3000, Actual: ???
}
// Output: 2847 (race condition - different each time!)
```

**Why?** The operation `counter++` is actually 3 steps:
1. Read current value
2. Add 1
3. Write new value

When two goroutines do this simultaneously, they can overwrite each other's changes!

### Solution 1: Mutex (Mutual Exclusion Lock)

```go
// ✅ SAFE: Using mutex
var counter int = 0
var mu sync.Mutex

func increment() {
    for i := 0; i < 1000; i++ {
        mu.Lock()   // Acquire lock
        counter++   // Only one goroutine can be here
        mu.Unlock() // Release lock
    }
}

func main() {
    go increment()
    go increment()
    go increment()

    time.Sleep(1 * time.Second)
    fmt.Println(counter) // Always 3000!
}
```

### Mutex vs Node.js

**Node.js doesn't need mutexes** because it's single-threaded!

```javascript
// No race condition in Node.js (single thread)
let counter = 0;

async function increment() {
    for (let i = 0; i < 1000; i++) {
        counter++; // Safe! Only one thing runs at a time
    }
}

// Even with Promise.all, it's safe
await Promise.all([
    increment(),
    increment(),
    increment(),
]);

console.log(counter); // Always 3000
```

But if you use worker threads:
```javascript
// With worker threads - need synchronization!
const { Worker } = require('worker_threads');

// Would need SharedArrayBuffer + Atomics
// (Go's mutexes are much simpler!)
```

### Practical Example: Shared Cache

```go
type Cache struct {
    mu    sync.RWMutex
    items map[string]string
}

func NewCache() *Cache {
    return &Cache{
        items: make(map[string]string),
    }
}

// Write requires exclusive lock
func (c *Cache) Set(key, value string) {
    c.mu.Lock()
    defer c.mu.Unlock()
    c.items[key] = value
}

// Read allows multiple readers
func (c *Cache) Get(key string) (string, bool) {
    c.mu.RLock() // Read lock (multiple readers OK)
    defer c.mu.RUnlock()
    value, ok := c.items[key]
    return value, ok
}

// Usage
func main() {
    cache := NewCache()

    // Multiple goroutines can safely access cache
    go cache.Set("user:1", "John")
    go cache.Set("user:2", "Jane")

    go func() {
        value, _ := cache.Get("user:1")
        fmt.Println(value)
    }()

    time.Sleep(1 * time.Second)
}
```

### RWMutex (Read-Write Mutex)

When you have many reads and few writes:

```go
var (
    data    map[string]string
    rwMu    sync.RWMutex
)

// Many readers can access simultaneously
func read(key string) string {
    rwMu.RLock()         // Multiple RLock() OK
    defer rwMu.RUnlock()
    return data[key]
}

// Writers get exclusive access
func write(key, value string) {
    rwMu.Lock()          // Blocks all RLock() and Lock()
    defer rwMu.Unlock()
    data[key] = value
}
```

---

## WaitGroups

WaitGroups are like **Promise.all()** - wait for multiple goroutines to finish.

### Node.js: Promise.all
```javascript
async function processAllUsers(users) {
    const promises = users.map(user => processUser(user));
    await Promise.all(promises);
    console.log('All users processed');
}
```

### Go: WaitGroup
```go
func processAllUsers(users []User) {
    var wg sync.WaitGroup

    for _, user := range users {
        wg.Add(1) // Increment counter

        go func(u User) {
            defer wg.Done() // Decrement counter when done
            processUser(u)
        }(user)
    }

    wg.Wait() // Block until counter reaches 0
    fmt.Println("All users processed")
}
```

### WaitGroup Lifecycle

```
┌──────────────────────────────────────────┐
│          WaitGroup Counter               │
├──────────────────────────────────────────┤
│ wg.Add(1)      →  Counter: 0 → 1        │
│ wg.Add(1)      →  Counter: 1 → 2        │
│ wg.Add(1)      →  Counter: 2 → 3        │
│                                          │
│ goroutine 1 finishes → wg.Done()        │
│                   Counter: 3 → 2         │
│ goroutine 2 finishes → wg.Done()        │
│                   Counter: 2 → 1         │
│ goroutine 3 finishes → wg.Done()        │
│                   Counter: 1 → 0         │
│                                          │
│ wg.Wait() unblocks! ✅                  │
└──────────────────────────────────────────┘
```

---

## Real-World Examples

### Example 1: Imageboard - Concurrent Thread Loading

#### Scenario
Load the latest 50 threads from multiple boards concurrently.

#### Node.js Version
```javascript
async function loadAllBoardThreads(boardIDs) {
    // Fetch all boards concurrently
    const promises = boardIDs.map(id =>
        db.query('SELECT * FROM threads WHERE board_id = ? LIMIT 50', [id])
    );

    const results = await Promise.all(promises);

    // Flatten results
    return results.flat();
}

// Usage
const threads = await loadAllBoardThreads([1, 2, 3, 4, 5]);
```

#### Go Version
```go
func loadAllBoardThreads(boardIDs []int) []Thread {
    var wg sync.WaitGroup
    threadsCh := make(chan []Thread, len(boardIDs))

    for _, boardID := range boardIDs {
        wg.Add(1)

        go func(id int) {
            defer wg.Done()

            threads := []Thread{}
            err := db.Query(&threads,
                "SELECT * FROM threads WHERE board_id = $1 LIMIT 50", id)

            if err == nil {
                threadsCh <- threads
            }
        }(boardID)
    }

    // Close channel when all done
    go func() {
        wg.Wait()
        close(threadsCh)
    }()

    // Collect all results
    allThreads := []Thread{}
    for threads := range threadsCh {
        allThreads = append(allThreads, threads...)
    }

    return allThreads
}
```

### Example 2: Worker Pool Pattern

Process many tasks with limited concurrency (like p-limit in Node.js).

#### Node.js (p-limit)
```javascript
const pLimit = require('p-limit');
const limit = pLimit(5); // Max 5 concurrent

const images = [...Array(100)]; // 100 images

const promises = images.map((img, i) =>
    limit(() => processImage(i))
);

await Promise.all(promises);
```

#### Go (Worker Pool)
```go
func processImagesWithPool(images []Image, maxWorkers int) {
    jobs := make(chan Image, len(images))
    var wg sync.WaitGroup

    // Start worker pool
    for w := 0; w < maxWorkers; w++ {
        wg.Add(1)

        go func(workerID int) {
            defer wg.Done()

            for img := range jobs {
                fmt.Printf("Worker %d processing image %s\n",
                    workerID, img.Name)
                processImage(img)
            }
        }(w)
    }

    // Send jobs
    for _, img := range images {
        jobs <- img
    }
    close(jobs) // No more jobs

    wg.Wait() // Wait for all workers to finish
}

// Usage
images := make([]Image, 100)
processImagesWithPool(images, 5) // 5 workers
```

### Example 3: Timeout Pattern

#### Node.js
```javascript
async function fetchWithTimeout(url, timeout = 5000) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    try {
        const response = await fetch(url, { signal: controller.signal });
        clearTimeout(timeoutId);
        return response.json();
    } catch (error) {
        if (error.name === 'AbortError') {
            throw new Error('Request timeout');
        }
        throw error;
    }
}
```

#### Go
```go
func fetchWithTimeout(url string, timeout time.Duration) (Data, error) {
    ctx, cancel := context.WithTimeout(context.Background(), timeout)
    defer cancel()

    resultCh := make(chan Data, 1)
    errorCh := make(chan error, 1)

    go func() {
        data, err := fetchData(url)
        if err != nil {
            errorCh <- err
            return
        }
        resultCh <- data
    }()

    select {
    case data := <-resultCh:
        return data, nil
    case err := <-errorCh:
        return Data{}, err
    case <-ctx.Done():
        return Data{}, errors.New("request timeout")
    }
}
```

---

## Common Patterns

### Pattern 1: Done Channel

Signal when work is complete:

```go
func worker(done chan bool) {
    fmt.Println("Working...")
    time.Sleep(1 * time.Second)
    done <- true // Signal completion
}

func main() {
    done := make(chan bool)
    go worker(done)
    <-done // Wait for signal
    fmt.Println("Worker finished")
}
```

### Pattern 2: Quit Channel

Gracefully stop goroutines:

```go
func worker(quit chan bool) {
    ticker := time.NewTicker(500 * time.Millisecond)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            fmt.Println("Working...")
        case <-quit:
            fmt.Println("Stopping worker")
            return
        }
    }
}

func main() {
    quit := make(chan bool)
    go worker(quit)

    time.Sleep(2 * time.Second)
    quit <- true // Tell worker to stop
    time.Sleep(100 * time.Millisecond)
}
```

### Pattern 3: Semaphore

Limit concurrent operations:

```go
type Semaphore chan struct{}

func NewSemaphore(max int) Semaphore {
    return make(chan struct{}, max)
}

func (s Semaphore) Acquire() {
    s <- struct{}{}
}

func (s Semaphore) Release() {
    <-s
}

// Usage
func processWithLimit(items []Item) {
    sem := NewSemaphore(5) // Max 5 concurrent
    var wg sync.WaitGroup

    for _, item := range items {
        wg.Add(1)

        go func(i Item) {
            defer wg.Done()

            sem.Acquire()
            defer sem.Release()

            process(i) // Only 5 running at once
        }(item)
    }

    wg.Wait()
}
```

---

## Pitfalls & Best Practices

### ❌ Pitfall 1: Not Passing Loop Variables

```go
// ❌ WRONG - all goroutines use same variable!
for _, user := range users {
    go func() {
        process(user) // Bug! 'user' changes in the loop
    }()
}

// ✅ CORRECT - pass as parameter
for _, user := range users {
    go func(u User) {
        process(u) // Each goroutine has its own copy
    }(user)
}
```

### ❌ Pitfall 2: Forgetting to Close Channels

```go
// ❌ WRONG - range will block forever
func producer(ch chan int) {
    for i := 0; i < 10; i++ {
        ch <- i
    }
    // Forgot to close!
}

func consumer(ch chan int) {
    for val := range ch { // Blocks forever waiting for close
        fmt.Println(val)
    }
}

// ✅ CORRECT - close channel when done
func producer(ch chan int) {
    for i := 0; i < 10; i++ {
        ch <- i
    }
    close(ch) // Signal no more values
}
```

### ❌ Pitfall 3: Mutex Not Unlocked

```go
// ❌ WRONG - might forget to unlock on error
func updateCache(key, value string) error {
    mu.Lock()

    if err := validate(value); err != nil {
        return err // Bug! Mutex never unlocked
    }

    cache[key] = value
    mu.Unlock()
    return nil
}

// ✅ CORRECT - use defer
func updateCache(key, value string) error {
    mu.Lock()
    defer mu.Unlock() // Always unlocks, even on error

    if err := validate(value); err != nil {
        return err
    }

    cache[key] = value
    return nil
}
```

### ❌ Pitfall 4: Unbuffered Channel Deadlock

```go
// ❌ WRONG - deadlock!
func main() {
    ch := make(chan int) // Unbuffered
    ch <- 42             // Blocks forever (no receiver!)
    fmt.Println(<-ch)    // Never reached
}

// ✅ CORRECT - use buffered or goroutine
func main() {
    ch := make(chan int, 1) // Buffered
    ch <- 42                // Doesn't block
    fmt.Println(<-ch)       // Works!
}

// Or use goroutine
func main() {
    ch := make(chan int)
    go func() {
        ch <- 42 // Send in goroutine
    }()
    fmt.Println(<-ch) // Receive in main
}
```

### ✅ Best Practice 1: Always Use Context for Cancellation

```go
func longRunningTask(ctx context.Context) error {
    for {
        select {
        case <-ctx.Done():
            return ctx.Err() // Cancelled or timeout
        default:
            // Do work
            time.Sleep(100 * time.Millisecond)
        }
    }
}

// Usage
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

err := longRunningTask(ctx)
```

### ✅ Best Practice 2: Prefer Channels Over Mutexes for Communication

```go
// ❌ Less idiomatic (mutex + shared state)
var jobs []Job
var mu sync.Mutex

func addJob(job Job) {
    mu.Lock()
    jobs = append(jobs, job)
    mu.Unlock()
}

// ✅ More idiomatic (channels)
jobsCh := make(chan Job, 100)

func addJob(job Job) {
    jobsCh <- job
}
```

**Go Proverb:** *"Don't communicate by sharing memory; share memory by communicating."*

---

## Quick Reference

### Comparison Table

| Need | Node.js | Go |
|------|---------|-----|
| Run async task | `Promise` | `go func()` |
| Wait for task | `await promise` | `<-channel` |
| Wait for all | `Promise.all()` | `WaitGroup` |
| Wait for first | `Promise.race()` | `select {}` |
| Timeout | `Promise.race([promise, timeout])` | `select { case <-time.After() }` |
| Protect shared data | N/A (single thread) | `sync.Mutex` |
| Worker pool | `p-limit` | Worker pool pattern |
| Queue | Array + callbacks | `chan` |

### When to Use What

| Use Case | Tool |
|----------|------|
| Start async operation | `go func()` |
| Get result from goroutine | `channel` |
| Wait for multiple goroutines | `WaitGroup` |
| Protect shared data | `Mutex` |
| Wait for one of many | `select` |
| Timeout | `context.WithTimeout` or `time.After` |
| Limit concurrency | Worker pool or semaphore |
| Cancel operations | `context.Context` |

---

## Summary

**Node.js Model:**
```javascript
// Single-threaded, event loop, promises
async function main() {
    const result = await doAsync(); // Pauses, but doesn't block thread
    return result;
}
```

**Go Model:**
```go
// Multi-threaded, goroutines, channels
func main() {
    ch := make(chan Result)
    go doAsync(ch)       // Truly parallel
    result := <-ch       // Receive result
}
```

**Key Takeaways:**

1. **Goroutines** = Lightweight threads (like Promises, but truly parallel)
2. **Channels** = Communication between goroutines (no return values!)
3. **Select** = Wait for multiple channels (like Promise.race)
4. **Mutexes** = Protect shared data (Node.js doesn't need these)
5. **WaitGroups** = Wait for all goroutines (like Promise.all)

**The Go Way:**
- Don't return values from goroutines - send them through channels
- Don't share memory - communicate through channels
- Use mutexes only when channels don't fit
- Always use `defer` to unlock mutexes
- Use contexts for cancellation

---

**Happy concurrent coding! 🚀**
