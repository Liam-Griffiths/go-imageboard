-- PostgreSQL initialization script for go-imageboard
-- Run this on a fresh database to set up the complete schema
--
-- Usage:
--   psql -U postgres -c "CREATE DATABASE imageboard;"
--   psql -U postgres -d imageboard -f initdb.sql

-- Enable extensions
CREATE EXTENSION IF NOT EXISTS pg_trgm; -- For full-text search

-- =============================================================================
-- CORE TABLES
-- =============================================================================

-- Boards table
CREATE TABLE IF NOT EXISTS boards (
    id SERIAL PRIMARY KEY,
    slug VARCHAR(50) UNIQUE NOT NULL,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),

    -- Imageboard settings
    thread_limit INTEGER NOT NULL DEFAULT 150,  -- Max threads per board
    bump_limit INTEGER NOT NULL DEFAULT 300,    -- Max posts before thread stops bumping

    -- Stats
    thread_count INTEGER NOT NULL DEFAULT 0
);

-- Threads table (primary storage)
CREATE TABLE IF NOT EXISTS threads (
    id SERIAL PRIMARY KEY,
    board_id INTEGER NOT NULL REFERENCES boards(id) ON DELETE CASCADE,
    title VARCHAR(255),
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),  -- Last bump time

    -- Imageboard mechanics
    post_count INTEGER NOT NULL DEFAULT 0,
    is_pinned BOOLEAN NOT NULL DEFAULT FALSE,      -- Pinned threads don't get pruned
    is_locked BOOLEAN NOT NULL DEFAULT FALSE       -- Locked threads can't receive posts
);

-- Posts table (primary storage)
CREATE TABLE IF NOT EXISTS posts (
    id SERIAL PRIMARY KEY,
    thread_id INTEGER NOT NULL REFERENCES threads(id) ON DELETE CASCADE,
    content TEXT NOT NULL,
    image_path VARCHAR(255),                       -- URL to image (CDN or local)
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),

    -- User identification (ephemeral, thread-scoped)
    user_id VARCHAR(8),                            -- MD5 hash of IP+thread
    country_code CHAR(2)                           -- Two-letter country code
);

-- Admin users
CREATE TABLE IF NOT EXISTS admin_users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- INDEXES FOR PERFORMANCE
-- =============================================================================

-- Threads: Board threads sorted by bump time (most common query)
CREATE INDEX IF NOT EXISTS idx_threads_board_updated
ON threads(board_id, updated_at DESC);

-- Threads: Pinned threads first, then by update time
CREATE INDEX IF NOT EXISTS idx_threads_board_pinned
ON threads(board_id, is_pinned DESC, updated_at DESC);

-- Posts: Thread posts in chronological order
CREATE INDEX IF NOT EXISTS idx_posts_thread_created
ON posts(thread_id, created_at ASC);

-- Posts: Full-text search on post content
CREATE INDEX IF NOT EXISTS idx_posts_content_search
ON posts USING gin(to_tsvector('english', content));

-- =============================================================================
-- DEFAULT DATA
-- =============================================================================

-- Create default boards
INSERT INTO boards (slug, name, description, thread_limit, bump_limit)
VALUES
    ('b', 'Random', 'Random discussion', 150, 300),
    ('g', 'Technology', 'Technology discussion', 100, 500),
    ('pol', 'Politics', 'Political discussion', 150, 300)
ON CONFLICT (slug) DO NOTHING;

-- Create default admin user
-- Username: admin
-- Password: admin123
-- IMPORTANT: Change this password immediately after first login!
INSERT INTO admin_users (username, password_hash)
VALUES ('admin', '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy')
ON CONFLICT (username) DO NOTHING;

-- =============================================================================
-- HELPER FUNCTIONS (OPTIONAL)
-- =============================================================================

-- Function to get thread count for a board
CREATE OR REPLACE FUNCTION get_thread_count(board_id_param INTEGER)
RETURNS INTEGER AS $$
    SELECT COUNT(*)::INTEGER
    FROM threads
    WHERE board_id = board_id_param AND is_pinned = FALSE;
$$ LANGUAGE SQL STABLE;

-- Function to check if thread should be bumped
CREATE OR REPLACE FUNCTION should_bump_thread(thread_id_param INTEGER)
RETURNS BOOLEAN AS $$
    SELECT t.post_count < b.bump_limit
    FROM threads t
    JOIN boards b ON t.board_id = b.id
    WHERE t.id = thread_id_param;
$$ LANGUAGE SQL STABLE;

-- =============================================================================
-- SEQUENCES (for compatibility with previous Redis-based system)
-- =============================================================================

-- These sequences ensure IDs don't conflict with old Redis data
CREATE SEQUENCE IF NOT EXISTS global_thread_id_seq START 1000;
CREATE SEQUENCE IF NOT EXISTS global_post_id_seq START 1000;

-- =============================================================================
-- SUMMARY
-- =============================================================================

DO $$
BEGIN
    RAISE NOTICE '=================================================';
    RAISE NOTICE 'go-imageboard database initialized successfully!';
    RAISE NOTICE '=================================================';
    RAISE NOTICE '';
    RAISE NOTICE 'Tables created:';
    RAISE NOTICE '  - boards (%)' , (SELECT COUNT(*) FROM boards);
    RAISE NOTICE '  - threads';
    RAISE NOTICE '  - posts';
    RAISE NOTICE '  - admin_users (%)' , (SELECT COUNT(*) FROM admin_users);
    RAISE NOTICE '';
    RAISE NOTICE 'Default admin credentials:';
    RAISE NOTICE '  Username: admin';
    RAISE NOTICE '  Password: admin123';
    RAISE NOTICE '  ⚠️  CHANGE THIS PASSWORD IMMEDIATELY!';
    RAISE NOTICE '';
    RAISE NOTICE 'Next steps:';
    RAISE NOTICE '  1. Update .env with database credentials';
    RAISE NOTICE '  2. Run: go run .';
    RAISE NOTICE '  3. Login at /admin and change password';
    RAISE NOTICE '';
END $$;
