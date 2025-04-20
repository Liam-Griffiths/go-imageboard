# Go Imageboard

A simple imageboard application written in Go, using PostgreSQL for persistent storage and Redis for caching.

## Features

- Multiple boards
- Thread and post creation
- Image uploads
- Admin panel for moderation
- Google reCAPTCHA integration

## Configuration

The application can be configured using environment variables or a `.env` file. A sample configuration file is provided in `.env.example`. To use it:

1. Copy `.env.example` to `.env`
2. Edit the values in `.env` to match your environment

### Configuration Options

#### Database Configuration
- `DB_HOST`: PostgreSQL host (default: localhost)
- `DB_PORT`: PostgreSQL port (default: 5432)
- `DB_USER`: PostgreSQL username (default: imageboard)
- `DB_PASSWORD`: PostgreSQL password (default: imageboard)
- `DB_NAME`: PostgreSQL database name (default: imageboard)

#### Redis Configuration
- `REDIS_ADDR`: Redis address (default: localhost:6379)
- `REDIS_PASSWORD`: Redis password (default: empty)
- `REDIS_DB`: Redis database number (default: 0)

#### Server Configuration
- `PORT`: HTTP server port (default: 8080)

#### reCAPTCHA Configuration
- `RECAPTCHA_SECRET_KEY`: Google reCAPTCHA secret key

## Running the Application

```bash
# Clone the repository
git clone https://github.com/yourusername/go-imageboard.git
cd go-imageboard

# Install dependencies
go mod download

# Set up the database and Redis
# (instructions depend on your environment)

# Copy and edit the configuration file
cp .env.example .env
# Edit .env with your configuration

# Run the application
go run .
```

## Default Admin User

On first run, a default admin user is created with the following credentials:
- Username: admin
- Password: admin123

It is recommended to change these credentials after the first login.
