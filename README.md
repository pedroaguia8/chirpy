# 🐦 Chirpy

Chirpy is a backend API server for a Twitter-like social media platform. It is built entirely in Go using only the standard library's `net/http` package to demonstrate a deep understanding of Go's concurrency model, HTTP servers, and backend architecture without a framework.

## ✨ Features

- **No Frameworks**: Built using only the Go standard library (`net/http`) for all routing, handlers, and middleware.
- **Full User Authentication**: Secure user creation with Argon2id password hashing.
- **JWT & Refresh Tokens**: Stateless authentication using JWTs (HS256) for access and stateful, revokable Refresh Tokens stored in the database for persistent sessions.
- **RESTful API**: A full CRUD API for "Users" and "Chirps".
- **Database Migrations**: Uses Goose for managing PostgreSQL database schema migrations.
- **Type-Safe SQL**: Uses sqlc to generate fully type-safe Go code from raw SQL queries, preventing SQL injection and improving developer ergonomics.
- **Authorization**: API endpoints are protected, ensuring users can only modify or delete their own resources.
- **Secure Webhooks**: A dedicated endpoint to handle user upgrades from a third-party service ("Polka") secured with API key authentication.
- **Admin & Metrics**: Includes administrative endpoints for monitoring site metrics and resetting the database in a development environment.

## 🛠️ Tech Stack

- **Backend**: Go (`net/http`)
- **Database**: PostgreSQL
- **Tooling**:
    - `sqlc`: Type-safe SQL query generation.
    - `Goose`: Database schema migrations.
- **Auth**:
    - `golang-jwt/jwt` for JWT generation and validation.
    - `alexedwards/argon2id` for secure password hashing.

## 🚀 Getting Started

Follow these instructions to get a local copy of the server up and running.

### Prerequisites

You will need the following tools installed on your machine:

- Go (1.22+ recommended)
- PostgreSQL (15+ recommended)
- Goose (for database migrations)
- sqlc (for code generation)

You can install `goose` and `sqlc` with the following commands:

```bash
go install github.com/pressly/goose/v3/cmd/goose@latest
go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
```

### 1. Clone the Repository

```bash
git clone https://github.com/pedroaguia8/chirpy.git
cd chirpy
```

### 2. Set Up the Database

1. Make sure your PostgreSQL server is running.
2. Connect to `psql` and create the database:

```sql
CREATE DATABASE chirpy;
```

### 3. Configure Environment

1. Create a `.env` file in the root of the project:

```bash
touch .env
```

2. Add the following variables to your `.env` file:

```env
# Example for a local Postgres setup.
# Replace 'username' and 'password' with your own.
DB_URL="postgres://username:password@localhost:5432/chirpy?sslmode=disable"

# A strong, randomly generated secret for signing JWTs
JWT_SECRET="YOUR_RANDOM_SECRET_KEY"

# The API key for the "Polka" webhook
POLKA_KEY="POLKA_API_SECRET_KEY"

# Set to "dev" to enable the /admin/reset endpoint
PLATFORM="dev"
```

> **Note**: You can generate a strong `JWT_SECRET` using `openssl rand -base64 32`

### 4. Run Migrations

Run `goose` from the `sql/schema` directory to set up your database tables.

```bash
cd sql/schema
# Use the $DB_URL from your .env file
goose postgres "$DB_URL" up
cd ../..
```

### 5. Run the Server

You can now start the Chirpy server:

```bash
go run .
```

The server will be running at `http://localhost:8080`.

## 📚 API Documentation

### Authentication

#### POST `/api/login`

- **Description**: Logs in a user and returns a new access token (JWT) and a refresh token.
- **Auth**: None
- **Request Body**:
  ```json
  {
    "email": "user@example.com",
    "password": "password123"
  }
  ```
- **Success Response**: `200 OK`
  ```json
  {
    "id": "...",
    "email": "user@example.com",
    "is_upgraded": false,
    "token": "ACCESS_TOKEN_JWT",
    "refresh_token": "REFRESH_TOKEN_STRING"
  }
  ```

#### POST `/api/refresh`

- **Description**: Uses a valid refresh token to generate a new access token.
- **Auth**: Refresh Token (`Authorization: Bearer <refresh_token>`)
- **Success Response**: `200 OK`
  ```json
  {
    "token": "NEW_ACCESS_TOKEN_JWT"
  }
  ```

#### POST `/api/revoke`

- **Description**: Revokes a refresh token, invalidating it for future use.
- **Auth**: Refresh Token (`Authorization: Bearer <refresh_token>`)
- **Success Response**: `204 No Content`

### Users

#### POST `/api/users`

- **Description**: Creates a new user in the database.
- **Auth**: None
- **Request Body**:
  ```json
  {
    "email": "newuser@example.com",
    "password": "strongpassword"
  }
  ```
- **Success Response**: `201 Created`
  ```json
  {
    "id": "...",
    "email": "newuser@example.com",
    "is_upgraded": false
  }
  ```

#### PUT `/api/users`

- **Description**: Updates the email and password for the authenticated user.
- **Auth**: Access Token (`Authorization: Bearer <access_token>`)
- **Request Body**:
  ```json
  {
    "email": "updated@example.com",
    "password": "newstrongpassword"
  }
  ```
- **Success Response**: `200 OK`

### Chirps

#### POST `/api/chirps`

- **Description**: Creates a new chirp as the authenticated user. Profane words are censored.
- **Auth**: Access Token (`Authorization: Bearer <access_token>`)
- **Request Body**:
  ```json
  {
    "body": "This is a new chirp, what a kerfuffle!"
  }
  ```
- **Success Response**: `201 Created`
  ```json
  {
    "id": "...",
    "body": "This is a new chirp, what a ****!",
    "user_id": "..."
  }
  ```

#### GET `/api/chirps`

- **Description**: Retrieves all chirps. Can be filtered and sorted using query parameters.
- **Auth**: None
- **Query Parameters**:
    - `author_id` (optional, string): Filters chirps for a specific user ID.
    - `sort` (optional, string): Sorts chirps. Can be `asc` (default) or `desc`.
- **Success Response**: `200 OK`

#### GET `/api/chirps/{chirpId}`

- **Description**: Retrieves a single chirp by its ID.
- **Auth**: None
- **Success Response**: `200 OK`

#### DELETE `/api/chirps/{chirpId}`

- **Description**: Deletes a chirp. Authorization check: The authenticated user must be the author of the chirp.
- **Auth**: Access Token (`Authorization: Bearer <access_token>`)
- **Success Response**: `204 No Content`
- **Failure Response**: `403 Forbidden` (if user is not the author)

### Webhooks

#### POST `/api/polka/webhooks`

- **Description**: Secure endpoint for the "Polka" payment service to upgrade a user to "Chirpy Red".
- **Auth**: API Key (`Authorization: ApiKey <polka_key>`)
- **Request Body**:
  ```json
  {
    "event": "user.upgraded",
    "data": {
      "user_id": "USER_ID_TO_UPGRADE"
    }
  }
  ```
- **Success Response**: `204 No Content`
- **Failure Response**: `401 Unauthorized` (if API key is missing or invalid)

### Admin & Health

#### GET `/api/healthz`

- **Description**: A health check endpoint for the server.
- **Auth**: None
- **Success Response**: `200 OK` (Body: `OK`)

#### GET `/admin/metrics`

- **Description**: An HTML page displaying the total number of hits to the site's fileserver.
- **Auth**: None
- **Success Response**: `200 OK` (Content-Type: `text/html`)

#### POST `/admin/reset`

- **Description**: Resets the site metrics and deletes all users and chirps from the database. Only available if `PLATFORM="dev"` is set in the `.env` file.
- **Auth**: None
- **Success Response**: `200 OK`

## 📁 Project Structure

```
.
├── app/                  # Static files (HTML, assets) served by /app/
├── go.mod                # Go module dependencies
├── internal/
│   ├── auth/             # Authentication logic (JWTs, passwords, API keys)
│   ├── database/         # sqlc-generated code for database queries
│   ├── handlers/         # HTTP handlers for all API routes
│   └── utils/            # Helper functions (JSON responses, profanity filter)
├── main.go               # Server entry point (config, router, server startup)
├── README.md             # This file
├── sql/
│   ├── queries/          # Raw SQL queries for sqlc
│   └── schema/           # Goose database migration files
└── sqlc.yaml             # sqlc configuration file
```
