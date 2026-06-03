# SLOX BIN

Underground paste service. Dark. Fast. No BS.

## Stack

- **Backend**: Node.js + Express
- **Database**: SQLite (via better-sqlite3)
- **Frontend**: Pure HTML/CSS served by Express (no framework)
- **Syntax highlighting**: highlight.js (CDN)

## Features

- Create pastes with title, author, syntax highlighting, expiry, and optional password
- Recent pastes list with view counts, timestamps, author
- Full-text search across paste titles and authors
- Paste viewer with line numbers, copy button, raw view
- Password-protected pastes
- Pinned/featured pastes support
- Hall of Clowns page
- Rate limiting on paste creation
- Auto-expiry cleanup on each request
- Scanline CRT overlay for that underground feel

## Setup

### Requirements

- Node.js 18+
- npm

### Install

```bash
cd "dox bin"
npm install
```

### Run

```bash
# Production
npm start

# Development (auto-reload)
npm run dev
```

Then open **http://localhost:3000**

The SQLite database (`sloxbin.db`) is created automatically on first run.

## Project Structure

```
dox bin/
├── server.js          # Express server + all routes + template engine
├── package.json
├── sloxbin.db         # Created automatically on first run
├── public/
│   └── style.css      # All styles
└── README.md
```

## Config

Default port is `3000`. Override with environment variable:

```bash
PORT=8080 npm start
```

## Pinning a Paste

Currently done directly in the database:

```bash
# Using sqlite3 CLI
sqlite3 sloxbin.db "UPDATE pastes SET pinned = 1 WHERE id = 'your_paste_id';"
```

## Notes

- No user accounts — pastes are anonymous by default
- Passwords are SHA-256 hashed with a salt before storage
- Rate limit: 30 pastes per IP per 15 minutes
- All HTML is server-rendered (no client-side framework)
