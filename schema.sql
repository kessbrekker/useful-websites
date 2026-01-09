DROP TABLE IF EXISTS favorites;
DROP TABLE IF EXISTS websites;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    is_admin BOOLEAN DEFAULT 0,
    created_at INTEGER DEFAULT (unixepoch())
);

CREATE TABLE websites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    title TEXT,
    screenshot_url TEXT,
    added_by_user_id INTEGER,
    created_at INTEGER DEFAULT (unixepoch()),
    FOREIGN KEY (added_by_user_id) REFERENCES users(id)
);

CREATE TABLE favorites (
    user_id INTEGER,
    website_id INTEGER,
    created_at INTEGER DEFAULT (unixepoch()),
    PRIMARY KEY (user_id, website_id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (website_id) REFERENCES websites(id)
);

-- Seed Admin User (password: admin123)
-- Hash generated using bcryptjs for 'admin123' might be distinct, but for local dev we can insert a known hash or handle registration.
-- For now, let's leave seeding for a script or manual registration to test the flow.
