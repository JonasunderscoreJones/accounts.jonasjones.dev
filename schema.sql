-- Drop the tables if they exist (to avoid errors if re-running the script)
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS user_actions;

-- Create the sessions table
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created DATETIME,
    expiration DATETIME,
    userid INTEGER,
    sessionkey TEXT,
    FOREIGN KEY (userid) REFERENCES users(id) -- Foreign key to the users table
);

-- Create the users table
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created DATETIME,
    username TEXT UNIQUE,
    passwordhash TEXT,
    scopes TEXT,
    email TEXT UNIQUE,
    first_name TEXT,
    last_name TEXT,
    is_active BOOLEAN DEFAULT 1, -- Example of another useful field
    last_login DATETIME
);

-- Create the user_actions table to log actions made by users
CREATE TABLE IF NOT EXISTS user_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userid INTEGER,
    timestamp DATETIME,
    path TEXT,
    status_code INTEGER,
    FOREIGN KEY (userid) REFERENCES users(id) -- Foreign key to users
);

-- create admin user with password admin (hashed)
INSERT INTO users (created, username, passwordhash, scopes, email, first_name, last_name) VALUES (datetime('now'), 'sudo-admin', '8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918', 'admin', 'admin@example.com', 'Admin', 'User');