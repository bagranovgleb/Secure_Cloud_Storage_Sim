# CloudSim — Secure Cloud Storage Simulation

A university project simulating a secure cloud file storage system built with PHP and MySQL.  
Users can register, upload files, download them, and manage their profile. Admins can monitor audit logs and manage users.

---

## Features

- AES-256-CTR file encryption at rest
- PBKDF2 key derivation (encryption key derived from user password — never stored)
- CSRF protection on all forms
- Role-based access (user / admin)
- Per-user 5 GB storage quota, 40 MB per-file limit
- Encrypted profile avatars stored as database blobs
- Security audit log with IP tracking
- Rate limiting (5 requests per 10 seconds per IP)
- Stealth 404 on admin panel for non-admins

---

## Requirements

- PHP 8.0 or higher
- MySQL 5.7 or higher
- Apache with mod_rewrite (XAMPP / WAMP / LAMP)
- PHP extensions: `mysqli`, `openssl`, `fileinfo`

---

## Folder Structure

```
project-root/
│
├── cloud_sim/                  ← web root (inside htdocs or www)
│   ├── index.php / login.php
│   ├── config.php
│   ├── storage/                ← encrypted .dat files are saved here
│   │   └── .gitkeep
│   ├── styles/                 ← CSS files
│   ├── js/                     ← JS files
│   └── ...other PHP files
│
└── secure_logs/                ← OUTSIDE the web root (two levels up)
    ├── security_audit.log
    └── rate_limits/
```

> **Important:** `secure_logs/` must sit **two directories above** `cloud_sim/`.  
> If your project is at `htdocs/cloud_sim/`, then `secure_logs/` goes at `htdocs/../secure_logs/` — i.e. next to `htdocs/`, not inside it.  
> This keeps logs inaccessible from the browser.

---

## Installation

### 1. Clone or copy the project

Place the project folder inside your web server root:

- XAMPP: `C:\xampp\htdocs\cloud_sim\`
- WAMP: `C:\wamp64\www\cloud_sim\`
- LAMP: `/var/www/html/cloud_sim/`

### 2. Create the config file

Copy `config_sample.php` to `config.php` and fill in your database credentials:

```php
$conn = new mysqli('localhost', 'YOUR_USER', 'YOUR_PASSWORD', 'cloud_simulation');
```

> `config.php` is listed in `.gitignore` and will never be committed.

### 3. Create the database

Open **phpMyAdmin** or your MySQL client and run:

```sql
CREATE DATABASE cloud_simulation CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE cloud_simulation;

CREATE TABLE users (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    username     VARCHAR(30)  NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    enc_salt     VARCHAR(32)  NOT NULL DEFAULT '',
    email        VARCHAR(255) NULL DEFAULT NULL,
    phone        VARCHAR(30)  NULL DEFAULT NULL,
    role         ENUM('user', 'admin') NOT NULL DEFAULT 'user',
    avatar_blob  MEDIUMBLOB   NULL DEFAULT NULL,
    avatar_mime  VARCHAR(50)  NULL DEFAULT NULL,
    created_at   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE INDEX idx_users_email (email)
);

CREATE TABLE file_registry (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    owner_id      INT          NOT NULL,
    original_name TEXT         NOT NULL,
    stored_name   VARCHAR(64)  NOT NULL UNIQUE,
    file_type     VARCHAR(100) NOT NULL,
    file_size     BIGINT       NOT NULL DEFAULT 0,
    uploaded_at   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
);
```

### 4. Create the secure_logs folder

Create the folder structure manually — it must be **outside** the web root:

**XAMPP (Windows):**
```
C:\xampp\secure_logs\
C:\xampp\secure_logs\rate_limits\
```

**WAMP (Windows):**
```
C:\wamp64\secure_logs\
C:\wamp64\secure_logs\rate_limits\
```

**LAMP (Linux):**
```bash
mkdir -p /var/secure_logs/rate_limits
chmod 755 /var/secure_logs
chmod 755 /var/secure_logs/rate_limits
```
Then update the path in `config.php` — change `dirname(__DIR__, 2)` to match your actual folder location if needed.

### 5. Create the storage folder

Inside the project folder, make sure `storage/` exists:

```
cloud_sim/storage/
```

It should already be there with a `.gitkeep` file. If not, create it manually and make sure it is writable by the web server.

### 6. Create an admin account

Register a normal account through the website, then promote it to admin directly in the database:

```sql
UPDATE users SET role = 'admin' WHERE username = 'your_username';
```


---

## Current Limits

| Setting | Value |
|---|---|
| Max file size per upload | 40 MB |
| Total storage per user | 5 GB |
| Profile picture max size | 5 MB |
| Allowed avatar formats | JPG, PNG |
| Rate limit | 15 requests / 10 seconds |

---

## Security Notes

- Encryption keys are **never stored** — they are derived from the user's password via PBKDF2 at login and held only in the session. If a user forgets their password, their files cannot be recovered.
- Changing a password re-encrypts all stored files automatically under the new key.


---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | PHP 8+ |
| Database | MySQL |
| Encryption | AES-256-CTR via OpenSSL |
| Key derivation | PBKDF2-SHA256 (200,000 iterations) |
| Frontend | HTML, CSS, JS (no frameworks) |
| Fonts | Google Sans (Google Fonts) |
| Icons | Feather Icons (inline SVG) |

---

*Made by Bagranov Gleb as a project for Messina University*