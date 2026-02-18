# Password Manager

Offline-first desktop password manager built with Electron, React, and TypeScript. All data is stored locally with per-entry AES-256-GCM encryption—no cloud, no sync, full control.

![Electron](https://img.shields.io/badge/Electron-37-47848F?logo=electron)
![React](https://img.shields.io/badge/React-18-61DAFB?logo=react)
![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?logo=typescript)
![License](https://img.shields.io/badge/License-MIT-green)

## Features

### Password management
- **CRUD** – add, edit, delete entries
- **Entry history** – track changes, rollback to previous versions
- **Bulk operations** – bulk edit categories, bulk delete
- **8 categories** – Work, Personal, Banking, Social Media, Shopping, Entertainment, Utilities, Other
- **Search & filter** – by service name, username, category
- **Sorting** – by name, date, category (A–Z, Z–A, newest, oldest)
- **URL field** – quick link to login page, open in browser
- **Notes** – extra info per entry (PINs, security questions)

### Security
- **AES-256-GCM** – authenticated encryption with integrity verification
- **PBKDF2** – 100,000 iterations, SHA-256, per-entry salt
- **Two-step login** – app account + master password
- **Lockout** – 5 failed attempts → 30 min block
- **Auto-lock** – vault locks after inactivity
- **Clipboard auto-clear** – passwords cleared after 30 seconds
- **Recovery** – Email/SMS code flow (dev: `alert`, prod: SendGrid/Twilio)

### Tools & UX
- **Password generator** – random (8–64 chars) or passphrase (4–8 words)
- **Strength meter** – 0–100 score with feedback
- **Dark/light theme**
- **Keyboard shortcuts** – Ctrl+F (search), Ctrl+N (new), Ctrl+L (lock)

## Quick start

### Prerequisites
- Node.js 18+
- npm

### Development

```bash
git clone <repository-url>
cd passwordManager

npm install
cd frontend && npm install && cd ..

npm start
```

This starts the Vite dev server and launches the Electron app.

### Build for Windows

```bash
npm run build
```

Output in `electron-builder-output/`:
- `Password Manager Setup 1.0.0.exe` – installer
- `Password Manager 1.0.0.exe` – portable (no install)

See [INSTALL_WINDOWS.md](INSTALL_WINDOWS.md) for detailed build instructions and troubleshooting.

## Project structure

```
passwordManager/
├── main.js              # Electron main process
├── preload.js           # IPC bridge (context isolation)
├── db/
│   ├── vault.js        # Vault logic, SQLite, encryption
│   └── vault-worker.js # Crypto operations (worker thread)
├── frontend/            # React + TypeScript + Vite
│   ├── src/
│   │   ├── components/
│   │   ├── contexts/
│   │   └── utils/
│   └── dist/           # Production build (after npm run build)
└── electron-builder-output/  # Built installers
```

## Security model

| Layer | Implementation |
|-------|----------------|
| **Encryption** | AES-256-GCM, 12-byte IV, 16-byte auth tag |
| **Key derivation** | PBKDF2, 100k iterations, SHA-256, 32-byte salt per entry |
| **Storage** | SQLite (plaintext file), sensitive data encrypted per-entry |
| **Isolation** | Context isolation, sandbox, preload bridge, no `nodeIntegration` |
| **Crypto** | Worker thread, on-demand decryption (passwords not in `getAllEntries`) |

**Protected against:** brute force, rainbow tables, tampering, replay, padding oracle.

**Not protected against:** physical DB access, keyloggers, memory dumps, malware with process access.

See [SECURITY_FEATURES.md](SECURITY_FEATURES.md) for implementation details.

## Configuration

Optional `.env` (see `.env.example`). Defaults work for most setups.

## License

MIT
