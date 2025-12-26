# Password Manager

Offline-first password manager built with Electron + React. Data is stored locally in SQLite with per-entry encryption.

## Features

- Encrypted vault (AES-256-CBC with PBKDF2 key derivation)
- Entry CRUD: add, edit, delete
- Entry history + rollback
- Bulk operations
- Password generator + strength meter
- Master password management: change password, hint, recovery flows
- Auto-lock on inactivity
- Dark/light theme

## Security model (high level)

- Data at rest is encrypted per entry; the database stores ciphertext + per-entry salt/IV.
- Master password is verified via a stored hash; encryption keys are derived from the master password.
- App is designed for local/offline usage; no cloud sync is built in.
- Renderer is isolated via Electron preload/IPC (context isolation enabled).

Notes:
- “DevTools blocking” and “context menu blocking” are UX hardening and do **not** replace OS-level security.

## Getting started

```bash
npm install
npm run dev
```

## Project structure

- `frontend/`: React + TypeScript UI
- `db/`: vault logic, SQLite, worker
- `main.js` / `preload.js`: Electron main + IPC bridge

## License

MIT
