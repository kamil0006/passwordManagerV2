# Password Manager

Offline-first password manager built with Electron + React. Data is stored locally in SQLite with per-entry encryption.

## Features

- Encrypted vault (AES-256-GCM with PBKDF2 key derivation, automatic migration from legacy CBC)
- Entry CRUD: add, edit, delete
- Entry history + rollback
- Bulk operations
- Password generator + strength meter
- Master password management: change password, hint, recovery flows
- Auto-lock on inactivity
- Dark/light theme

## Security model (high level)

- Data at rest is encrypted per entry using AES-256-GCM; the database stores ciphertext + per-entry salt/IV/authTag.
- Master password is verified via a stored hash; encryption keys are derived from the master password using PBKDF2.
- App is designed for local/offline usage; no cloud sync is built in.
- Renderer is isolated via Electron preload/IPC (context isolation enabled).
- Cryptographic operations are performed in a dedicated worker thread for better isolation.

### Memory Security

**Important**: JavaScript's garbage collector does **not** guarantee secure memory wiping. When the code sets sensitive variables to `null` (e.g., `password = null`), this is a "best effort" attempt to minimize the lifetime of sensitive data in memory, but it does **not** provide cryptographic-grade secure memory erasure. For production deployments requiring strict memory security, consider:

- Using native modules with explicit memory clearing
- Running in a secure enclave or TEE (Trusted Execution Environment)
- Implementing application-level memory protection policies

The current implementation minimizes sensitive data lifetime by:

- Clearing password references immediately after use
- Performing cryptographic operations in an isolated worker thread
- Avoiding logging of sensitive data

Notes:

- "DevTools blocking" and "context menu blocking" are UX hardening and do **not** replace OS-level security.
- Legacy CBC-encrypted entries are automatically migrated to GCM format on access.

## Security Changes & Migration

### Migration: CBC → GCM (v2.0)

The application has been upgraded from AES-256-CBC to **AES-256-GCM** encryption for improved security:

**Why GCM?**

- **Authenticated Encryption**: GCM provides both confidentiality and authenticity, preventing tampering with encrypted data
- **Security**: CBC mode is vulnerable to padding oracle attacks and doesn't provide integrity verification
- **Industry Standard**: GCM is the recommended mode for modern applications

**What Changed:**

- All new entries are encrypted using AES-256-GCM with authentication tags
- Legacy CBC-encrypted entries are automatically migrated to GCM on first access
- Database schema includes `enc_version` column to track encryption format per entry
- Batch migration function available for migrating all legacy entries at once

**Migration Process:**

- Automatic: Legacy entries are detected and re-encrypted when accessed
- Transparent: Users don't need to take any action
- Safe: Original data is preserved in entry history before migration
- Batch: `migrateEntriesToGCM()` function available for bulk migration

**Backward Compatibility:**

- Old CBC-encrypted entries continue to work during transition period
- Migration happens automatically without data loss
- Entry history preserves original encrypted format for rollback capability

### Security Improvements (v2.0)

**Cryptography:**

- Unified encryption to Node.js `crypto` (removed CryptoJS dependency for new data)
- All cryptographic operations delegated to isolated worker thread
- Consistent PBKDF2 key derivation with configurable iterations
- Per-entry unique salts and IVs for enhanced security

**Data Protection:**

- Passwords no longer returned in `getAllEntries()` - fetched on-demand via `getEntryPassword()`
- Reduced sensitive data lifetime in main thread
- Production logging restrictions (no sensitive data in logs)
- Enhanced error handling for corrupted GCM data (prevents silent fallback to legacy)

**Code Quality:**

- Removed unused imports and dead code
- Improved error messages for debugging
- Better handling of database schema migrations
- Worker isolation verified

## How to Run

### Prerequisites

- Node.js 18+
- npm or yarn

### Installation

1. Clone the repository:

```bash
git clone <repository-url>
cd passwordManager
```

2. Install dependencies:

```bash
npm install
cd frontend
npm install
cd ..
```

3. (Optional) Configure environment variables:

```bash
cp .env.example .env
# Edit .env if needed (usually not required for development)
```

4. Start the development server:

```bash
npm run dev
```

This will:

- Start the Vite dev server for the frontend (usually on http://localhost:5173)
- Launch the Electron app automatically

### Building for Production

```bash
cd frontend
npm run build
cd ..
# Then package with Electron Builder (if configured)
```

## Project structure

- `frontend/`: React + TypeScript UI
- `db/`: vault logic, SQLite, worker
- `main.js` / `preload.js`: Electron main + IPC bridge

## Configuration

The app uses environment variables for configuration (see `.env.example`). Most settings have sensible defaults and don't require configuration for basic usage.

## License

MIT
