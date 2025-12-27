# Password Manager

> ⚠️ **Status: Work in Progress** - This application is currently under active development and is not yet feature-complete. Some features may be incomplete or subject to change.

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

## Security Model

### Encryption Algorithm

**AES-256-GCM (Galois/Counter Mode)**

- **Algorithm**: AES-256 (256-bit key)
- **Mode**: GCM (authenticated encryption)
- **IV Length**: 12 bytes (96 bits) - recommended size for GCM
- **Authentication Tag**: 16 bytes (128 bits)
- **Additional Authenticated Data (AAD)**: `'password-manager-vault'` (context binding)

**Key Derivation: PBKDF2**

- **Function**: PBKDF2 with SHA-256
- **Iterations**: 100,000 (configurable via `PBKDF2_ITERATIONS`)
- **Salt Length**: 32 bytes (256 bits) - unique per entry
- **Key Length**: 32 bytes (256 bits)

**Storage Format:**

- Each entry encrypted separately with unique salt and IV
- Database stores: `encrypted_password` (format: `encrypted:authTag`), `salt`, `iv`, `enc_version`
- Database file itself is **not encrypted** (SQLite plaintext), but all sensitive data inside is encrypted per-entry

### Versioning

**Encryption Version Tracking:**

- `enc_version = 'gcm'`: New entries (v2.0+) - AES-256-GCM
- `enc_version = 'cbc'` or `null`: Legacy entries (v1.0) - AES-256-CBC
- Version stored per-entry in database `enc_version` column

**Application Versions:**

- **v1.0**: Initial release with AES-256-CBC encryption
- **v2.0**: Upgraded to AES-256-GCM with automatic migration

### Architecture

- **Local/Offline**: No cloud sync, all data stored locally in SQLite
- **Renderer Isolation**: Electron preload/IPC with context isolation enabled
- **Worker Thread**: All cryptographic operations performed in dedicated `vault-worker.js` thread
- **On-Demand Decryption**: Passwords fetched via `getEntryPassword()` API, not returned in `getAllEntries()`

### Migration: CBC → GCM

**Automatic Migration:**

- Legacy entries (`enc_version = 'cbc'` or `null`) are automatically detected and re-encrypted to GCM when accessed
- Migration happens transparently during `decrypt()` → `decryptLegacy()` → re-encrypt with GCM
- Original encrypted data preserved in entry history before migration
- New salt and IV generated during migration (prevents correlation attacks)

**Batch Migration:**

- `migrateEntriesToGCM(masterPassword)` function available for bulk migration
- Migrates all entries with `enc_version = 'cbc'` or `NULL` to `'gcm'`
- Returns `{ migrated: count, failed: [{ id, reason }] }`

**Backward Compatibility:**

- Legacy CBC entries continue to work during transition
- CryptoJS used for legacy decryption (backward compatibility)
- Entry history preserves original encrypted format for rollback

### Limitations & Security Considerations

**Memory Security:**
JavaScript's garbage collector does **not** guarantee secure memory wiping. Setting variables to `null` (e.g., `password = null`) is a "best effort" attempt to minimize sensitive data lifetime, but does **not** provide cryptographic-grade secure memory erasure.

**What This Means:**

- Passwords may remain in memory after use until GC runs
- Memory dumps (core dumps, hibernation files) may contain plaintext passwords
- For strict memory security, consider:
  - Native modules with explicit memory clearing (`Buffer.fill(0)`)
  - Secure enclaves or TEE (Trusted Execution Environment)
  - Application-level memory protection policies

**Current Mitigations:**

- Password references cleared immediately after use (`password = null`)
- Cryptographic operations isolated in worker thread
- No sensitive data in logs (production mode)
- Key buffers explicitly zeroed where possible (`key.fill(0)`)

**Database Security:**

- **Database file is NOT encrypted** - SQLite file is plaintext
- **Data inside is encrypted** - each entry encrypted separately
- **Metadata visible**: Entry names, usernames, categories, timestamps are stored in plaintext
- **Structure visible**: Table schema, entry IDs, access counts visible to anyone with file access

**Threat Model:**

**Protected Against:**

- ✅ Unauthorized data access without master password (strong encryption)
- ✅ Data tampering (GCM authentication tag verification)
- ✅ Brute force attacks (PBKDF2 with 100k iterations, account lockout)
- ✅ Rainbow table attacks (per-entry unique salts)
- ✅ Replay attacks (unique IVs per encryption)
- ✅ Padding oracle attacks (GCM mode, not CBC)

**NOT Protected Against:**

- ❌ Physical access to database file (can see structure, metadata, encrypted data)
- ❌ Memory dumps / hibernation files (may contain plaintext passwords)
- ❌ Keyloggers (master password can be captured)
- ❌ Screen capture (only UI-level detection, not prevention)
- ❌ Clipboard monitoring (passwords copied to clipboard)
- ❌ Malware with process memory access
- ❌ OS-level compromise (root/admin access)

**UX Hardening (Not Real Security):**

- DevTools blocking: Can be bypassed, only deters casual inspection
- Context menu blocking: Can be bypassed, only deters casual inspection
- Screen capture detection: Only alerts, doesn't prevent capture
- These features are **UX hardening**, not cryptographic security

## Security Changes & Migration (v2.0)

### Summary

The application was upgraded from **AES-256-CBC** to **AES-256-GCM** encryption in v2.0. See the [Security Model](#security-model) section above for detailed technical specifications.

**Key Changes:**

- ✅ Migrated to authenticated encryption (GCM) with integrity verification
- ✅ Automatic migration of legacy CBC entries on access
- ✅ Explicit version tracking (`enc_version` column per entry)
- ✅ All cryptographic operations isolated in worker thread
- ✅ On-demand password fetching (no bulk password exposure)

**Why GCM?**

- Authenticated encryption prevents tampering
- No padding oracle vulnerabilities (unlike CBC)
- Industry standard for modern applications
- Automatic integrity verification via authentication tags

### Security Improvements (v2.0)

**Cryptography:**

- Migrated from AES-256-CBC to AES-256-GCM (authenticated encryption)
- Unified to Node.js `crypto` module (CryptoJS only for legacy CBC decryption)
- All cryptographic operations delegated to isolated worker thread (`vault-worker.js`)
- Consistent PBKDF2 key derivation: 100,000 iterations, SHA-256, 32-byte keys
- Per-entry unique salts (32 bytes) and IVs (12 bytes for GCM)
- Explicit `enc_version` tracking per entry in database

**Data Protection:**

- Passwords no longer returned in `getAllEntries()` - fetched on-demand via `getEntryPassword(entryId, masterPassword)`
- Reduced sensitive data lifetime in main thread (worker isolation)
- Production logging restrictions (`NODE_ENV !== 'production'` - no sensitive data in logs)
- Enhanced error handling: corrupted GCM data returns `null` immediately (no silent fallback to legacy)
- GCM format validation: `encrypted:authTag` format strictly enforced

**Code Quality:**

- Removed unused imports (`path`, `fs` from worker)
- Removed dead code (`AUTH_TAG_LENGTH`, `sensitiveData` variables)
- Improved error messages for debugging (format errors, migration failures)
- Robust database schema migration with `try/catch` fallbacks
- Worker isolation verified (no `require('./vault')` in worker)

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
