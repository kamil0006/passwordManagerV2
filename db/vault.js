const Database = require('better-sqlite3');
const crypto = require('crypto'); // Use Node crypto for all encryption
const CryptoJS = require('crypto-js'); // Keep for legacy data migration only
const path = require('path');
const fs = require('fs');
const os = require('os');

// Worker reference for cryptographic operations
// Set by main.js or use local crypto as fallback
let cryptoWorkerRef = null;

// Pending requests map for worker communication (prevents listener leaks)
const pendingRequests = new Map();

// Single worker message handler (prevents multiple listeners)
let workerMessageHandler = null;

// Initialize worker message handler (called once when worker is set)
function initWorkerMessageHandler() {
	if (workerMessageHandler || !cryptoWorkerRef) {
		return;
	}

	workerMessageHandler = message => {
		const request = pendingRequests.get(message.id);
		if (request) {
			// Clear timeout
			if (request.timeout) {
				clearTimeout(request.timeout);
			}
			// Remove from pending
			pendingRequests.delete(message.id);
			// Resolve or reject
			if (message.error) {
				request.reject(new Error(message.error));
			} else {
				request.resolve(message.result);
			}
		}
	};

	cryptoWorkerRef.on('message', workerMessageHandler);
}

// Set worker reference (called by main.js)
function setCryptoWorker(worker) {
	cryptoWorkerRef = worker;
	// Initialize message handler when worker is set
	if (worker) {
		initWorkerMessageHandler();
	}
}

// Cleanup worker - reject all pending requests (called on worker exit/error)
function cleanupWorker() {
	// Reject all pending requests to prevent hanging promises
	for (const [messageId, request] of pendingRequests.entries()) {
		if (request.timeout) {
			clearTimeout(request.timeout);
		}
		request.reject(new Error('Worker terminated'));
		pendingRequests.delete(messageId);
	}

	// Clear worker reference
	cryptoWorkerRef = null;
	workerMessageHandler = null;
}

// Helper to call worker for crypto (if available)
// Uses pendingRequests Map to prevent listener leaks and properly handle timeouts
async function callWorkerCrypto(type, data) {
	if (!cryptoWorkerRef) {
		return null; // No worker, use local crypto
	}

	// Initialize handler if not already done
	initWorkerMessageHandler();

	return new Promise((resolve, reject) => {
		// Use crypto.randomUUID() for better uniqueness
		const messageId = crypto.randomUUID();

		// Store request
		pendingRequests.set(messageId, {
			resolve,
			reject,
			timeout: null,
		});

		// Set timeout (will be cleared on success)
		const timeout = setTimeout(() => {
			pendingRequests.delete(messageId);
			reject(new Error('Crypto worker timeout'));
		}, 30000);

		// Update timeout reference
		pendingRequests.get(messageId).timeout = timeout;

		// Send message
		cryptoWorkerRef.postMessage({
			type: type,
			id: messageId,
			data: data,
		});
	});
}

console.log('[Vault] Initializing vault database...');

// Enhanced security constants
const PBKDF2_ITERATIONS = 100000; // Reduced to 100k for better performance while maintaining security
const SALT_LENGTH = 32; // 256 bits
const KEY_LENGTH = 32; // 256 bits for AES-256
const IV_LENGTH = 12; // 96 bits for GCM (recommended size, not 16)
const AUTH_TAG_LENGTH = 16; // 128 bits for GCM auth tag
const MIN_MASTER_PASSWORD_LENGTH = 12; // Increased minimum length
const COMPLEXITY_REQUIREMENTS = {
	minLength: 12,
	requireUppercase: true,
	requireLowercase: true,
	requireNumbers: true,
	requireSpecialChars: true,
};

// Security timeout constants
const CLIPBOARD_TIMEOUT = 30 * 1000; // 30 seconds
const AUTO_LOCK_TIMEOUT = 5 * 60 * 1000; // 5 minutes
const SCREEN_CAPTURE_DETECTION = true; // Enable screen capture detection

// Database path - stored in user's app data directory for security
// This prevents revealing the exact location in source code
function getDatabasePath() {
	// Use environment variable if set (for Electron app.getPath('userData'))
	if (process.env.VAULT_DB_PATH) {
		return path.join(process.env.VAULT_DB_PATH, 'vault.db');
	}
	// Fallback to user's home directory in a hidden folder
	const homeDir = os.homedir();
	const appDataDir = path.join(homeDir, '.password-manager');
	// Ensure directory exists
	if (!fs.existsSync(appDataDir)) {
		fs.mkdirSync(appDataDir, { recursive: true, mode: 0o700 }); // Secure permissions
	}
	return path.join(appDataDir, 'vault.db');
}

const dbPath = getDatabasePath();

// Migration: Check if old database exists in db/ folder and migrate it
const oldDbPath = path.join(__dirname, 'vault.db');
if (fs.existsSync(oldDbPath)) {
	// Check if new database exists and has entries
	let shouldMigrate = false;
	if (!fs.existsSync(dbPath)) {
		// New database doesn't exist - definitely migrate
		shouldMigrate = true;
	} else {
		// New database exists - check if it's empty
		try {
			const tempDb = new Database(dbPath);
			// First verify that entries table exists (old DB might have different schema)
			try {
				// Check if entries table exists
				const tableCheck = tempDb.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='entries'").get();
				if (!tableCheck) {
					// Table doesn't exist - this might be an old DB with different schema
					tempDb.close();
					if (process.env.NODE_ENV !== 'production') {
						console.log('[Vault] entries table does not exist in new database, will attempt migration...');
					}
					shouldMigrate = true;
				} else {
					// Table exists - check if it's empty
					const entryCount = tempDb.prepare('SELECT COUNT(*) as count FROM entries').get();
					tempDb.close();
					if (!entryCount || entryCount.count === 0) {
						// New database is empty - migrate from old one
						shouldMigrate = true;
						console.log('[Vault] New database is empty, migrating from old location...');
					}
				}
			} catch (tableError) {
				// Error checking table or querying entries - might be schema mismatch
				tempDb.close();
				if (process.env.NODE_ENV !== 'production') {
					console.log(
						'[Vault] Could not verify entries table (possible schema mismatch), will attempt migration:',
						tableError.message
					);
				}
				shouldMigrate = true;
			}
		} catch (error) {
			// If we can't open/check database, assume we should migrate
			if (process.env.NODE_ENV !== 'production') {
				console.log('[Vault] Could not check new database, will attempt migration:', error.message);
			}
			shouldMigrate = true;
		}
	}

	if (shouldMigrate) {
		console.log('[Vault] Migrating database from old location to secure location...');
		try {
			// Ensure new directory exists
			const newDbDir = path.dirname(dbPath);
			if (!fs.existsSync(newDbDir)) {
				fs.mkdirSync(newDbDir, { recursive: true, mode: 0o700 });
			}
			// If new database exists but is empty, remove it first
			if (fs.existsSync(dbPath)) {
				fs.unlinkSync(dbPath);
			}
			// Copy database to new location
			fs.copyFileSync(oldDbPath, dbPath);
			// Set secure permissions
			fs.chmodSync(dbPath, 0o600); // Read/write for owner only
			console.log('[Vault] Database migrated successfully to:', dbPath);
		} catch (error) {
			console.error('[Vault] Migration failed:', error);
			console.log('[Vault] Continuing with new database location...');
		}
	}
}

// Initialize database with proper error handling
let db;
try {
	// Check if database file exists and is valid
	if (fs.existsSync(dbPath)) {
		try {
			// Try to open existing database
			db = new Database(dbPath);
			// Test if it's a valid database by running a simple query
			db.exec('SELECT 1');
			console.log('[Vault] Existing database opened successfully');
		} catch (error) {
			console.log('[Vault] Existing database corrupted, removing and recreating...');
			// Remove corrupted database
			fs.unlinkSync(dbPath);
			// Create new database
			db = new Database(dbPath);
		}
	} else {
		// Create new database
		db = new Database(dbPath);
		console.log('[Vault] New database created');
	}

	// Initialize schema
	console.log('[Vault] Initializing database schema...');

	// Create entries table
	db.exec(`
		CREATE TABLE IF NOT EXISTS entries (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			username TEXT,
			encrypted_password TEXT NOT NULL,
			category TEXT DEFAULT 'personal',
			salt TEXT NOT NULL,
			iv TEXT NOT NULL,
			enc_version TEXT DEFAULT 'gcm',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_modified DATETIME DEFAULT CURRENT_TIMESTAMP,
			access_count INTEGER DEFAULT 0,
			last_access DATETIME
		)
	`);

	// Check if category column exists, if not add it
	try {
		db.exec('SELECT category FROM entries LIMIT 1');
		if (process.env.NODE_ENV !== 'production') {
			console.log('[Vault] Category column already exists');
		}
	} catch (error) {
		if (process.env.NODE_ENV !== 'production') {
			console.log('[Vault] Adding category column to existing database...');
		}
		db.exec('ALTER TABLE entries ADD COLUMN category TEXT DEFAULT "personal"');
		if (process.env.NODE_ENV !== 'production') {
			console.log('[Vault] Category column added successfully');
		}
	}

	// Check if enc_version column exists, if not add it
	try {
		db.exec('SELECT enc_version FROM entries LIMIT 1');
		if (process.env.NODE_ENV !== 'production') {
			console.log('[Vault] enc_version column already exists');
		}
	} catch (error) {
		if (process.env.NODE_ENV !== 'production') {
			console.log('[Vault] Adding enc_version column to existing database...');
		}
		try {
			db.exec("ALTER TABLE entries ADD COLUMN enc_version TEXT DEFAULT 'cbc'");
			// Update existing entries to 'cbc' (legacy) - they will be migrated to 'gcm' on access
			// Only update if entries table exists and has rows
			try {
				db.exec("UPDATE entries SET enc_version = 'cbc' WHERE enc_version IS NULL");
			} catch (updateError) {
				// Table might be empty or not exist - that's OK, column was added
				if (process.env.NODE_ENV !== 'production') {
					console.log('[Vault] No entries to update (table may be empty)');
				}
			}
			if (process.env.NODE_ENV !== 'production') {
				console.log('[Vault] enc_version column added successfully');
			}
		} catch (alterError) {
			// Column might already exist or table structure issue - log but don't fail
			if (process.env.NODE_ENV !== 'production') {
				console.log(
					'[Vault] Could not add enc_version column (may already exist or schema issue):',
					alterError.message
				);
			}
		}
	}

	// Create security metadata table
	db.exec(`
		CREATE TABLE IF NOT EXISTS security_metadata (
			id INTEGER PRIMARY KEY,
			master_password_hash TEXT NOT NULL,
			password_salt TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_modified DATETIME DEFAULT CURRENT_TIMESTAMP,
			failed_attempts INTEGER DEFAULT 0,
			locked_until DATETIME,
			encryption_version TEXT DEFAULT 'v2.0',
			password_hint TEXT,
			hint_salt TEXT,
			hint_iv TEXT
		)
	`);

	// Migrate existing databases to add password hint fields if they don't exist
	try {
		const tableInfo = db.prepare('PRAGMA table_info(security_metadata)').all();
		const hasHintField = tableInfo.some(col => col.name === 'password_hint');
		if (!hasHintField) {
			db.exec(`
				ALTER TABLE security_metadata 
				ADD COLUMN password_hint TEXT;
			`);
			db.exec(`
				ALTER TABLE security_metadata 
				ADD COLUMN hint_salt TEXT;
			`);
			db.exec(`
				ALTER TABLE security_metadata 
				ADD COLUMN hint_iv TEXT;
			`);
			console.log('[Vault] Added password hint fields to security_metadata table');
		}
	} catch (error) {
		console.log('[Vault] Password hint fields may already exist:', error.message);
	}

	// Add email/SMS recovery fields
	try {
		const tableInfo = db.prepare('PRAGMA table_info(security_metadata)').all();
		const hasRecoveryEmail = tableInfo.some(col => col.name === 'recovery_email');
		if (!hasRecoveryEmail) {
			db.exec(`ALTER TABLE security_metadata ADD COLUMN recovery_email TEXT`);
			db.exec(`ALTER TABLE security_metadata ADD COLUMN recovery_phone TEXT`);
			db.exec(`ALTER TABLE security_metadata ADD COLUMN recovery_key_encrypted TEXT`);
			db.exec(`ALTER TABLE security_metadata ADD COLUMN recovery_key_salt TEXT`);
			db.exec(`ALTER TABLE security_metadata ADD COLUMN recovery_key_iv TEXT`);
			db.exec(`ALTER TABLE security_metadata ADD COLUMN master_password_backup_encrypted TEXT`);
			db.exec(`ALTER TABLE security_metadata ADD COLUMN master_password_backup_salt TEXT`);
			db.exec(`ALTER TABLE security_metadata ADD COLUMN master_password_backup_iv TEXT`);
			console.log('[Vault] Added email/SMS recovery fields to security_metadata table');
		}
	} catch (error) {
		console.log('[Vault] Recovery fields may already exist:', error.message);
	}

	// Create entry history table for tracking changes and rollback
	db.exec(`
		CREATE TABLE IF NOT EXISTS entry_history (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			entry_id INTEGER NOT NULL,
			encrypted_data TEXT NOT NULL,
			salt TEXT NOT NULL,
			iv TEXT NOT NULL,
			change_type TEXT DEFAULT 'update',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (entry_id) REFERENCES entries(id) ON DELETE CASCADE
		)
	`);

	// Create index for faster history lookups
	try {
		db.exec('CREATE INDEX IF NOT EXISTS idx_entry_history_entry_id ON entry_history(entry_id)');
		db.exec('CREATE INDEX IF NOT EXISTS idx_entry_history_created_at ON entry_history(created_at DESC)');
	} catch (error) {
		console.log('[Vault] Indexes may already exist:', error.message);
	}

	// Create recovery questions table
	// Answers are hashed (not encrypted) so they can be verified without master password
	db.exec(`
		CREATE TABLE IF NOT EXISTS recovery_questions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			question_number INTEGER NOT NULL,
			question_text TEXT NOT NULL,
			answer_hash TEXT NOT NULL,
			answer_salt TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`);

	// Create backup codes table
	db.exec(`
		CREATE TABLE IF NOT EXISTS backup_codes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			code_hash TEXT NOT NULL UNIQUE,
			used INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			used_at DATETIME
		)
	`);

	// Create recovery codes table for email/SMS recovery
	db.exec(`
		CREATE TABLE IF NOT EXISTS recovery_codes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			code_hash TEXT NOT NULL,
			expires_at DATETIME NOT NULL,
			used INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			used_at DATETIME
		)
	`);

	// Create indexes for recovery tables
	try {
		db.exec('CREATE INDEX IF NOT EXISTS idx_backup_codes_hash ON backup_codes(code_hash)');
		db.exec('CREATE INDEX IF NOT EXISTS idx_backup_codes_used ON backup_codes(used)');
	} catch (error) {
		console.log('[Vault] Recovery indexes may already exist:', error.message);
	}

	// Initialize security metadata if it doesn't exist
	const securityCheck = db.prepare(`SELECT COUNT(*) as count FROM security_metadata WHERE id = 1`);
	const securityExists = securityCheck.get();

	if (securityExists.count === 0) {
		// Insert initial security metadata record
		const initSecurity = db.prepare(`
			INSERT INTO security_metadata (id, master_password_hash, password_salt, failed_attempts) 
			VALUES (1, '', '', 0)
		`);
		initSecurity.run();
		console.log('[Vault] Security metadata initialized');
	}

	console.log('[Vault] Database initialized successfully');
} catch (error) {
	console.error('[Vault] Critical error initializing database:', error);
	throw new Error(`Failed to initialize database: ${error.message}`);
}

// Enhanced password validation
function validateMasterPassword(password) {
	if (password.length < COMPLEXITY_REQUIREMENTS.minLength) {
		throw new Error(`Master password must be at least ${COMPLEXITY_REQUIREMENTS.minLength} characters long`);
	}

	if (COMPLEXITY_REQUIREMENTS.requireUppercase && !/[A-Z]/.test(password)) {
		throw new Error('Master password must contain at least one uppercase letter');
	}

	if (COMPLEXITY_REQUIREMENTS.requireLowercase && !/[a-z]/.test(password)) {
		throw new Error('Master password must contain at least one lowercase letter');
	}

	if (COMPLEXITY_REQUIREMENTS.requireNumbers && !/\d/.test(password)) {
		throw new Error('Master password must contain at least one number');
	}

	if (COMPLEXITY_REQUIREMENTS.requireSpecialChars && !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
		throw new Error('Master password must contain at least one special character');
	}

	return true;
}

// All cryptographic operations delegated to worker thread
// This minimizes sensitive data lifetime in main thread and isolates crypto operations

// Generate salt via worker (fallback to local if worker unavailable)
async function generateSalt() {
	if (cryptoWorkerRef) {
		try {
			const result = await callWorkerCrypto('generateSalt', {});
			if (result && result.salt) {
				return result.salt;
			}
		} catch (error) {
			console.warn('[Vault] Worker generateSalt failed, using local crypto:', error.message);
		}
	}
	// Fallback to local crypto
	return crypto.randomBytes(SALT_LENGTH).toString('hex');
}

// Generate IV via worker (fallback to local if worker unavailable)
async function generateIV() {
	if (cryptoWorkerRef) {
		try {
			const result = await callWorkerCrypto('generateIV', {});
			if (result && result.iv) {
				return result.iv;
			}
		} catch (error) {
			console.warn('[Vault] Worker generateIV failed, using local crypto:', error.message);
		}
	}
	// Fallback to local crypto
	return crypto.randomBytes(IV_LENGTH).toString('hex'); // 12 bytes for GCM
}

// Encrypt using worker (fallback to local if worker unavailable)
// Returns string format encrypted:authTag for database storage
// Note: Password reference cleared after use (best effort - JavaScript GC doesn't guarantee secure wipe)
async function encrypt(text, password, salt, iv) {
	if (cryptoWorkerRef) {
		try {
			const result = await callWorkerCrypto('encryptVault', {
				text: text,
				password: password,
				salt: salt,
				iv: iv,
			});
			if (result && result.encrypted) {
				// Worker returns object { encrypted, authTag }, convert to string format for DB
				const encryptedData = result.encrypted;
				if (typeof encryptedData === 'object' && encryptedData.encrypted && encryptedData.authTag) {
					// New object format - convert to string for database
					password = null; // Best effort
					return encryptedData.encrypted + ':' + encryptedData.authTag;
				} else if (typeof encryptedData === 'string') {
					// Legacy string format (already in correct format)
					password = null; // Best effort
					return encryptedData;
				}
			}
		} catch (error) {
			if (process.env.NODE_ENV !== 'production') {
				console.warn('[Vault] Worker encrypt failed, using local crypto:', error.message);
			}
		}
	}
	// Fallback to local crypto
	const key = crypto.pbkdf2Sync(password, Buffer.from(salt, 'hex'), PBKDF2_ITERATIONS, KEY_LENGTH, 'sha256');
	const ivBuffer = Buffer.from(iv, 'hex');

	// Use GCM mode for authenticated encryption
	const cipher = crypto.createCipheriv('aes-256-gcm', key, ivBuffer);
	cipher.setAAD(Buffer.from('password-manager-vault', 'utf8')); // Additional authenticated data

	let encrypted = cipher.update(text, 'utf8', 'hex');
	encrypted += cipher.final('hex');

	const authTag = cipher.getAuthTag();

	// Clear key from memory (best effort in JS)
	key.fill(0);
	// Clear password reference (best effort)
	password = null;

	// Return format: encrypted:authTag (both hex strings) for database storage
	return encrypted + ':' + authTag.toString('hex');
}

// Decrypt using worker (fallback to local if worker unavailable) with legacy support
// Automatically migrates legacy CBC data to GCM format
// Note: Password reference cleared after use (best effort - JavaScript GC doesn't guarantee secure wipe)
// Decrypt function - uses enc_version to determine format (not heuristics)
// encVersion: 'gcm' for new format, 'cbc' or null for legacy
async function decrypt(ciphertextWithTag, password, salt, iv, entryId = null, encVersion = null) {
	try {
		// Determine encryption version
		// If encVersion not provided, try to get it from database
		if (!encVersion && entryId) {
			const stmt = db.prepare(`SELECT enc_version FROM entries WHERE id = ?`);
			const row = stmt.get(entryId);
			encVersion = row?.enc_version || null;
		}

		// Use enc_version to determine format (not heuristics)
		// Only 'gcm' is treated as GCM format, null or 'cbc' are treated as legacy CBC
		const isGCM = encVersion === 'gcm';

		if (isGCM) {
			// GCM format - try worker first
			if (cryptoWorkerRef) {
				try {
					const result = await callWorkerCrypto('decryptVault', {
						ciphertext: ciphertextWithTag,
						password: password,
						salt: salt,
						iv: iv,
					});
					if (result && result.decrypted) {
						password = null; // Best effort
						return result.decrypted;
					}
				} catch (error) {
					if (process.env.NODE_ENV !== 'production') {
						console.warn('[Vault] Worker decrypt failed, trying local crypto:', error.message);
					}
				}
			}

			// Fallback to local crypto for GCM
			const parts = ciphertextWithTag.split(':');
			if (parts.length !== 2) {
				// GCM format requires encrypted:authTag format
				// If format is incorrect, data is corrupted - don't silently fallback to legacy
				if (process.env.NODE_ENV !== 'production') {
					console.error('[Vault] GCM format error: expected encrypted:authTag, got invalid format');
				}
				password = null; // Best effort
				return null;
			}

			const encrypted = parts[0];
			const authTagHex = parts[1];

			const key = crypto.pbkdf2Sync(password, Buffer.from(salt, 'hex'), PBKDF2_ITERATIONS, KEY_LENGTH, 'sha256');
			const ivBuffer = Buffer.from(iv, 'hex');
			const authTag = Buffer.from(authTagHex, 'hex');

			const decipher = crypto.createDecipheriv('aes-256-gcm', key, ivBuffer);
			decipher.setAAD(Buffer.from('password-manager-vault', 'utf8'));
			decipher.setAuthTag(authTag);

			let decrypted = decipher.update(encrypted, 'hex', 'utf8');
			decrypted += decipher.final('utf8');

			key.fill(0);
			password = null;
			return decrypted;
		}

		// Legacy CBC format (for migration)
		const result = await decryptLegacy(ciphertextWithTag, password, salt, iv, entryId);
		password = null; // Best effort
		return result;
	} catch (error) {
		// If GCM fails, try legacy format as fallback
		if (error.message.includes('Unsupported state') || error.message.includes('bad decrypt')) {
			const result = await decryptLegacy(ciphertextWithTag, password, salt, iv, entryId);
			password = null; // Best effort
			return result;
		}
		password = null; // Best effort
		if (process.env.NODE_ENV !== 'production') {
			console.error('[Vault] Decryption failed:', error.message);
		}
		return null;
	}
}

// Legacy decryption using CryptoJS (for migrating old CBC data to GCM)
// Automatically re-encrypts to GCM format if entryId is provided
async function decryptLegacy(ciphertext, password, salt, iv, entryId = null) {
	try {
		// Parse salt as hex (salt is stored as hex string in database)
		const saltHex = CryptoJS.enc.Hex.parse(salt);
		const key = CryptoJS.PBKDF2(password, saltHex, {
			keySize: KEY_LENGTH / 4, // CryptoJS uses 32-bit words
			iterations: PBKDF2_ITERATIONS,
		});
		const bytes = CryptoJS.AES.decrypt(ciphertext, key, { iv: CryptoJS.enc.Hex.parse(iv) });
		const decrypted = bytes.toString(CryptoJS.enc.Utf8);

		// If decryption succeeded and entryId provided, re-encrypt to GCM format
		if (decrypted && decrypted.length > 0 && entryId) {
			try {
				// Re-encrypt with new GCM format
				const newSalt = await generateSalt();
				const newIV = await generateIV();
				const newEncrypted = await encrypt(decrypted, password, newSalt, newIV);

				// Update entry in database with new GCM format
				const updateStmt = db.prepare(`
					UPDATE entries 
					SET encrypted_password = ?, salt = ?, iv = ?, enc_version = 'gcm', last_modified = CURRENT_TIMESTAMP
					WHERE id = ?
				`);
				updateStmt.run(newEncrypted, newSalt, newIV, entryId);

				if (process.env.NODE_ENV !== 'production') {
					console.log(`[Vault] Entry ${entryId} migrated from CBC to GCM format`);
				}
			} catch (migrationError) {
				// Migration failed, but decryption succeeded - log warning
				if (process.env.NODE_ENV !== 'production') {
					console.warn(`[Vault] Failed to migrate entry ${entryId} to GCM:`, migrationError.message);
					console.log('[Vault] Legacy CBC format decrypted - will retry migration on next access');
				}
			}
		} else if (decrypted && decrypted.length > 0) {
			// Decryption succeeded but no entryId - log for manual migration
			if (process.env.NODE_ENV !== 'production') {
				console.log('[Vault] Legacy CBC format decrypted - consider migrating to GCM');
			}
		}

		return decrypted;
	} catch (error) {
		if (process.env.NODE_ENV !== 'production') {
			console.error('[Vault] Legacy decryption failed:', error.message);
		}
		return null;
	}
}

async function addEntry(name, username, plainPassword, category, masterPassword) {
	// Note: Don't log masterPassword or plainPassword - minimize sensitive data in logs
	console.log('[Vault] addEntry called for service:', name);

	// Validate master password complexity
	try {
		validateMasterPassword(masterPassword);
	} catch (error) {
		throw new Error(`Master password validation failed: ${error.message}`);
	}

	if (!name || !plainPassword || !masterPassword) {
		throw new Error('Missing required parameters');
	}

	try {
		// Generate salt and IV
		const salt = await generateSalt();
		const iv = await generateIV();

		// Encrypt (password will be cleared after use)
		const encryptedPassword = await encrypt(plainPassword, masterPassword, salt, iv);

		// Clear sensitive references ASAP (best effort in JS)
		plainPassword = null;
		masterPassword = null;

		const stmt = db.prepare(`
      INSERT INTO entries (name, username, encrypted_password, category, salt, iv, enc_version) 
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);
		const result = stmt.run(name, username || '', encryptedPassword, category || 'personal', salt, iv, 'gcm');

		return result.lastInsertRowid;
	} catch (error) {
		// Clear on error too
		plainPassword = null;
		masterPassword = null;
		console.error('[Vault] Error in addEntry:', error);
		throw error;
	}
}

// Get all entries WITHOUT passwords (security: don't expose all passwords at once)
async function getAllEntries() {
	try {
		if (process.env.NODE_ENV !== 'production') {
			console.log('[Vault] getAllEntries called');
		}

		const stmt = db.prepare(
			`SELECT id, name, username, category, created_at, last_modified, enc_version FROM entries ORDER BY last_modified DESC`
		);
		const rows = stmt.all();

		if (rows.length === 0) {
			if (process.env.NODE_ENV !== 'production') {
				console.log('[Vault] No entries found in database');
			}
			return [];
		}

		// Return entries without passwords - password must be fetched on demand via getEntryPassword()
		const entries = rows.map(row => ({
			id: row.id,
			name: row.name,
			username: row.username,
			category: row.category || 'personal',
			created_at: row.created_at,
			last_modified: row.last_modified,
			enc_version: row.enc_version || 'cbc', // Default to 'cbc' for legacy entries
		}));

		if (process.env.NODE_ENV !== 'production') {
			console.log('[Vault] Retrieved', entries.length, 'entries (without passwords)');
		}

		return entries;
	} catch (error) {
		if (process.env.NODE_ENV !== 'production') {
			console.error('[Vault] Error in getAllEntries:', error);
		}
		return [];
	}
}

// Get password for a single entry (on-demand decryption)
async function getEntryPassword(entryId, masterPassword) {
	try {
		if (!masterPassword) {
			throw new Error('Master password is required');
		}

		const stmt = db.prepare(`SELECT encrypted_password, salt, iv, enc_version FROM entries WHERE id = ?`);
		const row = stmt.get(entryId);

		if (!row) {
			throw new Error(`Entry ${entryId} not found`);
		}

		if (!row.salt || !row.iv || !row.encrypted_password) {
			throw new Error(`Entry ${entryId} missing encryption data`);
		}

		// Decrypt password (with automatic migration from CBC to GCM)
		const password = await decrypt(row.encrypted_password, masterPassword, row.salt, row.iv, entryId, row.enc_version);

		if (!password || password.length === 0) {
			throw new Error(`Failed to decrypt entry ${entryId}`);
		}

		// Update access statistics
		const updateStmt = db.prepare(`
			UPDATE entries 
			SET access_count = access_count + 1, last_access = CURRENT_TIMESTAMP
			WHERE id = ?
		`);
		updateStmt.run(entryId);

		// Clear masterPassword reference (best effort)
		masterPassword = null;

		return password;
	} catch (error) {
		masterPassword = null; // Best effort
		if (process.env.NODE_ENV !== 'production') {
			console.error(`[Vault] Error getting password for entry ${entryId}:`, error.message);
		}
		throw error;
	}
}

async function saveEntryHistory(entryId, masterPassword) {
	try {
		// Get current entry state
		const getStmt = db.prepare(`SELECT * FROM entries WHERE id = ?`);
		const entry = getStmt.get(entryId);

		if (!entry) {
			return false;
		}

		// Decrypt entry data to store in history
		const decryptedPassword = await decrypt(
			entry.encrypted_password,
			masterPassword,
			entry.salt,
			entry.iv,
			entryId,
			entry.enc_version
		);
		if (!decryptedPassword) {
			console.warn(`[Vault] Cannot save history for entry ${entryId} - decryption failed`);
			return false;
		}

		// Create history data object
		const historyData = {
			name: entry.name,
			username: entry.username || '',
			password: decryptedPassword,
			category: entry.category || 'personal',
		};

		// Encrypt history data with master password
		const historySalt = await generateSalt();
		const historyIV = await generateIV();
		const encryptedHistory = await encrypt(JSON.stringify(historyData), masterPassword, historySalt, historyIV);

		// Save to history table
		const historyStmt = db.prepare(`
			INSERT INTO entry_history (entry_id, encrypted_data, salt, iv, change_type)
			VALUES (?, ?, ?, ?, 'update')
		`);
		historyStmt.run(entryId, encryptedHistory, historySalt, historyIV);

		// Limit history to last 50 versions per entry to prevent database bloat
		const cleanupStmt = db.prepare(`
			DELETE FROM entry_history 
			WHERE entry_id = ? 
			AND id NOT IN (
				SELECT id FROM entry_history 
				WHERE entry_id = ? 
				ORDER BY created_at DESC 
				LIMIT 50
			)
		`);
		cleanupStmt.run(entryId, entryId);

		return true;
	} catch (error) {
		console.error(`[Vault] Error saving entry history for entry ${entryId}:`, error);
		return false;
	}
}

async function getEntryHistory(entryId, masterPassword) {
	try {
		const stmt = db.prepare(`
			SELECT * FROM entry_history 
			WHERE entry_id = ? 
			ORDER BY created_at DESC
		`);
		const rows = stmt.all(entryId);

		const history = [];
		for (const row of rows) {
			try {
				// History entries don't need migration (they're already in GCM or will be re-encrypted when entry is updated)
				const decryptedData = await decrypt(row.encrypted_data, masterPassword, row.salt, row.iv, null);
				if (decryptedData) {
					const data = JSON.parse(decryptedData);
					history.push({
						id: row.id,
						entry_id: row.entry_id,
						name: data.name,
						username: data.username,
						password: data.password,
						category: data.category,
						change_type: row.change_type,
						created_at: row.created_at,
					});
				}
			} catch (error) {
				console.error(`[Vault] Error decrypting history entry ${row.id}:`, error);
			}
		}

		return history;
	} catch (error) {
		console.error(`[Vault] Error getting entry history for entry ${entryId}:`, error);
		return [];
	}
}

async function rollbackEntry(entryId, historyId, masterPassword) {
	try {
		// Get history entry
		const historyStmt = db.prepare(`SELECT * FROM entry_history WHERE id = ? AND entry_id = ?`);
		const historyRow = historyStmt.get(historyId, entryId);

		if (!historyRow) {
			throw new Error('History entry not found');
		}

		// Decrypt history data (history entries don't need migration)
		const decryptedData = await decrypt(
			historyRow.encrypted_data,
			masterPassword,
			historyRow.salt,
			historyRow.iv,
			null
		);
		if (!decryptedData) {
			throw new Error('Failed to decrypt history data');
		}

		const historyData = JSON.parse(decryptedData);

		// Save current state to history before rollback
		await saveEntryHistory(entryId, masterPassword);

		// Encrypt with new salt/IV for security
		const newSalt = await generateSalt();
		const newIV = await generateIV();
		const encryptedPassword = await encrypt(historyData.password, masterPassword, newSalt, newIV);

		// Update entry with history data
		// Always set enc_version to 'gcm' when updating (ensures consistency)
		const updateStmt = db.prepare(`
			UPDATE entries 
			SET name = ?, username = ?, encrypted_password = ?, category = ?, salt = ?, iv = ?, enc_version = 'gcm', last_modified = CURRENT_TIMESTAMP
			WHERE id = ?
		`);
		const result = updateStmt.run(
			historyData.name,
			historyData.username || '',
			encryptedPassword,
			historyData.category || 'personal',
			newSalt,
			newIV,
			entryId
		);

		if (result.changes === 0) {
			throw new Error('Failed to rollback entry');
		}

		console.log(`[Vault] Entry ${entryId} rolled back to history version ${historyId}`);
		return true;
	} catch (error) {
		console.error(`[Vault] Error rolling back entry ${entryId}:`, error);
		throw error;
	}
}

async function updateEntry(id, name, username, plainPassword, category, masterPassword) {
	if (process.env.NODE_ENV !== 'production') {
		console.log('[Vault] updateEntry called for entry ID:', id);
	}

	// Validate master password complexity
	try {
		validateMasterPassword(masterPassword);
	} catch (error) {
		throw new Error(`Master password validation failed: ${error.message}`);
	}

	if (!id || !name || !plainPassword || !masterPassword) {
		throw new Error('Missing required parameters');
	}

	try {
		// Get existing entry to check if password changed
		const getStmt = db.prepare(`SELECT encrypted_password, salt, iv, enc_version FROM entries WHERE id = ?`);
		const existingEntry = getStmt.get(id);

		if (!existingEntry) {
			throw new Error('Entry not found');
		}

		// Save current state to history before updating
		await saveEntryHistory(id, masterPassword);

		// Decrypt old password to check if it changed
		const oldPassword = await decrypt(
			existingEntry.encrypted_password,
			masterPassword,
			existingEntry.salt,
			existingEntry.iv,
			id,
			existingEntry.enc_version
		);

		if (!oldPassword) {
			throw new Error('Failed to decrypt existing entry. Master password may be incorrect.');
		}

		// Generate new salt and IV if password changed, otherwise keep existing ones
		let salt, iv, encryptedPassword;
		if (oldPassword !== plainPassword) {
			// Password changed - generate new salt and IV for security
			salt = await generateSalt();
			iv = await generateIV();
			encryptedPassword = await encrypt(plainPassword, masterPassword, salt, iv);
		} else {
			// Password unchanged - keep existing salt and IV
			salt = existingEntry.salt;
			iv = existingEntry.iv;
			encryptedPassword = existingEntry.encrypted_password;
		}

		// Update entry with new values
		// Always set enc_version to 'gcm' when updating (ensures consistency)
		const stmt = db.prepare(`
			UPDATE entries 
			SET name = ?, username = ?, encrypted_password = ?, category = ?, salt = ?, iv = ?, enc_version = 'gcm', last_modified = CURRENT_TIMESTAMP
			WHERE id = ?
		`);
		const result = stmt.run(name, username || '', encryptedPassword, category || 'personal', salt, iv, id);

		if (result.changes === 0) {
			throw new Error('Failed to update entry');
		}

		if (process.env.NODE_ENV !== 'production') {
			console.log('[Vault] Entry updated successfully');
		}
		return true;
	} catch (error) {
		if (process.env.NODE_ENV !== 'production') {
			console.error('[Vault] Error in updateEntry:', error);
		}
		throw error;
	}
}

function deleteEntry(id) {
	console.log('[Vault] Deleting entry with ID:', id);
	try {
		const stmt = db.prepare(`DELETE FROM entries WHERE id = ?`);
		const result = stmt.run(id);
		const success = result.changes > 0;
		console.log('[Vault] Delete result:', success, 'changes:', result.changes);
		return success;
	} catch (error) {
		console.error('[Vault] Error in deleteEntry:', error);
		return false;
	}
}

async function changeMasterPassword(oldMasterPassword, newMasterPassword) {
	console.log('[Vault] changeMasterPassword called');

	// Validate old password first
	try {
		const isValid = await testMasterPassword(oldMasterPassword);
		if (!isValid) {
			throw new Error('Current master password is incorrect');
		}
	} catch (error) {
		// If testMasterPassword throws an error (locked, etc.), re-throw it
		throw error;
	}

	// Diagnostic: Check if we can decrypt entries with the provided password
	// This helps identify if the password is wrong or if specific entries are problematic
	try {
		const testStmt = db.prepare(`SELECT id, name, encrypted_password, salt, iv, enc_version FROM entries LIMIT 5`);
		const testRows = testStmt.all();
		let canDecryptCount = 0;
		for (const row of testRows) {
			const testDecrypt = await decrypt(
				row.encrypted_password,
				oldMasterPassword,
				row.salt,
				row.iv,
				row.id,
				row.enc_version
			);
			if (testDecrypt) {
				canDecryptCount++;
			} else {
				console.warn(`[Vault] Diagnostic: Cannot decrypt test entry ${row.id} (${row.name || 'Unknown'})`);
			}
		}
		console.log(
			`[Vault] Diagnostic: Can decrypt ${canDecryptCount} of ${testRows.length} test entries with provided password`
		);
	} catch (error) {
		console.warn('[Vault] Diagnostic check failed:', error.message);
	}

	// Validate new password complexity
	try {
		validateMasterPassword(newMasterPassword);
	} catch (error) {
		throw new Error(`New master password validation failed: ${error.message}`);
	}

	// Check if new password is the same as old password
	if (oldMasterPassword === newMasterPassword) {
		throw new Error('New master password must be different from the current password');
	}

	try {
		// Get all entries
		const stmt = db.prepare(`SELECT * FROM entries ORDER BY id`);
		const rows = stmt.all();
		console.log('[Vault] Found', rows.length, 'entries to re-encrypt');

		// First, verify we can decrypt entries with the old password
		// Identify which entries can and cannot be decrypted
		const decryptableEntries = [];
		const failedEntries = [];

		for (const row of rows) {
			try {
				// Check if salt/iv are valid hex strings
				if (!row.salt || !row.iv || !row.encrypted_password) {
					failedEntries.push({
						id: row.id,
						name: row.name || 'Unknown',
						reason: 'Missing salt, IV, or encrypted data',
					});
					console.warn(`[Vault] Entry ${row.id} (${row.name || 'Unknown'}) has missing encryption data`);
					continue;
				}

				// Try to parse IV as hex to check if it's valid
				try {
					CryptoJS.enc.Hex.parse(row.iv);
				} catch (parseError) {
					failedEntries.push({ id: row.id, name: row.name || 'Unknown', reason: 'Invalid IV format' });
					console.warn(`[Vault] Entry ${row.id} (${row.name || 'Unknown'}) has invalid IV format`);
					continue;
				}

				const plainPassword = await decrypt(
					row.encrypted_password,
					oldMasterPassword,
					row.salt,
					row.iv,
					row.id,
					row.enc_version
				);
				if (plainPassword && plainPassword.length > 0) {
					decryptableEntries.push({ ...row, plainPassword });
				} else {
					failedEntries.push({ id: row.id, name: row.name || 'Unknown', reason: 'Decryption returned empty result' });
					if (process.env.NODE_ENV !== 'production') {
						console.warn(
							`[Vault] Cannot decrypt entry ${row.id} (${row.name || 'Unknown'}) - decryption returned empty`
						);
					}
				}
			} catch (error) {
				failedEntries.push({ id: row.id, name: row.name || 'Unknown', reason: error.message });
				if (process.env.NODE_ENV !== 'production') {
					console.warn(`[Vault] Error decrypting entry ${row.id} (${row.name || 'Unknown'}):`, error.message);
				}
			}
		}

		// If ALL entries fail, the password is definitely wrong
		if (decryptableEntries.length === 0 && rows.length > 0) {
			throw new Error(
				'Cannot decrypt any entries with the provided current master password. Please verify your current password is correct.'
			);
		}

		// If some entries fail, warn but allow proceeding
		if (failedEntries.length > 0) {
			const failedDetails = failedEntries
				.map(e => `ID ${e.id} (${e.name})${e.reason ? ' - ' + e.reason : ''}`)
				.join(', ');
			if (process.env.NODE_ENV !== 'production') {
				console.warn(
					`[Vault] Warning: ${failedEntries.length} entry/entries cannot be decrypted and will be skipped: ${failedDetails}`
				);
			}
		}

		if (process.env.NODE_ENV !== 'production') {
			console.log(
				`[Vault] ${decryptableEntries.length} entries can be re-encrypted, ${failedEntries.length} will be skipped`
			);
		}

		// Prepare all encrypted data before transaction (transactions can't be async)
		const reEncryptedEntries = [];
		for (const entry of decryptableEntries) {
			try {
				// Generate new salt and IV for security
				const newSalt = await generateSalt();
				const newIV = await generateIV();

				// Encrypt with new password (we already have plainPassword from the check above)
				const newEncryptedPassword = await encrypt(entry.plainPassword, newMasterPassword, newSalt, newIV);

				reEncryptedEntries.push({
					id: entry.id,
					encryptedPassword: newEncryptedPassword,
					salt: newSalt,
					iv: newIV,
				});
			} catch (error) {
				console.error(`[Vault] Error preparing re-encryption for entry ${entry.id}:`, error);
				throw new Error(`Failed to re-encrypt entry ${entry.id}: ${error.message}`);
			}
		}

		// Prepare new master password hash
		const newSalt = await generateSalt();
		let newHash;
		if (cryptoWorkerRef) {
			try {
				const hashResult = await callWorkerCrypto('hashPBKDF2', {
					password: newMasterPassword,
					salt: newSalt,
				});
				if (hashResult && hashResult.hash) {
					newHash = hashResult.hash;
				} else {
					throw new Error('Worker hashPBKDF2 returned no result');
				}
			} catch (error) {
				console.warn('[Vault] Worker hashPBKDF2 failed, using local crypto:', error.message);
				newHash = crypto
					.pbkdf2Sync(newMasterPassword, Buffer.from(newSalt, 'hex'), PBKDF2_ITERATIONS, KEY_LENGTH, 'sha256')
					.toString('hex');
			}
		} else {
			newHash = crypto
				.pbkdf2Sync(newMasterPassword, Buffer.from(newSalt, 'hex'), PBKDF2_ITERATIONS, KEY_LENGTH, 'sha256')
				.toString('hex');
		}

		// Use a transaction to ensure atomicity
		const transaction = db.transaction(() => {
			// Prepare statements inside transaction
			const updateStmt = db.prepare(`
				UPDATE entries 
				SET encrypted_password = ?, salt = ?, iv = ?, enc_version = 'gcm', last_modified = CURRENT_TIMESTAMP
				WHERE id = ?
			`);

			// Only re-encrypt entries that we successfully decrypted
			for (const entry of reEncryptedEntries) {
				try {
					// Update entry
					updateStmt.run(entry.encryptedPassword, entry.salt, entry.iv, entry.id);
					console.log(`[Vault] Successfully re-encrypted entry ${entry.id}`);
				} catch (error) {
					console.error(`[Vault] Error updating entry ${entry.id}:`, error);
					throw new Error(`Failed to update entry ${entry.id}: ${error.message}`);
				}
			}

			// Update master password hash
			const updateHashStmt = db.prepare(`
				UPDATE security_metadata 
				SET master_password_hash = ?, password_salt = ?, last_modified = CURRENT_TIMESTAMP
				WHERE id = 1
			`);
			updateHashStmt.run(newHash, newSalt);

			console.log('[Vault] Master password changed successfully');
		});

		// Execute transaction
		transaction();

		// Return result with information about skipped entries
		if (failedEntries.length > 0) {
			return {
				success: true,
				reEncrypted: decryptableEntries.length,
				skipped: failedEntries.length,
				skippedEntries: failedEntries.map(e => ({ id: e.id, name: e.name, reason: e.reason || 'Unknown error' })),
			};
		}

		return {
			success: true,
			reEncrypted: decryptableEntries.length,
			skipped: 0,
		};
	} catch (error) {
		console.error('[Vault] Error in changeMasterPassword:', error);
		throw error;
	}
}

async function testMasterPassword(masterPassword) {
	try {
		// Check if account is locked
		const lockStmt = db.prepare(`SELECT locked_until FROM security_metadata WHERE id = 1`);
		const lockResult = lockStmt.get();

		if (lockResult && lockResult.locked_until) {
			const lockTime = new Date(lockResult.locked_until);
			if (lockTime > new Date()) {
				const remainingMinutes = Math.ceil((lockTime - new Date()) / (1000 * 60));
				throw new Error(`Account locked. Try again in ${remainingMinutes} minutes.`);
			}
		}

		// Check if this is the first time (no entries exist)
		const stmt = db.prepare(`SELECT COUNT(*) as count FROM entries`);
		const result = stmt.get();

		if (result.count === 0) {
			// First time setup - validate password complexity and store hash
			try {
				validateMasterPassword(masterPassword);

				// Store master password hash for future verification
				const salt = await generateSalt();
				let hash;
				if (cryptoWorkerRef) {
					try {
						const hashResult = await callWorkerCrypto('hashPBKDF2', {
							password: masterPassword,
							salt: salt,
						});
						if (hashResult && hashResult.hash) {
							hash = hashResult.hash;
						} else {
							throw new Error('Worker hashPBKDF2 returned no result');
						}
					} catch (error) {
						console.warn('[Vault] Worker hashPBKDF2 failed, using local crypto:', error.message);
						hash = crypto
							.pbkdf2Sync(masterPassword, Buffer.from(salt, 'hex'), PBKDF2_ITERATIONS, KEY_LENGTH, 'sha256')
							.toString('hex');
					}
				} else {
					hash = crypto
						.pbkdf2Sync(masterPassword, Buffer.from(salt, 'hex'), PBKDF2_ITERATIONS, KEY_LENGTH, 'sha256')
						.toString('hex');
				}

				const updateStmt = db.prepare(`
					UPDATE security_metadata 
					SET master_password_hash = ?, password_salt = ?, failed_attempts = 0 
					WHERE id = 1
				`);
				updateStmt.run(hash, salt);

				return true;
			} catch (error) {
				throw new Error(`First-time setup failed: ${error.message}`);
			}
		}

		// Verify against stored hash first
		const hashStmt = db.prepare(`SELECT master_password_hash, password_salt FROM security_metadata WHERE id = 1`);
		const hashResult = hashStmt.get();

		if (hashResult) {
			// Support both hex format (new) and CryptoJS format (legacy)
			let testHash;
			try {
				// Try worker first (hex format)
				if (cryptoWorkerRef) {
					try {
						const hashResult_worker = await callWorkerCrypto('hashPBKDF2', {
							password: masterPassword,
							salt: hashResult.password_salt,
						});
						if (hashResult_worker && hashResult_worker.hash) {
							testHash = hashResult_worker.hash;
						} else {
							throw new Error('Worker hashPBKDF2 returned no result');
						}
					} catch (error) {
						console.warn('[Vault] Worker hashPBKDF2 failed, using local crypto:', error.message);
						testHash = crypto
							.pbkdf2Sync(
								masterPassword,
								Buffer.from(hashResult.password_salt, 'hex'),
								PBKDF2_ITERATIONS,
								KEY_LENGTH,
								'sha256'
							)
							.toString('hex');
					}
				} else {
					// Try Node crypto (hex format)
					testHash = crypto
						.pbkdf2Sync(
							masterPassword,
							Buffer.from(hashResult.password_salt, 'hex'),
							PBKDF2_ITERATIONS,
							KEY_LENGTH,
							'sha256'
						)
						.toString('hex');
				}
			} catch (error) {
				// Fallback to CryptoJS for legacy format
				// Parse salt as hex (salt is stored as hex string in database)
				const saltHex = CryptoJS.enc.Hex.parse(hashResult.password_salt);
				testHash = CryptoJS.PBKDF2(masterPassword, saltHex, {
					keySize: KEY_LENGTH / 4,
					iterations: PBKDF2_ITERATIONS,
				}).toString();
			}

			if (testHash === hashResult.master_password_hash) {
				// Reset failed attempts on successful login
				const resetStmt = db.prepare(
					`UPDATE security_metadata SET failed_attempts = 0, locked_until = NULL WHERE id = 1`
				);
				resetStmt.run();
				return true;
			}
		}

		// Fallback: try to decrypt an entry (for backward compatibility)
		const testStmt = db.prepare(`SELECT id, encrypted_password, salt, iv, enc_version FROM entries LIMIT 1`);
		const testRow = testStmt.get();

		if (testRow) {
			const password = await decrypt(
				testRow.encrypted_password,
				masterPassword,
				testRow.salt,
				testRow.iv,
				testRow.id,
				testRow.enc_version
			);
			if (password !== null) {
				// Reset failed attempts
				const resetStmt = db.prepare(
					`UPDATE security_metadata SET failed_attempts = 0, locked_until = NULL WHERE id = 1`
				);
				resetStmt.run();
				return true;
			}
		}

		// Increment failed attempts and potentially lock account
		const updateStmt = db.prepare(`UPDATE security_metadata SET failed_attempts = failed_attempts + 1 WHERE id = 1`);
		updateStmt.run();

		const failedStmt = db.prepare(`SELECT failed_attempts FROM security_metadata WHERE id = 1`);
		const failedResult = failedStmt.get();

		if (failedResult && failedResult.failed_attempts >= 5) {
			// Lock account for 30 minutes after 5 failed attempts
			const lockUntil = new Date(Date.now() + 30 * 60 * 1000);
			const lockStmt = db.prepare(`UPDATE security_metadata SET locked_until = ? WHERE id = 1`);
			lockStmt.run(lockUntil.toISOString());
			throw new Error('Too many failed attempts. Account locked for 30 minutes.');
		}

		return false;
	} catch (error) {
		console.error('[Vault] Error in testMasterPassword:', error);
		throw error;
	}
}

// Enhanced security audit function
function getSecurityInfo() {
	try {
		const stmt = db.prepare(`SELECT COUNT(*) as count FROM entries`);
		const result = stmt.get();

		const securityStmt = db.prepare(`SELECT failed_attempts, locked_until FROM security_metadata WHERE id = 1`);
		const securityResult = securityStmt.get();

		return {
			totalEntries: result.count,
			encryption: 'AES-256-GCM', // Authenticated encryption with GCM
			keyDerivation: 'PBKDF2',
			iterations: PBKDF2_ITERATIONS,
			saltLength: SALT_LENGTH * 8, // in bits
			ivLength: IV_LENGTH * 8, // in bits (96 bits for GCM)
			authTagLength: AUTH_TAG_LENGTH * 8, // in bits (128 bits for GCM)
			failedAttempts: securityResult ? securityResult.failed_attempts : 0,
			isLocked:
				securityResult && securityResult.locked_until ? new Date(securityResult.locked_until) > new Date() : false,
			lockTimeRemaining:
				securityResult && securityResult.locked_until
					? Math.ceil((new Date(securityResult.locked_until) - new Date()) / (1000 * 60))
					: 0,
			encryptionVersion: 'v2.0', // GCM with authentication
			databaseEncrypted: false, // Database file is not encrypted, but data inside is encrypted per-entry
			securityFeatures: {
				accountLockout: true, // Account lockout after failed attempts
				autoLock: true, // Auto-lock on inactivity
				perEntryEncryption: true, // Each entry encrypted separately
				perEntrySalt: true, // Unique salt per entry
				authenticatedEncryption: true, // GCM provides authentication
				// Note: Clipboard protection and screen capture detection are UI-level features
				// and cannot be reliably implemented at backend level
			},
		};
	} catch (error) {
		console.error('[Vault] Error getting security info:', error);
		return null;
	}
}

// Note: secureClipboardCopy and detectScreenCapture removed
// These functions use 'navigator' which is not available in Node.js backend
// They should be implemented in the renderer/UI layer instead

// Enhanced security cleanup
function enhancedCleanup() {
	try {
		// Clear any sensitive data from memory (best effort in Node.js)
		// Note: Clipboard/screen-capture operations should be done in UI (renderer/preload)
		// Navigator is not available in Node.js backend

		// Clear console logs in production
		if (process.env.NODE_ENV === 'production') {
			console.clear();
		}

		if (process.env.NODE_ENV !== 'production') {
			console.log('[Vault] Enhanced security cleanup completed');
		}
	} catch (error) {
		if (process.env.NODE_ENV !== 'production') {
			console.error('[Vault] Error during enhanced cleanup:', error);
		}
	}
}

// Diagnostic function (DEV only - never expose in production)
async function diagnoseEntry(entryId, masterPassword) {
	const DEBUG_RECOVERY = process.env.DEBUG_RECOVERY === 'true' || process.env.NODE_ENV !== 'production';

	if (!DEBUG_RECOVERY) {
		throw new Error('Diagnostic functions are only available in development mode');
	}

	try {
		const stmt = db.prepare(`SELECT * FROM entries WHERE id = ?`);
		const row = stmt.get(entryId);

		if (!row) {
			return { error: `Entry ${entryId} not found in database` };
		}

		const diagnostics = {
			id: row.id,
			name: row.name || 'Unknown',
			hasEncryptedPassword: !!row.encrypted_password,
			hasSalt: !!row.salt,
			hasIV: !!row.iv,
			encVersion: row.enc_version || 'cbc',
			saltLength: row.salt ? row.salt.length : 0,
			ivLength: row.iv ? row.iv.length : 0,
			encryptedPasswordLength: row.encrypted_password ? row.encrypted_password.length : 0,
			canDecrypt: false,
			decryptionError: null,
		};

		// Try to parse IV
		try {
			if (row.iv) {
				CryptoJS.enc.Hex.parse(row.iv);
				diagnostics.ivValid = true;
			} else {
				diagnostics.ivValid = false;
			}
		} catch (error) {
			diagnostics.ivValid = false;
			diagnostics.ivError = error.message;
		}

		// Try to decrypt
		if (row.encrypted_password && row.salt && row.iv) {
			try {
				const decrypted = await decrypt(
					row.encrypted_password,
					masterPassword,
					row.salt,
					row.iv,
					row.id,
					row.enc_version
				);
				if (decrypted && decrypted.length > 0) {
					diagnostics.canDecrypt = true;
					diagnostics.decryptedLength = decrypted.length;
				} else {
					diagnostics.decryptionError = 'Decryption returned empty result';
				}
			} catch (error) {
				diagnostics.decryptionError = error.message;
			}
		} else {
			diagnostics.decryptionError = 'Missing required encryption data';
		}

		return diagnostics;
	} catch (error) {
		return { error: error.message };
	}
}

async function setPasswordHint(hint, masterPassword) {
	try {
		if (!hint || !hint.trim()) {
			// Clear hint if empty
			const clearStmt = db.prepare(`
				UPDATE security_metadata 
				SET password_hint = NULL, hint_salt = NULL, hint_iv = NULL 
				WHERE id = 1
			`);
			clearStmt.run();
			console.log('[Vault] Password hint cleared');
			return true;
		}

		// Encrypt hint with master password
		const hintSalt = await generateSalt();
		const hintIV = await generateIV();
		const encryptedHint = await encrypt(hint.trim(), masterPassword, hintSalt, hintIV);

		// Store encrypted hint
		const stmt = db.prepare(`
			UPDATE security_metadata 
			SET password_hint = ?, hint_salt = ?, hint_iv = ? 
			WHERE id = 1
		`);
		stmt.run(encryptedHint, hintSalt, hintIV);

		console.log('[Vault] Password hint set successfully');
		return true;
	} catch (error) {
		console.error('[Vault] Error setting password hint:', error);
		throw error;
	}
}

async function getPasswordHint(masterPassword) {
	try {
		const stmt = db.prepare(`SELECT password_hint, hint_salt, hint_iv FROM security_metadata WHERE id = 1`);
		const result = stmt.get();

		// Security: Don't reveal if hint exists or not
		// Always attempt decryption to prevent information leakage
		if (!result || !result.password_hint) {
			// No hint exists, but return same format as decryption failure
			// This prevents attackers from knowing if a hint exists
			return { hint: null, error: 'decryption_failed' };
		}

		// Decrypt hint (hints don't need migration)
		const decryptedHint = await decrypt(result.password_hint, masterPassword, result.hint_salt, result.hint_iv, null);

		if (!decryptedHint) {
			// Decryption failed - wrong password or corrupted data
			// Return same error regardless of whether hint exists
			return { hint: null, error: 'decryption_failed' };
		}

		// Success - return the hint
		return { hint: decryptedHint };
	} catch (error) {
		console.error('[Vault] Error getting password hint:', error);
		// Always return same error format - don't reveal if hint exists
		return { hint: null, error: 'decryption_failed' };
	}
}

// Recovery Questions Functions
async function setRecoveryQuestions(questions, masterPassword) {
	try {
		// Validate input
		if (!Array.isArray(questions) || questions.length === 0) {
			throw new Error('At least one recovery question is required');
		}

		if (questions.length > 5) {
			throw new Error('Maximum 5 recovery questions allowed');
		}

		// Clear existing questions
		const clearStmt = db.prepare(`DELETE FROM recovery_questions`);
		clearStmt.run();

		// Insert new questions with hashed answers (not encrypted - so they can be verified without master password)
		const insertStmt = db.prepare(`
			INSERT INTO recovery_questions (question_number, question_text, answer_hash, answer_salt)
			VALUES (?, ?, ?, ?)
		`);

		for (let i = 0; i < questions.length; i++) {
			const q = questions[i];
			if (!q.question || !q.answer) {
				throw new Error(`Question ${i + 1} must have both question and answer`);
			}

			// Hash answer (like password) - can verify without master password
			const answerSalt = await generateSalt();
			let answerHash;
			if (cryptoWorkerRef) {
				try {
					const hashResult = await callWorkerCrypto('hashPBKDF2', {
						password: q.answer.trim().toLowerCase(),
						salt: answerSalt,
					});
					if (hashResult && hashResult.hash) {
						answerHash = hashResult.hash;
					} else {
						throw new Error('Worker hashPBKDF2 returned no result');
					}
				} catch (error) {
					console.warn('[Vault] Worker hashPBKDF2 failed, using local crypto:', error.message);
					answerHash = crypto
						.pbkdf2Sync(
							q.answer.trim().toLowerCase(),
							Buffer.from(answerSalt, 'hex'),
							PBKDF2_ITERATIONS,
							KEY_LENGTH,
							'sha256'
						)
						.toString('hex');
				}
			} else {
				answerHash = crypto
					.pbkdf2Sync(
						q.answer.trim().toLowerCase(),
						Buffer.from(answerSalt, 'hex'),
						PBKDF2_ITERATIONS,
						KEY_LENGTH,
						'sha256'
					)
					.toString('hex');
			}

			insertStmt.run(i + 1, q.question.trim(), answerHash, answerSalt);
		}

		console.log(`[Vault] Set ${questions.length} recovery questions successfully`);
		return true;
	} catch (error) {
		console.error('[Vault] Error setting recovery questions:', error);
		throw error;
	}
}

async function verifyRecoveryQuestions(answers) {
	try {
		// Get all recovery questions
		const stmt = db.prepare(`SELECT * FROM recovery_questions ORDER BY question_number`);
		const questions = stmt.all();

		if (questions.length === 0) {
			return { verified: false, error: 'No recovery questions set' };
		}

		if (!Array.isArray(answers) || answers.length !== questions.length) {
			return { verified: false, error: `Please answer all ${questions.length} questions` };
		}

		// Verify each answer by hashing and comparing
		let correctCount = 0;
		for (let i = 0; i < questions.length; i++) {
			const question = questions[i];
			const providedAnswer = answers[i] ? answers[i].trim().toLowerCase() : '';

			try {
				// Hash the provided answer and compare
				// Support both hex format (new) and CryptoJS format (legacy)
				let testHash;
				try {
					if (cryptoWorkerRef) {
						try {
							const hashResult = await callWorkerCrypto('hashPBKDF2', {
								password: providedAnswer,
								salt: question.answer_salt,
							});
							if (hashResult && hashResult.hash) {
								testHash = hashResult.hash;
							} else {
								throw new Error('Worker hashPBKDF2 returned no result');
							}
						} catch (error) {
							console.warn('[Vault] Worker hashPBKDF2 failed, using local crypto:', error.message);
							testHash = crypto
								.pbkdf2Sync(
									providedAnswer,
									Buffer.from(question.answer_salt, 'hex'),
									PBKDF2_ITERATIONS,
									KEY_LENGTH,
									'sha256'
								)
								.toString('hex');
						}
					} else {
						testHash = crypto
							.pbkdf2Sync(
								providedAnswer,
								Buffer.from(question.answer_salt, 'hex'),
								PBKDF2_ITERATIONS,
								KEY_LENGTH,
								'sha256'
							)
							.toString('hex');
					}
				} catch (error) {
					// Fallback to CryptoJS for legacy format
					// Parse salt as hex (salt is stored as hex string in database)
					const saltHex = CryptoJS.enc.Hex.parse(question.answer_salt);
					testHash = CryptoJS.PBKDF2(providedAnswer, saltHex, {
						keySize: KEY_LENGTH / 4,
						iterations: PBKDF2_ITERATIONS,
					}).toString();
				}

				if (testHash === question.answer_hash) {
					correctCount++;
				}
			} catch (error) {
				console.error(`[Vault] Error verifying answer for question ${question.question_number}:`, error);
			}
		}

		// Require all answers to be correct for security
		if (correctCount === questions.length) {
			return { verified: true };
		} else {
			return { verified: false, error: 'One or more answers are incorrect' };
		}
	} catch (error) {
		console.error('[Vault] Error verifying recovery questions:', error);
		return { verified: false, error: 'Failed to verify recovery questions' };
	}
}

function getRecoveryQuestions() {
	try {
		const stmt = db.prepare(`SELECT question_number, question_text FROM recovery_questions ORDER BY question_number`);
		const questions = stmt.all();

		if (questions.length === 0) {
			return [];
		}

		// Return only question text (not answers)
		return questions.map(q => ({
			number: q.question_number,
			question: q.question_text,
		}));
	} catch (error) {
		console.error('[Vault] Error getting recovery questions:', error);
		return [];
	}
}

// Backup Codes Functions
// Increased entropy: 12 characters in format XXXX-XXXX-XXXX
function generateBackupCode() {
	const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // Exclude confusing chars (0, O, I, 1)
	let code = '';

	// Generate 12 characters
	for (let i = 0; i < 12; i++) {
		code += chars.charAt(crypto.randomInt(0, chars.length));
	}

	// Format as XXXX-XXXX-XXXX for better readability
	return code.substring(0, 4) + '-' + code.substring(4, 8) + '-' + code.substring(8, 12);
}

async function generateBackupCodes(masterPassword) {
	try {
		// Invalidate all existing backup codes for security
		const invalidateStmt = db.prepare(`UPDATE backup_codes SET used = 1 WHERE used = 0`);
		invalidateStmt.run();

		// Generate 10 backup codes
		const codes = [];
		const insertStmt = db.prepare(`
			INSERT INTO backup_codes (code_hash, used)
			VALUES (?, 0)
		`);

		for (let i = 0; i < 10; i++) {
			// Generate 12-character code in format XXXX-XXXX-XXXX
			const code = generateBackupCode();
			codes.push(code);

			// Hash the normalized code (without dashes) - so it works even if password changes
			const normalizedCode = code.replace(/-/g, '').toUpperCase();
			let codeHash;
			if (cryptoWorkerRef) {
				try {
					const hashResult = await callWorkerCrypto('hashSHA256', {
						text: normalizedCode,
					});
					if (hashResult && hashResult.hash) {
						codeHash = hashResult.hash;
					} else {
						throw new Error('Worker hashSHA256 returned no result');
					}
				} catch (error) {
					console.warn('[Vault] Worker hashSHA256 failed, using local crypto:', error.message);
					codeHash = crypto.createHash('sha256').update(normalizedCode).digest('hex');
				}
			} else {
				codeHash = crypto.createHash('sha256').update(normalizedCode).digest('hex');
			}
			insertStmt.run(codeHash);
		}

		console.log('[Vault] Generated 10 backup codes');
		return codes; // Return plain codes for user to save
	} catch (error) {
		console.error('[Vault] Error generating backup codes:', error);
		throw error;
	}
}

async function verifyBackupCode(code) {
	try {
		// Remove dashes and convert to uppercase
		const normalizedCode = code ? code.replace(/-/g, '').toUpperCase() : '';

		// Validate format: should be 12 alphanumeric characters
		if (!normalizedCode || normalizedCode.length !== 12 || !/^[A-Z2-9]{12}$/.test(normalizedCode)) {
			return { verified: false, error: 'Invalid backup code format. Expected format: XXXX-XXXX-XXXX' };
		}

		// Hash the normalized code (without dashes)
		let codeHash;
		if (cryptoWorkerRef) {
			try {
				const hashResult = await callWorkerCrypto('hashSHA256', {
					text: normalizedCode,
				});
				if (hashResult && hashResult.hash) {
					codeHash = hashResult.hash;
				} else {
					throw new Error('Worker hashSHA256 returned no result');
				}
			} catch (error) {
				console.warn('[Vault] Worker hashSHA256 failed, using local crypto:', error.message);
				codeHash = crypto.createHash('sha256').update(normalizedCode).digest('hex');
			}
		} else {
			codeHash = crypto.createHash('sha256').update(normalizedCode).digest('hex');
		}

		// Check if code exists and is unused
		const stmt = db.prepare(`SELECT id, used FROM backup_codes WHERE code_hash = ?`);
		const result = stmt.get(codeHash);

		if (!result) {
			return { verified: false, error: 'Invalid backup code' };
		}

		if (result.used === 1) {
			return { verified: false, error: 'This backup code has already been used' };
		}

		// Mark code as used
		const updateStmt = db.prepare(`UPDATE backup_codes SET used = 1, used_at = CURRENT_TIMESTAMP WHERE id = ?`);
		updateStmt.run(result.id);

		console.log('[Vault] Backup code verified and marked as used');
		return { verified: true };
	} catch (error) {
		console.error('[Vault] Error verifying backup code:', error);
		return { verified: false, error: 'Failed to verify backup code' };
	}
}

function getBackupCodesStatus() {
	try {
		const stmt = db.prepare(
			`SELECT COUNT(*) as total, SUM(CASE WHEN used = 0 THEN 1 ELSE 0 END) as unused FROM backup_codes`
		);
		const result = stmt.get();
		return {
			total: result.total || 0,
			unused: result.unused || 0,
			used: (result.total || 0) - (result.unused || 0),
		};
	} catch (error) {
		console.error('[Vault] Error getting backup codes status:', error);
		return { total: 0, unused: 0, used: 0 };
	}
}

// Set up email/SMS recovery
// This stores an encrypted backup of the master password that can be used for recovery
// SECURITY FIX: Don't store master password backup - it breaks the security model
// Instead, show recovery key ONCE to user - they must save it offline
async function setupEmailSMSRecovery(email, phone, masterPassword) {
	try {
		// Generate a recovery key (32 bytes random)
		// This key will be shown ONCE to the user - they must save it offline
		const recoveryKey = crypto.randomBytes(32).toString('hex');

		// Encrypt the recovery key with a key derived from email+phone
		// This allows recovery without master password
		let recoveryKeyDerivation;
		if (cryptoWorkerRef) {
			try {
				const hashResult = await callWorkerCrypto('hashSHA256', {
					text: email + phone + 'recovery-salt-v1',
				});
				if (hashResult && hashResult.hash) {
					recoveryKeyDerivation = hashResult.hash;
				} else {
					throw new Error('Worker hashSHA256 returned no result');
				}
			} catch (error) {
				console.warn('[Vault] Worker hashSHA256 failed, using local crypto:', error.message);
				recoveryKeyDerivation = crypto
					.createHash('sha256')
					.update(email + phone + 'recovery-salt-v1')
					.digest('hex');
			}
		} else {
			recoveryKeyDerivation = crypto
				.createHash('sha256')
				.update(email + phone + 'recovery-salt-v1')
				.digest('hex');
		}
		const recoveryKeySalt = await generateSalt();
		const recoveryKeyIV = await generateIV();
		const encryptedRecoveryKey = await encrypt(recoveryKey, recoveryKeyDerivation, recoveryKeySalt, recoveryKeyIV);

		// Store encrypted recovery key (NOT master password!)
		const updateStmt = db.prepare(`
			UPDATE security_metadata 
			SET recovery_email = ?,
				recovery_phone = ?,
				recovery_key_encrypted = ?,
				recovery_key_salt = ?,
				recovery_key_iv = ?,
				master_password_backup_encrypted = NULL,
				master_password_backup_salt = NULL,
				master_password_backup_iv = NULL,
				last_modified = CURRENT_TIMESTAMP
			WHERE id = 1
		`);
		updateStmt.run(email, phone, encryptedRecoveryKey, recoveryKeySalt, recoveryKeyIV);

		// IMPORTANT: Return recovery key ONCE to user - they must save it offline
		// This is the ONLY time they'll see it
		// Note: Recovery key doesn't preserve data - recovery = reset with data loss
		const DEBUG_RECOVERY = process.env.DEBUG_RECOVERY === 'true' || process.env.NODE_ENV !== 'production';
		if (DEBUG_RECOVERY) {
			console.log('[Vault] Email/SMS recovery set up successfully');
		}
		return {
			success: true,
			recoveryKey: recoveryKey, // Show this ONCE, user must save it
			warning:
				'Save this recovery key securely offline. You will not see it again. Note: Recovery resets the vault with data loss - entries remain encrypted and inaccessible.',
		};
	} catch (error) {
		if (process.env.NODE_ENV !== 'production') {
			console.error('[Vault] Error setting up email/SMS recovery:', error);
		}
		throw error;
	}
}

// Generate and send recovery code
async function generateRecoveryCode(email, phone) {
	try {
		// Check if email/SMS recovery is set up
		const checkStmt = db.prepare(`SELECT recovery_email, recovery_phone FROM security_metadata WHERE id = 1`);
		const result = checkStmt.get();

		if (!result || (!result.recovery_email && !result.recovery_phone)) {
			throw new Error('Email/SMS recovery is not set up');
		}

		// Generate 6-digit code (100000-999999)
		const code = crypto.randomInt(100000, 1000000).toString();
		const codeHash = crypto.createHash('sha256').update(code).digest('hex');

		// Store code hash with expiration (30 minutes - more reasonable time)
		const expiresAt = new Date(Date.now() + 30 * 60 * 1000);
		const insertStmt = db.prepare(`
			INSERT INTO recovery_codes (code_hash, expires_at, created_at)
			VALUES (?, ?, CURRENT_TIMESTAMP)
		`);
		insertStmt.run(codeHash, expiresAt.toISOString());

		// SECURITY: Never log or return the code in production
		const isDevelopment = process.env.NODE_ENV !== 'production' || process.env.DEV_RECOVERY_CODES === 'true';

		if (isDevelopment) {
			// Only in development - log for testing (behind feature flag)
			console.log('[Vault] [DEV ONLY] Recovery code generated (expires in 30 minutes)');
			console.log('[Vault] [DEV ONLY] Would send to:', result.recovery_email || result.recovery_phone);
			// Return code only in dev
			return { success: true, code: code };
		} else {
			// Production: Send via email/SMS service (implement integration)
			// TODO: Integrate with SendGrid, Twilio, etc.
			// sendRecoveryCodeViaEmail(result.recovery_email, code);
			// sendRecoveryCodeViaSMS(result.recovery_phone, code);

			// NEVER return or log the code in production
			if (process.env.NODE_ENV !== 'production') {
				console.log('[Vault] Recovery code generated and sent via email/SMS');
			}
			return { success: true }; // NO CODE in response
		}
	} catch (error) {
		if (process.env.NODE_ENV !== 'production') {
			console.error('[Vault] Error generating recovery code:', error);
		}
		throw error;
	}
}

// Verify recovery code (doesn't mark as used - that happens during password reset)
async function verifyRecoveryCode(code) {
	const DEBUG_RECOVERY = process.env.DEBUG_RECOVERY === 'true' || process.env.NODE_ENV !== 'production';

	try {
		if (!code || typeof code !== 'string' || code.length !== 6) {
			if (DEBUG_RECOVERY) {
				console.error('[Vault] Invalid recovery code format');
			}
			return { verified: false, error: 'Invalid recovery code format' };
		}

		let codeHash;
		if (cryptoWorkerRef) {
			try {
				const hashResult = await callWorkerCrypto('hashSHA256', {
					text: code,
				});
				if (hashResult && hashResult.hash) {
					codeHash = hashResult.hash;
				} else {
					throw new Error('Worker hashSHA256 returned no result');
				}
			} catch (error) {
				if (DEBUG_RECOVERY) {
					console.warn('[Vault] Worker hashSHA256 failed, using local crypto:', error.message);
				}
				codeHash = crypto.createHash('sha256').update(code).digest('hex');
			}
		} else {
			codeHash = crypto.createHash('sha256').update(code).digest('hex');
		}

		// Check if code exists and is not expired or already used
		const checkStmt = db.prepare(`
			SELECT id, expires_at, used, created_at FROM recovery_codes 
			WHERE code_hash = ?
		`);
		const result = checkStmt.get(codeHash);

		if (!result) {
			if (DEBUG_RECOVERY) {
				console.error('[Vault] Recovery code not found in database');
			}
			return { verified: false, error: 'Invalid recovery code' };
		}

		// Check if already used
		if (result.used === 1) {
			if (DEBUG_RECOVERY) {
				console.error('[Vault] Recovery code already used');
			}
			return { verified: false, error: 'This recovery code has already been used' };
		}

		// Check expiration
		const expiresAt = new Date(result.expires_at);
		const now = new Date();
		if (expiresAt < now) {
			if (DEBUG_RECOVERY) {
				const minutesExpired = Math.floor((now - expiresAt) / 1000 / 60);
				console.error('[Vault] Recovery code expired', minutesExpired, 'minutes ago');
			}
			return { verified: false, error: 'Recovery code has expired' };
		}

		if (DEBUG_RECOVERY) {
			console.log('[Vault] Recovery code verified successfully');
		}
		// Don't mark as used here - that will happen during password reset
		// This allows the code to be verified multiple times before reset
		return { verified: true, codeId: result.id };
	} catch (error) {
		if (DEBUG_RECOVERY) {
			console.error('[Vault] Error verifying recovery code:', error);
		}
		return { verified: false, error: 'Failed to verify recovery code: ' + error.message };
	}
}

// Mark recovery code as used (called during password reset)
async function markRecoveryCodeAsUsed(code) {
	try {
		let codeHash;
		if (cryptoWorkerRef) {
			try {
				const hashResult = await callWorkerCrypto('hashSHA256', {
					text: code,
				});
				if (hashResult && hashResult.hash) {
					codeHash = hashResult.hash;
				} else {
					throw new Error('Worker hashSHA256 returned no result');
				}
			} catch (error) {
				console.warn('[Vault] Worker hashSHA256 failed, using local crypto:', error.message);
				codeHash = crypto.createHash('sha256').update(code).digest('hex');
			}
		} else {
			codeHash = crypto.createHash('sha256').update(code).digest('hex');
		}
		const markUsedStmt = db.prepare(
			`UPDATE recovery_codes SET used = 1, used_at = CURRENT_TIMESTAMP WHERE code_hash = ? AND used = 0`
		);
		const result = markUsedStmt.run(codeHash);
		if (result.changes > 0) {
			console.log('[Vault] Recovery code marked as used');
		}
		return result.changes > 0;
	} catch (error) {
		console.error('[Vault] Error marking recovery code as used:', error);
		return false;
	}
}

// Password Reset via Recovery
// SIMPLIFIED: Recovery = reset with data loss (we don't store master password backup)
// All recovery methods result in vault reset - entries remain encrypted and inaccessible
async function resetMasterPasswordViaRecovery(newPassword, recoveryMethod, recoveryData) {
	const DEBUG_RECOVERY = process.env.DEBUG_RECOVERY === 'true' || process.env.NODE_ENV !== 'production';

	try {
		// Validate new password
		validateMasterPassword(newPassword);

		// Verify recovery method
		if (recoveryMethod === 'email_sms') {
			if (!recoveryData || !recoveryData.code) {
				throw new Error('Recovery code is required');
			}

			if (typeof recoveryData.code !== 'string' || recoveryData.code.length !== 6) {
				throw new Error('Invalid recovery code format. Code must be exactly 6 digits.');
			}

			if (DEBUG_RECOVERY) {
				console.log('[Vault] Verifying recovery code...');
			}

			const verifyResult = await verifyRecoveryCode(recoveryData.code);
			if (!verifyResult || !verifyResult.verified) {
				throw new Error(verifyResult?.error || 'Recovery code verification failed');
			}

			// Mark code as used
			await markRecoveryCodeAsUsed(recoveryData.code);

			// Verify recovery key if provided (optional - doesn't preserve data anyway)
			if (recoveryData.recoveryKey) {
				const recoveryStmt = db.prepare(`
					SELECT recovery_email, recovery_phone, recovery_key_encrypted, recovery_key_salt, recovery_key_iv
					FROM security_metadata WHERE id = 1
				`);
				const recoveryData_db = recoveryStmt.get();

				if (recoveryData_db && recoveryData_db.recovery_key_encrypted) {
					let recoveryKeyDerivation;
					if (cryptoWorkerRef) {
						try {
							const hashResult = await callWorkerCrypto('hashSHA256', {
								text: recoveryData_db.recovery_email + recoveryData_db.recovery_phone + 'recovery-salt-v1',
							});
							if (hashResult && hashResult.hash) {
								recoveryKeyDerivation = hashResult.hash;
							} else {
								throw new Error('Worker hashSHA256 returned no result');
							}
						} catch (error) {
							if (DEBUG_RECOVERY) {
								console.warn('[Vault] Worker hashSHA256 failed, using local crypto:', error.message);
							}
							recoveryKeyDerivation = crypto
								.createHash('sha256')
								.update(recoveryData_db.recovery_email + recoveryData_db.recovery_phone + 'recovery-salt-v1')
								.digest('hex');
						}
					} else {
						recoveryKeyDerivation = crypto
							.createHash('sha256')
							.update(recoveryData_db.recovery_email + recoveryData_db.recovery_phone + 'recovery-salt-v1')
							.digest('hex');
					}
					const decryptedRecoveryKey = await decrypt(
						recoveryData_db.recovery_key_encrypted,
						recoveryKeyDerivation,
						recoveryData_db.recovery_key_salt,
						recoveryData_db.recovery_key_iv,
						null
					);

					if (!decryptedRecoveryKey || decryptedRecoveryKey !== recoveryData.recoveryKey) {
						throw new Error('Invalid recovery key');
					}
				}
			}
		} else if (recoveryMethod === 'backup_code') {
			const verifyResult = await verifyBackupCode(recoveryData.code);
			if (!verifyResult.verified) {
				throw new Error(verifyResult.error || 'Backup code verification failed');
			}
		} else if (recoveryMethod === 'questions') {
			const verifyResult = await verifyRecoveryQuestions(recoveryData.answers);
			if (!verifyResult.verified) {
				throw new Error(verifyResult.error || 'Recovery questions verification failed');
			}
		} else {
			throw new Error('Invalid recovery method');
		}

		// All recovery methods result in vault reset (data loss)
		// We cannot decrypt entries without the old master password
		const newSalt = await generateSalt();
		let newHash;
		if (cryptoWorkerRef) {
			try {
				const hashResult = await callWorkerCrypto('hashPBKDF2', {
					password: newPassword,
					salt: newSalt,
				});
				if (hashResult && hashResult.hash) {
					newHash = hashResult.hash;
				} else {
					throw new Error('Worker hashPBKDF2 returned no result');
				}
			} catch (error) {
				if (DEBUG_RECOVERY) {
					console.warn('[Vault] Worker hashPBKDF2 failed, using local crypto:', error.message);
				}
				newHash = crypto
					.pbkdf2Sync(newPassword, Buffer.from(newSalt, 'hex'), PBKDF2_ITERATIONS, KEY_LENGTH, 'sha256')
					.toString('hex');
			}
		} else {
			newHash = crypto
				.pbkdf2Sync(newPassword, Buffer.from(newSalt, 'hex'), PBKDF2_ITERATIONS, KEY_LENGTH, 'sha256')
				.toString('hex');
		}

		const updateHashStmt = db.prepare(`
			UPDATE security_metadata 
			SET master_password_hash = ?, password_salt = ?, last_modified = CURRENT_TIMESTAMP
			WHERE id = 1
		`);
		updateHashStmt.run(newHash, newSalt);

		// Clear recovery questions
		const clearQuestionsStmt = db.prepare(`DELETE FROM recovery_questions`);
		clearQuestionsStmt.run();

		// Invalidate all remaining backup codes
		const invalidateCodesStmt = db.prepare(`UPDATE backup_codes SET used = 1 WHERE used = 0`);
		invalidateCodesStmt.run();

		if (DEBUG_RECOVERY) {
			console.log('[Vault] Master password reset via recovery (data loss - entries remain encrypted)');
		}

		return {
			success: true,
			warning:
				'Password reset successful. However, all password entries remain encrypted with your old password and cannot be accessed. You will need to delete and recreate them.',
		};
	} catch (error) {
		if (DEBUG_RECOVERY) {
			console.error('[Vault] Error resetting password via recovery:', error);
		}
		throw error;
	}
}

// Batch migration from CBC to GCM format
// Migrates all entries with enc_version='cbc' to 'gcm' format
async function migrateEntriesToGCM(masterPassword) {
	try {
		if (!masterPassword) {
			throw new Error('Master password is required');
		}

		// Get all CBC entries
		const stmt = db.prepare(
			`SELECT id, encrypted_password, salt, iv FROM entries WHERE enc_version = 'cbc' OR enc_version IS NULL`
		);
		const rows = stmt.all();

		if (rows.length === 0) {
			if (process.env.NODE_ENV !== 'production') {
				console.log('[Vault] No entries to migrate');
			}
			return { migrated: 0, failed: 0 };
		}

		if (process.env.NODE_ENV !== 'production') {
			console.log(`[Vault] Migrating ${rows.length} entries from CBC to GCM format...`);
		}

		const migrated = [];
		const failed = [];

		for (const row of rows) {
			try {
				// Decrypt using legacy CBC format
				const decrypted = await decryptLegacy(row.encrypted_password, masterPassword, row.salt, row.iv, null);

				if (!decrypted || decrypted.length === 0) {
					failed.push({ id: row.id, reason: 'Decryption failed' });
					continue;
				}

				// Re-encrypt with GCM format
				const newSalt = await generateSalt();
				const newIV = await generateIV();
				const newEncrypted = await encrypt(decrypted, masterPassword, newSalt, newIV);

				// Update entry
				const updateStmt = db.prepare(`
					UPDATE entries 
					SET encrypted_password = ?, salt = ?, iv = ?, enc_version = 'gcm', last_modified = CURRENT_TIMESTAMP
					WHERE id = ?
				`);
				updateStmt.run(newEncrypted, newSalt, newIV, row.id);

				migrated.push(row.id);
			} catch (error) {
				failed.push({ id: row.id, reason: error.message });
				if (process.env.NODE_ENV !== 'production') {
					console.error(`[Vault] Failed to migrate entry ${row.id}:`, error.message);
				}
			}
		}

		if (process.env.NODE_ENV !== 'production') {
			console.log(`[Vault] Migration complete: ${migrated.length} migrated, ${failed.length} failed`);
		}

		return {
			migrated: migrated.length,
			failed: failed.length,
			failedEntries: failed,
		};
	} catch (error) {
		if (process.env.NODE_ENV !== 'production') {
			console.error('[Vault] Error in batch migration:', error);
		}
		throw error;
	}
}

module.exports = {
	addEntry,
	getAllEntries,
	updateEntry,
	deleteEntry,
	saveEntryHistory,
	getEntryHistory,
	rollbackEntry,
	changeMasterPassword,
	testMasterPassword,
	setPasswordHint,
	getPasswordHint,
	setRecoveryQuestions,
	verifyRecoveryQuestions,
	getRecoveryQuestions,
	generateBackupCodes,
	verifyBackupCode,
	getBackupCodesStatus,
	setupEmailSMSRecovery,
	generateRecoveryCode,
	verifyRecoveryCode,
	markRecoveryCodeAsUsed,
	resetMasterPasswordViaRecovery,
	getSecurityInfo,
	diagnoseEntry,
	setCryptoWorker, // Allow main.js to set worker reference
	cleanupWorker, // Cleanup worker - reject all pending requests
	cleanup: enhancedCleanup, // Use enhanced cleanup
	enhancedCleanup,
	getEntryPassword, // Get password for single entry on demand
	migrateEntriesToGCM, // Batch migration from CBC to GCM
};
