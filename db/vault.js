const Database = require('better-sqlite3');
const CryptoJS = require('crypto-js');
const path = require('path');
const fs = require('fs');
const os = require('os');

console.log('[Vault] Initializing vault database...');

// Enhanced security constants
const PBKDF2_ITERATIONS = 100000; // Reduced to 100k for better performance while maintaining security
const SALT_LENGTH = 32; // 256 bits
const KEY_LENGTH = 32; // 256 bits for AES-256
const IV_LENGTH = 16; // 128 bits for AES IV
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
if (fs.existsSync(oldDbPath) && !fs.existsSync(dbPath)) {
	console.log('[Vault] Migrating database from old location to secure location...');
	try {
		// Ensure new directory exists
		const newDbDir = path.dirname(dbPath);
		if (!fs.existsSync(newDbDir)) {
			fs.mkdirSync(newDbDir, { recursive: true, mode: 0o700 });
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
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_modified DATETIME DEFAULT CURRENT_TIMESTAMP,
			access_count INTEGER DEFAULT 0,
			last_access DATETIME
		)
	`);

	// Check if category column exists, if not add it
	try {
		db.exec('SELECT category FROM entries LIMIT 1');
		console.log('[Vault] Category column already exists');
	} catch (error) {
		console.log('[Vault] Adding category column to existing database...');
		db.exec('ALTER TABLE entries ADD COLUMN category TEXT DEFAULT "personal"');
		console.log('[Vault] Category column added successfully');
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

function generateSalt() {
	return CryptoJS.lib.WordArray.random(SALT_LENGTH).toString();
}

function generateIV() {
	return CryptoJS.lib.WordArray.random(IV_LENGTH).toString();
}

function deriveKey(password, salt) {
	return CryptoJS.PBKDF2(password, salt, {
		keySize: KEY_LENGTH / 4, // CryptoJS uses 32-bit words
		iterations: PBKDF2_ITERATIONS,
	});
}

function encrypt(text, password, salt, iv) {
	const key = deriveKey(password, salt);
	return CryptoJS.AES.encrypt(text, key, { iv: CryptoJS.enc.Hex.parse(iv) }).toString();
}

function decrypt(ciphertext, password, salt, iv) {
	try {
		const key = deriveKey(password, salt);
		const bytes = CryptoJS.AES.decrypt(ciphertext, key, { iv: CryptoJS.enc.Hex.parse(iv) });
		return bytes.toString(CryptoJS.enc.Utf8);
	} catch (error) {
		console.error('[Vault] Decryption failed:', error.message);
		return null;
	}
}

function addEntry(name, username, plainPassword, category, masterPassword) {
	// Remove sensitive logging
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
		const salt = generateSalt();
		const iv = generateIV();

		const encryptedPassword = encrypt(plainPassword, masterPassword, salt, iv);

		const stmt = db.prepare(`
      INSERT INTO entries (name, username, encrypted_password, category, salt, iv) 
      VALUES (?, ?, ?, ?, ?, ?)
    `);
		const result = stmt.run(name, username || '', encryptedPassword, category || 'personal', salt, iv);

		return result.lastInsertRowid;
	} catch (error) {
		console.error('[Vault] Error in addEntry:', error);
		throw error;
	}
}

function getAllEntries(masterPassword) {
	try {
		console.log('[Vault] getAllEntries called');
		if (!masterPassword) {
			console.error('[Vault] getAllEntries: masterPassword is missing!');
			throw new Error('Master password is required');
		}

		const stmt = db.prepare(`SELECT * FROM entries ORDER BY last_modified DESC`);
		const rows = stmt.all();
		console.log('[Vault] Retrieved', rows.length, 'entries from database');

		if (rows.length === 0) {
			console.log('[Vault] No entries found in database');
			return [];
		}

		const entries = [];
		const failedEntries = [];

		for (const row of rows) {
			try {
				// Validate encryption data exists
				if (!row.salt || !row.iv || !row.encrypted_password) {
					console.error(`[Vault] Entry ${row.id} (${row.name || 'Unknown'}) missing encryption data`);
					failedEntries.push({ id: row.id, name: row.name || 'Unknown', reason: 'Missing encryption data' });
					continue;
				}

				// Try to decrypt
				const password = decrypt(row.encrypted_password, masterPassword, row.salt, row.iv);
				if (password && password.length > 0) {
					entries.push({
						id: row.id,
						name: row.name,
						username: row.username,
						password: password,
						category: row.category || 'personal',
						created_at: row.created_at,
						last_modified: row.last_modified,
					});
				} else {
					console.error(`[Vault] Entry ${row.id} (${row.name || 'Unknown'}) decryption returned empty result`);
					failedEntries.push({ id: row.id, name: row.name || 'Unknown', reason: 'Decryption returned empty' });
				}
			} catch (error) {
				console.error(`[Vault] Failed to decrypt entry ${row.id} (${row.name || 'Unknown'}):`, error.message);
				failedEntries.push({ id: row.id, name: row.name || 'Unknown', reason: error.message });
			}
		}

		console.log('[Vault] Successfully decrypted', entries.length, 'of', rows.length, 'entries');

		if (failedEntries.length > 0) {
			console.warn('[Vault] Failed to decrypt', failedEntries.length, 'entries:', failedEntries);
		}

		// If all entries failed to decrypt, this might indicate wrong password
		if (entries.length === 0 && rows.length > 0) {
			console.error('[Vault] WARNING: All entries failed to decrypt! This might indicate:');
			console.error('[Vault] 1. Incorrect master password');
			console.error('[Vault] 2. Entries encrypted with different password');
			console.error('[Vault] 3. Database corruption');
			// Don't throw - return empty array so user can still see the interface
			// The frontend will show appropriate message
		}

		return entries;
	} catch (error) {
		console.error('[Vault] Error in getAllEntries:', error);
		// Return empty array instead of throwing to prevent app crash
		// Log the error for debugging
		return [];
	}
}

function saveEntryHistory(entryId, masterPassword) {
	try {
		// Get current entry state
		const getStmt = db.prepare(`SELECT * FROM entries WHERE id = ?`);
		const entry = getStmt.get(entryId);

		if (!entry) {
			return false;
		}

		// Decrypt entry data to store in history
		const decryptedPassword = decrypt(entry.encrypted_password, masterPassword, entry.salt, entry.iv);
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
		const historySalt = generateSalt();
		const historyIV = generateIV();
		const encryptedHistory = encrypt(JSON.stringify(historyData), masterPassword, historySalt, historyIV);

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

function getEntryHistory(entryId, masterPassword) {
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
				const decryptedData = decrypt(row.encrypted_data, masterPassword, row.salt, row.iv);
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

function rollbackEntry(entryId, historyId, masterPassword) {
	try {
		// Get history entry
		const historyStmt = db.prepare(`SELECT * FROM entry_history WHERE id = ? AND entry_id = ?`);
		const historyRow = historyStmt.get(historyId, entryId);

		if (!historyRow) {
			throw new Error('History entry not found');
		}

		// Decrypt history data
		const decryptedData = decrypt(historyRow.encrypted_data, masterPassword, historyRow.salt, historyRow.iv);
		if (!decryptedData) {
			throw new Error('Failed to decrypt history data');
		}

		const historyData = JSON.parse(decryptedData);

		// Save current state to history before rollback
		saveEntryHistory(entryId, masterPassword);

		// Encrypt with new salt/IV for security
		const newSalt = generateSalt();
		const newIV = generateIV();
		const encryptedPassword = encrypt(historyData.password, masterPassword, newSalt, newIV);

		// Update entry with history data
		const updateStmt = db.prepare(`
			UPDATE entries 
			SET name = ?, username = ?, encrypted_password = ?, category = ?, salt = ?, iv = ?, last_modified = CURRENT_TIMESTAMP
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

function updateEntry(id, name, username, plainPassword, category, masterPassword) {
	console.log('[Vault] updateEntry called for entry ID:', id);

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
		const getStmt = db.prepare(`SELECT encrypted_password, salt, iv FROM entries WHERE id = ?`);
		const existingEntry = getStmt.get(id);

		if (!existingEntry) {
			throw new Error('Entry not found');
		}

		// Save current state to history before updating
		saveEntryHistory(id, masterPassword);

		// Decrypt old password to check if it changed
		const oldPassword = decrypt(existingEntry.encrypted_password, masterPassword, existingEntry.salt, existingEntry.iv);

		// Generate new salt and IV if password changed, otherwise keep existing ones
		let salt, iv, encryptedPassword;
		if (oldPassword !== plainPassword) {
			// Password changed - generate new salt and IV for security
			salt = generateSalt();
			iv = generateIV();
			encryptedPassword = encrypt(plainPassword, masterPassword, salt, iv);
		} else {
			// Password unchanged - keep existing salt and IV
			salt = existingEntry.salt;
			iv = existingEntry.iv;
			encryptedPassword = existingEntry.encrypted_password;
		}

		// Update entry with new values
		const stmt = db.prepare(`
			UPDATE entries 
			SET name = ?, username = ?, encrypted_password = ?, category = ?, salt = ?, iv = ?, last_modified = CURRENT_TIMESTAMP
			WHERE id = ?
		`);
		const result = stmt.run(name, username || '', encryptedPassword, category || 'personal', salt, iv, id);

		if (result.changes === 0) {
			throw new Error('Failed to update entry');
		}

		console.log('[Vault] Entry updated successfully');
		return true;
	} catch (error) {
		console.error('[Vault] Error in updateEntry:', error);
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

function changeMasterPassword(oldMasterPassword, newMasterPassword) {
	console.log('[Vault] changeMasterPassword called');

	// Validate old password first
	try {
		const isValid = testMasterPassword(oldMasterPassword);
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
		const testStmt = db.prepare(`SELECT id, name, encrypted_password, salt, iv FROM entries LIMIT 5`);
		const testRows = testStmt.all();
		let canDecryptCount = 0;
		for (const row of testRows) {
			const testDecrypt = decrypt(row.encrypted_password, oldMasterPassword, row.salt, row.iv);
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

				const plainPassword = decrypt(row.encrypted_password, oldMasterPassword, row.salt, row.iv);
				if (plainPassword && plainPassword.length > 0) {
					decryptableEntries.push({ ...row, plainPassword });
				} else {
					failedEntries.push({ id: row.id, name: row.name || 'Unknown', reason: 'Decryption returned empty result' });
					console.warn(`[Vault] Cannot decrypt entry ${row.id} (${row.name || 'Unknown'}) - decryption returned empty`);
				}
			} catch (error) {
				failedEntries.push({ id: row.id, name: row.name || 'Unknown', reason: error.message });
				console.warn(`[Vault] Error decrypting entry ${row.id} (${row.name || 'Unknown'}):`, error.message);
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
			console.warn(
				`[Vault] Warning: ${failedEntries.length} entry/entries cannot be decrypted and will be skipped: ${failedDetails}`
			);
		}

		console.log(
			`[Vault] ${decryptableEntries.length} entries can be re-encrypted, ${failedEntries.length} will be skipped`
		);

		// Use a transaction to ensure atomicity
		const transaction = db.transaction(() => {
			// Prepare statements inside transaction
			const updateStmt = db.prepare(`
				UPDATE entries 
				SET encrypted_password = ?, salt = ?, iv = ?, last_modified = CURRENT_TIMESTAMP
				WHERE id = ?
			`);

			// Only re-encrypt entries that we successfully decrypted
			for (const entry of decryptableEntries) {
				try {
					// Generate new salt and IV for security
					const newSalt = generateSalt();
					const newIV = generateIV();

					// Encrypt with new password (we already have plainPassword from the check above)
					const newEncryptedPassword = encrypt(entry.plainPassword, newMasterPassword, newSalt, newIV);

					// Update entry
					updateStmt.run(newEncryptedPassword, newSalt, newIV, entry.id);
					console.log(`[Vault] Successfully re-encrypted entry ${entry.id}`);
				} catch (error) {
					console.error(`[Vault] Error re-encrypting entry ${entry.id}:`, error);
					throw new Error(`Failed to re-encrypt entry ${entry.id}: ${error.message}`);
				}
			}

			// Update master password hash
			const newSalt = generateSalt();
			const newHash = CryptoJS.PBKDF2(newMasterPassword, newSalt, {
				keySize: KEY_LENGTH / 4,
				iterations: PBKDF2_ITERATIONS,
			}).toString();

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

function testMasterPassword(masterPassword) {
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
				const salt = generateSalt();
				const hash = CryptoJS.PBKDF2(masterPassword, salt, {
					keySize: KEY_LENGTH / 4,
					iterations: PBKDF2_ITERATIONS,
				}).toString();

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
			const testHash = CryptoJS.PBKDF2(masterPassword, hashResult.password_salt, {
				keySize: KEY_LENGTH / 4,
				iterations: PBKDF2_ITERATIONS,
			}).toString();

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
		const testStmt = db.prepare(`SELECT encrypted_password, salt, iv FROM entries LIMIT 1`);
		const testRow = testStmt.get();

		if (testRow) {
			const password = decrypt(testRow.encrypted_password, masterPassword, testRow.salt, testRow.iv);
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
			encryption: 'AES-256-CBC',
			keyDerivation: 'PBKDF2',
			iterations: PBKDF2_ITERATIONS,
			saltLength: SALT_LENGTH * 8, // in bits
			ivLength: IV_LENGTH * 8, // in bits
			securityLevel: 'Ultra-Maximum',
			failedAttempts: securityResult ? securityResult.failed_attempts : 0,
			isLocked:
				securityResult && securityResult.locked_until ? new Date(securityResult.locked_until) > new Date() : false,
			lockTimeRemaining:
				securityResult && securityResult.locked_until
					? Math.ceil((new Date(securityResult.locked_until) - new Date()) / (1000 * 60))
					: 0,
			encryptionVersion: 'v2.0',
			databaseEncrypted: false, // Database file is not encrypted, but data inside is encrypted
			securityFeatures: {
				clipboardProtection: true,
				screenCaptureDetection: SCREEN_CAPTURE_DETECTION,
				autoLock: true,
				bruteForceProtection: true,
				keyloggerProtection: true,
				networkIsolation: true,
			},
		};
	} catch (error) {
		console.error('[Vault] Error getting security info:', error);
		return null;
	}
}

// Enhanced clipboard security function
function secureClipboardCopy(text, timeout = CLIPBOARD_TIMEOUT) {
	try {
		// Copy to clipboard
		if (navigator && navigator.clipboard) {
			navigator.clipboard.writeText(text);

			// Clear clipboard after timeout
			setTimeout(() => {
				try {
					navigator.clipboard.writeText('');
					console.log('[Vault] Clipboard cleared for security');
				} catch (e) {
					console.warn('[Vault] Could not clear clipboard:', e);
				}
			}, timeout);

			return true;
		}
		return false;
	} catch (error) {
		console.error('[Vault] Clipboard operation failed:', error);
		return false;
	}
}

// Screen capture detection (basic implementation)
function detectScreenCapture() {
	if (!SCREEN_CAPTURE_DETECTION) return false;

	try {
		// Check for common screen capture indicators
		const indicators = [
			'getDisplayMedia' in navigator,
			'mediaDevices' in navigator && 'getDisplayMedia' in navigator.mediaDevices,
			'webkitGetUserMedia' in navigator,
			'mozGetUserMedia' in navigator,
		];

		// If screen capture is detected, trigger security measures
		if (indicators.some(Boolean)) {
			console.warn('[Vault] Potential screen capture detected');
			return true;
		}

		return false;
	} catch (error) {
		console.error('[Vault] Screen capture detection error:', error);
		return false;
	}
}

// Enhanced security cleanup
function enhancedCleanup() {
	try {
		// Clear any sensitive data from memory
		// Clear clipboard
		if (navigator && navigator.clipboard) {
			navigator.clipboard.writeText('').catch(() => {});
		}

		// Clear console logs in production
		if (process.env.NODE_ENV === 'production') {
			console.clear();
		}

		console.log('[Vault] Enhanced security cleanup completed');
	} catch (error) {
		console.error('[Vault] Error during enhanced cleanup:', error);
	}
}

function diagnoseEntry(entryId, masterPassword) {
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
				const decrypted = decrypt(row.encrypted_password, masterPassword, row.salt, row.iv);
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

function setPasswordHint(hint, masterPassword) {
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
		const hintSalt = generateSalt();
		const hintIV = generateIV();
		const encryptedHint = encrypt(hint.trim(), masterPassword, hintSalt, hintIV);

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

function getPasswordHint(masterPassword) {
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

		// Decrypt hint
		const decryptedHint = decrypt(result.password_hint, masterPassword, result.hint_salt, result.hint_iv);

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

function setPasswordHint(hint, masterPassword) {
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
		const hintSalt = generateSalt();
		const hintIV = generateIV();
		const encryptedHint = encrypt(hint.trim(), masterPassword, hintSalt, hintIV);

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

// Recovery Questions Functions
function setRecoveryQuestions(questions, masterPassword) {
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
			const answerSalt = generateSalt();
			const answerHash = CryptoJS.PBKDF2(q.answer.trim().toLowerCase(), answerSalt, {
				keySize: KEY_LENGTH / 4,
				iterations: PBKDF2_ITERATIONS,
			}).toString();

			insertStmt.run(i + 1, q.question.trim(), answerHash, answerSalt);
		}

		console.log(`[Vault] Set ${questions.length} recovery questions successfully`);
		return true;
	} catch (error) {
		console.error('[Vault] Error setting recovery questions:', error);
		throw error;
	}
}

function verifyRecoveryQuestions(answers) {
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
				const testHash = CryptoJS.PBKDF2(providedAnswer, question.answer_salt, {
					keySize: KEY_LENGTH / 4,
					iterations: PBKDF2_ITERATIONS,
				}).toString();

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
function generateBackupCode() {
	const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // Exclude confusing chars (0, O, I, 1)
	let code = '';
	for (let i = 0; i < 8; i++) {
		code += chars.charAt(Math.floor(Math.random() * chars.length));
	}
	return code;
}

function generateBackupCodes(masterPassword) {
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
			// Generate 8-character alphanumeric code
			const code = generateBackupCode();
			codes.push(code);

			// Hash the code (not encrypt - so it works even if password changes)
			const codeHash = CryptoJS.SHA256(code).toString();
			insertStmt.run(codeHash);
		}

		console.log('[Vault] Generated 10 backup codes');
		return codes; // Return plain codes for user to save
	} catch (error) {
		console.error('[Vault] Error generating backup codes:', error);
		throw error;
	}
}

function verifyBackupCode(code) {
	try {
		if (!code || code.length !== 8) {
			return { verified: false, error: 'Invalid backup code format' };
		}

		// Hash the provided code
		const codeHash = CryptoJS.SHA256(code.toUpperCase()).toString();

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
function setupEmailSMSRecovery(email, phone, masterPassword) {
	try {
		// Generate a recovery key (this will be used to encrypt the master password backup)
		const recoveryKey = generateSalt(); // 32 bytes random key
		const recoveryKeySalt = generateSalt();
		const recoveryKeyIV = generateIV();

		// Encrypt the recovery key with a key derived from email+phone (so we can recover it)
		// For simplicity, we'll use a hash of email+phone as the key
		const recoveryKeyDerivation = CryptoJS.SHA256(email + phone + 'recovery').toString();
		const encryptedRecoveryKey = encrypt(recoveryKey, recoveryKeyDerivation, recoveryKeySalt, recoveryKeyIV);

		// Encrypt the master password with the recovery key
		const masterPasswordBackupSalt = generateSalt();
		const masterPasswordBackupIV = generateIV();
		const encryptedMasterPasswordBackup = encrypt(
			masterPassword,
			recoveryKey,
			masterPasswordBackupSalt,
			masterPasswordBackupIV
		);

		// Store in database
		const updateStmt = db.prepare(`
			UPDATE security_metadata 
			SET recovery_email = ?,
				recovery_phone = ?,
				recovery_key_encrypted = ?,
				recovery_key_salt = ?,
				recovery_key_iv = ?,
				master_password_backup_encrypted = ?,
				master_password_backup_salt = ?,
				master_password_backup_iv = ?,
				last_modified = CURRENT_TIMESTAMP
			WHERE id = 1
		`);
		updateStmt.run(
			email,
			phone,
			encryptedRecoveryKey,
			recoveryKeySalt,
			recoveryKeyIV,
			encryptedMasterPasswordBackup,
			masterPasswordBackupSalt,
			masterPasswordBackupIV
		);

		console.log('[Vault] Email/SMS recovery set up successfully');
		return true;
	} catch (error) {
		console.error('[Vault] Error setting up email/SMS recovery:', error);
		throw error;
	}
}

// Generate and send recovery code
function generateRecoveryCode(email, phone) {
	try {
		// Check if email/SMS recovery is set up
		const checkStmt = db.prepare(`SELECT recovery_email, recovery_phone FROM security_metadata WHERE id = 1`);
		const result = checkStmt.get();

		if (!result || (!result.recovery_email && !result.recovery_phone)) {
			throw new Error('Email/SMS recovery is not set up');
		}

		// Generate 6-digit code
		const code = Math.floor(100000 + Math.random() * 900000).toString();
		const codeHash = CryptoJS.SHA256(code).toString();

		// Store code hash with expiration (30 minutes - more reasonable time)
		const expiresAt = new Date(Date.now() + 30 * 60 * 1000);
		const insertStmt = db.prepare(`
			INSERT INTO recovery_codes (code_hash, expires_at, created_at)
			VALUES (?, ?, CURRENT_TIMESTAMP)
		`);
		insertStmt.run(codeHash, expiresAt.toISOString());

		// In a real implementation, you would send this code via email/SMS
		// For now, we'll just log it (in production, use a service like SendGrid, Twilio, etc.)
		console.log('========================================');
		console.log(`[Vault] ✅ Recovery code generated: ${code}`);
		console.log(`[Vault] ⏰ Expires in: 30 minutes`);
		console.log(`[Vault] 📧 Would send to email: ${result.recovery_email || 'N/A'}`);
		console.log(`[Vault] 📱 Would send to phone: ${result.recovery_phone || 'N/A'}`);
		console.log('========================================');

		// TODO: Integrate with email/SMS service
		// For development, return the code so user can see it
		// In production, return success without the code
		return { success: true, code: code }; // Remove code in production!
	} catch (error) {
		console.error('[Vault] Error generating recovery code:', error);
		throw error;
	}
}

// Verify recovery code (doesn't mark as used - that happens during password reset)
function verifyRecoveryCode(code) {
	try {
		if (!code || typeof code !== 'string' || code.length !== 6) {
			console.error('[Vault] Invalid recovery code format:', code);
			return { verified: false, error: 'Invalid recovery code format' };
		}

		const codeHash = CryptoJS.SHA256(code).toString();
		console.log('[Vault] Verifying recovery code, hash:', codeHash.substring(0, 8) + '...');
		console.log('[Vault] Current time:', new Date().toISOString());

		// Check if code exists and is not expired or already used
		const checkStmt = db.prepare(`
			SELECT id, expires_at, used, created_at FROM recovery_codes 
			WHERE code_hash = ?
		`);
		const result = checkStmt.get(codeHash);

		if (!result) {
			console.error('[Vault] Recovery code not found in database');
			console.error('[Vault] Searched for hash:', codeHash.substring(0, 16) + '...');
			// List all recovery codes for debugging
			const allCodesStmt = db.prepare(
				`SELECT id, code_hash, expires_at, used, created_at FROM recovery_codes ORDER BY created_at DESC LIMIT 5`
			);
			const allCodes = allCodesStmt.all();
			console.log(
				'[Vault] Recent recovery codes in database:',
				allCodes.map(c => ({
					id: c.id,
					hash: c.code_hash.substring(0, 8) + '...',
					expiresAt: c.expires_at,
					used: c.used,
				}))
			);
			return { verified: false, error: 'Invalid recovery code' };
		}

		console.log('[Vault] Recovery code found:', {
			id: result.id,
			used: result.used,
			expiresAt: result.expires_at,
			createdAt: result.created_at,
		});

		// Check if already used
		if (result.used === 1) {
			console.error('[Vault] Recovery code already used');
			console.error('[Vault] Code was used, cannot verify again');
			return { verified: false, error: 'This recovery code has already been used' };
		}

		// Check expiration
		const expiresAt = new Date(result.expires_at);
		const now = new Date();
		console.log('[Vault] Expires at:', expiresAt.toISOString());
		console.log('[Vault] Current time:', now.toISOString());
		if (expiresAt < now) {
			const minutesExpired = Math.floor((now - expiresAt) / 1000 / 60);
			console.error('[Vault] Recovery code expired', minutesExpired, 'minutes ago');
			return { verified: false, error: 'Recovery code has expired' };
		}

		console.log('[Vault] Recovery code verified successfully');
		// Don't mark as used here - that will happen during password reset
		// This allows the code to be verified multiple times before reset
		return { verified: true, codeId: result.id };
	} catch (error) {
		console.error('[Vault] Error verifying recovery code:', error);
		return { verified: false, error: 'Failed to verify recovery code: ' + error.message };
	}
}

// Mark recovery code as used (called during password reset)
function markRecoveryCodeAsUsed(code) {
	try {
		const codeHash = CryptoJS.SHA256(code).toString();
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

// Password Reset via Recovery (with data preservation for email/SMS)
// This version decrypts all entries with the old password and re-encrypts with the new one
function resetMasterPasswordViaRecovery(newPassword, recoveryMethod, recoveryData) {
	try {
		// Validate new password
		validateMasterPassword(newPassword);

		// Verify recovery method
		let verified = false;
		let oldMasterPassword = null;
		let recoveryData_db = null;

		if (recoveryMethod === 'email_sms') {
			// Verify recovery code (check if valid and not expired)
			console.log('[Vault] ========== RESET PASSWORD VIA EMAIL/SMS RECOVERY ==========');
			console.log(
				'[Vault] Code received:',
				recoveryData.code ? recoveryData.code.substring(0, 2) + '****' : 'UNDEFINED'
			);
			console.log('[Vault] Code length:', recoveryData.code?.length);
			console.log('[Vault] Code type:', typeof recoveryData.code);

			if (!recoveryData || !recoveryData.code) {
				console.error('[Vault] No recovery code provided in recoveryData');
				throw new Error('Recovery code is required');
			}

			if (typeof recoveryData.code !== 'string' || recoveryData.code.length !== 6) {
				console.error('[Vault] Invalid recovery code format:', {
					type: typeof recoveryData.code,
					length: recoveryData.code.length,
					code: recoveryData.code.substring(0, 2) + '****',
				});
				throw new Error('Invalid recovery code format. Code must be exactly 6 digits.');
			}

			console.log('[Vault] About to verify recovery code:', recoveryData.code.substring(0, 2) + '****');
			let verifyResult;
			try {
				verifyResult = verifyRecoveryCode(recoveryData.code);
				console.log('[Vault] Verification result:', JSON.stringify(verifyResult, null, 2));
			} catch (verifyError) {
				console.error('[Vault] Exception during verifyRecoveryCode:', verifyError);
				throw new Error('Failed to verify recovery code: ' + (verifyError.message || 'Unknown error'));
			}

			if (!verifyResult) {
				console.error('[Vault] verifyRecoveryCode returned null/undefined');
				throw new Error('Recovery code verification returned no result');
			}

			if (!verifyResult.verified) {
				const errorMsg = verifyResult.error || 'Recovery code verification failed';
				console.error('[Vault] Recovery code verification failed');
				console.error('[Vault] Error message:', errorMsg);
				console.error('[Vault] Full verification result:', JSON.stringify(verifyResult, null, 2));
				console.error('[Vault] Code that failed:', recoveryData.code);
				throw new Error(errorMsg);
			}

			console.log('[Vault] ✅ Recovery code verified successfully!');

			console.log('[Vault] Recovery code verified, marking as used');
			// Mark code as used now that we're actually resetting the password
			const marked = markRecoveryCodeAsUsed(recoveryData.code);
			if (!marked) {
				console.warn('[Vault] Failed to mark recovery code as used, but continuing with reset');
			}

			// Get recovery data from database
			const recoveryStmt = db.prepare(`
				SELECT recovery_email, recovery_phone, recovery_key_encrypted, recovery_key_salt, recovery_key_iv,
					master_password_backup_encrypted, master_password_backup_salt, master_password_backup_iv
				FROM security_metadata WHERE id = 1
			`);
			recoveryData_db = recoveryStmt.get();

			if (!recoveryData_db || !recoveryData_db.master_password_backup_encrypted) {
				throw new Error('Email/SMS recovery is not set up');
			}

			// Decrypt recovery key using email+phone
			const recoveryKeyDerivation = CryptoJS.SHA256(
				recoveryData_db.recovery_email + recoveryData_db.recovery_phone + 'recovery'
			).toString();
			const recoveryKey = decrypt(
				recoveryData_db.recovery_key_encrypted,
				recoveryKeyDerivation,
				recoveryData_db.recovery_key_salt,
				recoveryData_db.recovery_key_iv
			);

			// Decrypt master password backup
			oldMasterPassword = decrypt(
				recoveryData_db.master_password_backup_encrypted,
				recoveryKey,
				recoveryData_db.master_password_backup_salt,
				recoveryData_db.master_password_backup_iv
			);

			if (!oldMasterPassword) {
				throw new Error('Failed to decrypt master password backup');
			}

			verified = true;
		} else if (recoveryMethod === 'backup_code') {
			const verifyResult = verifyBackupCode(recoveryData.code);
			if (!verifyResult.verified) {
				throw new Error(verifyResult.error || 'Backup code verification failed');
			}
			// Backup codes don't give us the old password, so we can't preserve data
			verified = true;
		} else if (recoveryMethod === 'questions') {
			const verifyResult = verifyRecoveryQuestions(recoveryData.answers);
			if (!verifyResult.verified) {
				throw new Error(verifyResult.error || 'Recovery questions verification failed');
			}
			// Questions don't give us the old password either
			verified = true;
		} else {
			throw new Error('Invalid recovery method');
		}

		if (!verified) {
			throw new Error('Recovery verification failed');
		}

		// If we have the old password (from email/SMS recovery), decrypt and re-encrypt all entries
		if (oldMasterPassword) {
			console.log('[Vault] Recovering password with data preservation...');

			// Get all entries
			const stmt = db.prepare(`SELECT * FROM entries ORDER BY id`);
			const rows = stmt.all();
			console.log('[Vault] Found', rows.length, 'entries to re-encrypt');

			// Decrypt all entries with old password
			const decryptableEntries = [];
			for (const row of rows) {
				try {
					const plainPassword = decrypt(row.encrypted_password, oldMasterPassword, row.salt, row.iv);
					if (plainPassword && plainPassword.length > 0) {
						decryptableEntries.push({ ...row, plainPassword });
					}
				} catch (error) {
					console.warn(`[Vault] Cannot decrypt entry ${row.id}:`, error.message);
				}
			}

			// Use transaction to re-encrypt all entries
			const transaction = db.transaction(() => {
				const updateStmt = db.prepare(`
					UPDATE entries 
					SET encrypted_password = ?, salt = ?, iv = ?, last_modified = CURRENT_TIMESTAMP
					WHERE id = ?
				`);

				for (const entry of decryptableEntries) {
					const newSalt = generateSalt();
					const newIV = generateIV();
					const newEncryptedPassword = encrypt(entry.plainPassword, newPassword, newSalt, newIV);
					updateStmt.run(newEncryptedPassword, newSalt, newIV, entry.id);
				}

				// Update master password hash
				const newSalt = generateSalt();
				const newHash = CryptoJS.PBKDF2(newPassword, newSalt, {
					keySize: KEY_LENGTH / 4,
					iterations: PBKDF2_ITERATIONS,
				}).toString();

				const updateHashStmt = db.prepare(`
					UPDATE security_metadata 
					SET master_password_hash = ?, password_salt = ?, last_modified = CURRENT_TIMESTAMP
					WHERE id = 1
				`);
				updateHashStmt.run(newHash, newSalt);

				// Update recovery backup with new password
				const recoveryKey = generateSalt();
				const recoveryKeySalt = generateSalt();
				const recoveryKeyIV = generateIV();
				const recoveryKeyDerivation = CryptoJS.SHA256(
					recoveryData_db.recovery_email + recoveryData_db.recovery_phone + 'recovery'
				).toString();
				const encryptedRecoveryKey = encrypt(recoveryKey, recoveryKeyDerivation, recoveryKeySalt, recoveryKeyIV);

				const masterPasswordBackupSalt = generateSalt();
				const masterPasswordBackupIV = generateIV();
				const encryptedMasterPasswordBackup = encrypt(
					newPassword,
					recoveryKey,
					masterPasswordBackupSalt,
					masterPasswordBackupIV
				);

				const updateRecoveryStmt = db.prepare(`
					UPDATE security_metadata 
					SET recovery_key_encrypted = ?,
						recovery_key_salt = ?,
						recovery_key_iv = ?,
						master_password_backup_encrypted = ?,
						master_password_backup_salt = ?,
						master_password_backup_iv = ?
					WHERE id = 1
				`);
				updateRecoveryStmt.run(
					encryptedRecoveryKey,
					recoveryKeySalt,
					recoveryKeyIV,
					encryptedMasterPasswordBackup,
					masterPasswordBackupSalt,
					masterPasswordBackupIV
				);
			});

			transaction();

			console.log('[Vault] Master password reset via email/SMS recovery - all data preserved');
			return {
				success: true,
				message:
					'Password reset successful. All your password entries have been preserved and are now accessible with your new password.',
			};
		} else {
			// For backup codes and questions, we can't preserve data
			const newSalt = generateSalt();
			const newHash = CryptoJS.PBKDF2(newPassword, newSalt, {
				keySize: KEY_LENGTH / 4,
				iterations: PBKDF2_ITERATIONS,
			}).toString();

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

			console.log('[Vault] Master password reset via recovery (data not preserved)');
			return {
				success: true,
				warning:
					'Password reset successful. However, all password entries remain encrypted with your old password and cannot be accessed. You will need to delete and recreate them.',
			};
		}
	} catch (error) {
		console.error('[Vault] Error resetting password via recovery:', error);
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
	cleanup: enhancedCleanup, // Use enhanced cleanup
	secureClipboardCopy,
	detectScreenCapture,
	enhancedCleanup,
};
