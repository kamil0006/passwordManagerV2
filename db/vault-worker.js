const { parentPort } = require('worker_threads');
const crypto = require('crypto');

if (process.env.NODE_ENV !== 'production') {
	console.log('[VaultWorker] Secure worker thread started');
}

// Security constants
const PBKDF2_ITERATIONS = 100000;
const SALT_LENGTH = 32;
const KEY_LENGTH = 32;
const IV_LENGTH = 12; // 12 bytes (96 bits) for GCM - recommended size

// Enhanced error handling
process.on('uncaughtException', error => {
	console.error('[VaultWorker] Uncaught exception:', error);
	// Don't crash the worker, just log and continue
	if (parentPort) {
		parentPort.postMessage({
			id: 'error',
			result: null,
			error: `Worker error: ${error.message}`,
			timestamp: Date.now(),
		});
	}
});

process.on('unhandledRejection', (reason, promise) => {
	console.error('[VaultWorker] Unhandled rejection at:', promise, 'reason:', reason);
	// Handle unhandled promises gracefully
});

// Memory cleanup (best effort - JavaScript GC doesn't guarantee secure wipe)
function secureMemoryCleanup() {
	try {
		// Force garbage collection if available
		if (global.gc) {
			global.gc();
		}

		if (process.env.NODE_ENV !== 'production') {
			console.log('[VaultWorker] Memory cleanup completed');
		}
	} catch (error) {
		if (process.env.NODE_ENV !== 'production') {
			console.error('[VaultWorker] Memory cleanup error:', error);
		}
	}
}

// Real encryption functions
function generateSecureSalt() {
	return crypto.randomBytes(SALT_LENGTH);
}

function generateSecureIV() {
	return crypto.randomBytes(IV_LENGTH); // 12 bytes for GCM
}

function deriveSecureKey(password, salt) {
	return crypto.pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, KEY_LENGTH, 'sha256');
}

// Unified AAD for all encryption operations
const ENCRYPTION_AAD = Buffer.from('password-manager-vault', 'utf8');

// FIXED: Use createCipheriv with explicit IV (required for GCM)
function encryptSecure(text, key, iv) {
	// Ensure IV is a Buffer
	const ivBuffer = Buffer.isBuffer(iv) ? iv : Buffer.from(iv, 'hex');

	// Use createCipheriv (not createCipher) with explicit IV
	const cipher = crypto.createCipheriv('aes-256-gcm', key, ivBuffer);
	cipher.setAAD(ENCRYPTION_AAD);

	let encrypted = cipher.update(text, 'utf8', 'hex');
	encrypted += cipher.final('hex');

	const authTag = cipher.getAuthTag();

	return {
		encrypted,
		authTag: authTag.toString('hex'),
		iv: ivBuffer.toString('hex'),
	};
}

// FIXED: Use createDecipheriv with explicit IV (required for GCM)
function decryptSecure(encryptedData, key, iv) {
	try {
		// Ensure IV is a Buffer
		const ivBuffer = Buffer.isBuffer(iv) ? iv : Buffer.from(iv, 'hex');

		// Use createDecipheriv (not createDecipher) with explicit IV
		const decipher = crypto.createDecipheriv('aes-256-gcm', key, ivBuffer);
		decipher.setAAD(ENCRYPTION_AAD);
		decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));

		let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
		decrypted += decipher.final('utf8');

		return decrypted;
	} catch (error) {
		console.error('[VaultWorker] Decryption failed:', error.message);
		return null;
	}
}

// High-level encryption function (for vault.js)
// Returns object with separate fields for better structure
function encryptVault(text, password, salt, iv) {
	const key = deriveSecureKey(password, Buffer.from(salt, 'hex'));
	const result = encryptSecure(text, key, Buffer.from(iv, 'hex'));
	// Return object format for consistency
	return {
		encrypted: result.encrypted,
		authTag: result.authTag,
	};
}

// High-level decryption function (for vault.js) with legacy support
// Accepts both object format (new) and string format (legacy compatibility)
function decryptVault(ciphertextData, password, salt, iv) {
	try {
		let encrypted, authTagHex;

		// Handle both object format (new) and string format (legacy)
		if (typeof ciphertextData === 'object' && ciphertextData.encrypted && ciphertextData.authTag) {
			// New object format
			encrypted = ciphertextData.encrypted;
			authTagHex = ciphertextData.authTag;
		} else if (typeof ciphertextData === 'string') {
			// Legacy string format (encrypted:authTag)
			const parts = ciphertextData.split(':');
			if (parts.length === 2) {
				encrypted = parts[0];
				authTagHex = parts[1];
			} else {
				// Legacy CBC format - return null, vault.js will handle it
				return null;
			}
		} else {
			return null;
		}

		const key = deriveSecureKey(password, Buffer.from(salt, 'hex'));
		const result = decryptSecure({ encrypted, authTag: authTagHex }, key, Buffer.from(iv, 'hex'));
		return result;
	} catch (error) {
		if (process.env.NODE_ENV !== 'production') {
			console.error('[VaultWorker] Decryption failed:', error.message);
		}
		return null;
	}
}

// Secure password validation
function validatePasswordStrength(password) {
	const checks = {
		length: password.length >= 12,
		uppercase: /[A-Z]/.test(password),
		lowercase: /[a-z]/.test(password),
		numbers: /\d/.test(password),
		special: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password),
		noCommon: !['password', '123456', 'qwerty', 'admin'].includes(password.toLowerCase()),
	};

	const score = Object.values(checks).filter(Boolean).length;
	const strength = score < 3 ? 'weak' : score < 5 ? 'medium' : 'strong';

	return {
		isValid: score >= 4,
		score,
		strength,
		checks,
		recommendations: Object.entries(checks)
			.filter(([_, passed]) => !passed)
			.map(([check]) => check),
	};
}

// Handle messages from main process
parentPort.on('message', async message => {
	try {
		// Only log message type in development, never log message.data
		if (process.env.NODE_ENV !== 'production') {
			console.log('[VaultWorker] Processing message:', message.type);
		}

		let result;

		switch (message.type) {
			case 'initialize':
				result = { success: true };
				break;

			// Note: All vault operations (addEntry, getEntries, etc.) removed from worker
			// Worker handles ONLY cryptographic operations for better isolation
			// Vault operations should be called directly from main.js -> vault.js

			case 'validatePassword':
				result = validatePasswordStrength(message.data.password);
				break;

			case 'encryptData':
				const salt = generateSecureSalt();
				const iv = generateSecureIV();
				const key = deriveSecureKey(message.data.password, salt);
				const encrypted = encryptSecure(message.data.text, key, iv);

				result = {
					encrypted: encrypted.encrypted,
					salt: salt.toString('hex'),
					iv: encrypted.iv,
					authTag: encrypted.authTag,
				};
				break;

			case 'decryptData':
				const decKey = deriveSecureKey(message.data.password, Buffer.from(message.data.salt, 'hex'));
				const decrypted = decryptSecure(message.data.encryptedData, decKey, Buffer.from(message.data.iv, 'hex'));

				result = { decrypted };
				break;

			case 'generatePassword':
				const length = message.data.length || 16;
				const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
				let generatedPassword = '';

				for (let i = 0; i < length; i++) {
					generatedPassword += charset.charAt(crypto.randomInt(charset.length));
				}

				result = { password: generatedPassword };
				break;

			// Cryptographic operations for vault.js (all crypto in worker)
			case 'generateSalt':
				result = { salt: generateSecureSalt().toString('hex') };
				break;

			case 'generateIV':
				result = { iv: generateSecureIV().toString('hex') };
				break;

			case 'encryptVault':
				result = {
					encrypted: encryptVault(message.data.text, message.data.password, message.data.salt, message.data.iv),
				};
				// Best effort to clear password reference (JavaScript GC doesn't guarantee secure wipe)
				message.data.password = null;
				break;

			case 'decryptVault':
				result = {
					decrypted: decryptVault(message.data.ciphertext, message.data.password, message.data.salt, message.data.iv),
				};
				// Best effort to clear password reference (JavaScript GC doesn't guarantee secure wipe)
				message.data.password = null;
				break;

			case 'hashPBKDF2':
				const hashSalt = message.data.salt ? Buffer.from(message.data.salt, 'hex') : generateSecureSalt();
				const hash = crypto.pbkdf2Sync(message.data.password, hashSalt, PBKDF2_ITERATIONS, KEY_LENGTH, 'sha256');
				result = {
					hash: hash.toString('hex'),
					salt: hashSalt.toString('hex'),
				};
				// Best effort to clear password reference (JavaScript GC doesn't guarantee secure wipe)
				message.data.password = null;
				break;

			case 'hashSHA256':
				result = {
					hash: crypto.createHash('sha256').update(message.data.text).digest('hex'),
				};
				break;

			case 'cleanup':
				secureMemoryCleanup();
				result = { success: true, message: 'Secure cleanup completed' };
				break;

			default:
				throw new Error(`Unknown message type: ${message.type}`);
		}

		// Send result back to main process
		parentPort.postMessage({
			id: message.id,
			result,
			error: null,
			timestamp: Date.now(),
		});
	} catch (error) {
		if (process.env.NODE_ENV !== 'production') {
			console.error('[VaultWorker] Error processing message:', error);
		}

		// Send error back to main process
		parentPort.postMessage({
			id: message.id,
			result: null,
			error: error.message,
			timestamp: Date.now(),
		});
	}
});

// Handle worker shutdown
process.on('exit', () => {
	if (process.env.NODE_ENV !== 'production') {
		console.log('[VaultWorker] Worker thread shutting down');
	}
	secureMemoryCleanup();
});

// Handle SIGTERM for graceful shutdown
process.on('SIGTERM', () => {
	if (process.env.NODE_ENV !== 'production') {
		console.log('[VaultWorker] Received SIGTERM, shutting down gracefully');
	}
	secureMemoryCleanup();
	process.exit(0);
});

// Periodic memory cleanup
setInterval(() => {
	secureMemoryCleanup();
}, 300000); // Every 5 minutes
