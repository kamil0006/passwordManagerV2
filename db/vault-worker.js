const { parentPort } = require('worker_threads');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

console.log('[VaultWorker] Secure worker thread started');

// Security constants
const PBKDF2_ITERATIONS = 100000;
const SALT_LENGTH = 32;
const KEY_LENGTH = 32;
const IV_LENGTH = 16;

// Memory management
let sensitiveData = new Map();

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

// Secure memory cleanup
function secureMemoryCleanup() {
	try {
		// Clear sensitive data from memory
		sensitiveData.clear();

		// Force garbage collection if available
		if (global.gc) {
			global.gc();
		}

		console.log('[VaultWorker] Secure memory cleanup completed');
	} catch (error) {
		console.error('[VaultWorker] Memory cleanup error:', error);
	}
}

// Real encryption functions
function generateSecureSalt() {
	return crypto.randomBytes(SALT_LENGTH);
}

function generateSecureIV() {
	return crypto.randomBytes(IV_LENGTH);
}

function deriveSecureKey(password, salt) {
	return crypto.pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, KEY_LENGTH, 'sha256');
}

function encryptSecure(text, key, iv) {
	const cipher = crypto.createCipher('aes-256-gcm', key);
	cipher.setAAD(Buffer.from('password-manager', 'utf8'));

	let encrypted = cipher.update(text, 'utf8', 'hex');
	encrypted += cipher.final('hex');

	const authTag = cipher.getAuthTag();

	return {
		encrypted,
		authTag: authTag.toString('hex'),
		iv: iv.toString('hex'),
	};
}

function decryptSecure(encryptedData, key, iv) {
	try {
		const decipher = crypto.createDecipher('aes-256-gcm', key);
		decipher.setAAD(Buffer.from('password-manager', 'utf8'));
		decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));

		let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
		decrypted += decipher.final('utf8');

		return decrypted;
	} catch (error) {
		console.error('[VaultWorker] Decryption failed:', error.message);
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
		console.log('[VaultWorker] Processing message:', message.type);

		let result;

		switch (message.type) {
			case 'initialize':
				result = { success: true };
				break;

			case 'addEntry':
				// Handle old vault operations for compatibility
				try {
					const vault = require('./vault');
					result = vault.addEntry(
						message.data.name,
						message.data.username,
						message.data.password,
						message.data.category,
						message.data.masterPassword
					);
				} catch (error) {
					console.error('[VaultWorker] Error in addEntry:', error);
					throw error;
				}
				break;

			case 'getEntries':
				try {
					const vault = require('./vault');
					result = vault.getAllEntries(message.data);
				} catch (error) {
					console.error('[VaultWorker] Error in getEntries:', error);
					throw error;
				}
				break;

			case 'updateEntry':
				try {
					const vault = require('./vault');
					result = vault.updateEntry(
						message.data.id,
						message.data.name,
						message.data.username,
						message.data.password,
						message.data.category,
						message.data.masterPassword
					);
				} catch (error) {
					console.error('[VaultWorker] Error in updateEntry:', error);
					throw error;
				}
				break;

			case 'getEntryHistory':
				try {
					const vault = require('./vault');
					result = vault.getEntryHistory(message.data.entryId, message.data.masterPassword);
				} catch (error) {
					console.error('[VaultWorker] Error in getEntryHistory:', error);
					throw error;
				}
				break;

			case 'rollbackEntry':
				try {
					const vault = require('./vault');
					result = vault.rollbackEntry(message.data.entryId, message.data.historyId, message.data.masterPassword);
				} catch (error) {
					console.error('[VaultWorker] Error in rollbackEntry:', error);
					throw error;
				}
				break;

			case 'changeMasterPassword':
				try {
					const vault = require('./vault');
					result = vault.changeMasterPassword(message.data.oldPassword, message.data.newPassword);
				} catch (error) {
					console.error('[VaultWorker] Error in changeMasterPassword:', error);
					throw error;
				}
				break;

			case 'diagnoseEntry':
				try {
					const vault = require('./vault');
					result = vault.diagnoseEntry(message.data.entryId, message.data.masterPassword);
				} catch (error) {
					console.error('[VaultWorker] Error in diagnoseEntry:', error);
					throw error;
				}
				break;

			case 'deleteEntry':
				try {
					const vault = require('./vault');
					result = vault.deleteEntry(message.data);
				} catch (error) {
					console.error('[VaultWorker] Error in deleteEntry:', error);
					throw error;
				}
				break;

			case 'testMasterPassword':
				try {
					const vault = require('./vault');
					result = vault.testMasterPassword(message.data);
				} catch (error) {
					console.error('[VaultWorker] Error in testMasterPassword:', error);
					throw error;
				}
				break;

			case 'setPasswordHint':
				try {
					const vault = require('./vault');
					result = vault.setPasswordHint(message.data.hint, message.data.masterPassword);
				} catch (error) {
					console.error('[VaultWorker] Error in setPasswordHint:', error);
					throw error;
				}
				break;

			case 'getPasswordHint':
				try {
					const vault = require('./vault');
					result = vault.getPasswordHint(message.data);
				} catch (error) {
					console.error('[VaultWorker] Error in getPasswordHint:', error);
					throw error;
				}
				break;

			case 'setRecoveryQuestions':
				try {
					const vault = require('./vault');
					result = vault.setRecoveryQuestions(message.data.questions, message.data.masterPassword);
				} catch (error) {
					console.error('[VaultWorker] Error in setRecoveryQuestions:', error);
					throw error;
				}
				break;

			case 'verifyRecoveryQuestions':
				try {
					const vault = require('./vault');
					result = vault.verifyRecoveryQuestions(message.data.answers);
				} catch (error) {
					console.error('[VaultWorker] Error in verifyRecoveryQuestions:', error);
					throw error;
				}
				break;

			case 'getRecoveryQuestions':
				try {
					const vault = require('./vault');
					result = vault.getRecoveryQuestions();
				} catch (error) {
					console.error('[VaultWorker] Error in getRecoveryQuestions:', error);
					throw error;
				}
				break;

			case 'generateBackupCodes':
				try {
					const vault = require('./vault');
					result = vault.generateBackupCodes(message.data);
				} catch (error) {
					console.error('[VaultWorker] Error in generateBackupCodes:', error);
					throw error;
				}
				break;

			case 'verifyBackupCode':
				try {
					const vault = require('./vault');
					result = vault.verifyBackupCode(message.data);
				} catch (error) {
					console.error('[VaultWorker] Error in verifyBackupCode:', error);
					throw error;
				}
				break;

			case 'getBackupCodesStatus':
				try {
					const vault = require('./vault');
					result = vault.getBackupCodesStatus();
				} catch (error) {
					console.error('[VaultWorker] Error in getBackupCodesStatus:', error);
					throw error;
				}
				break;

			case 'setupEmailSMSRecovery':
				try {
					const vault = require('./vault');
					result = vault.setupEmailSMSRecovery(message.data.email, message.data.phone, message.data.masterPassword);
				} catch (error) {
					console.error('[VaultWorker] Error in setupEmailSMSRecovery:', error);
					throw error;
				}
				break;

			case 'generateRecoveryCode':
				try {
					const vault = require('./vault');
					result = vault.generateRecoveryCode(message.data.email, message.data.phone);
				} catch (error) {
					console.error('[VaultWorker] Error in generateRecoveryCode:', error);
					throw error;
				}
				break;

			case 'verifyRecoveryCode':
				try {
					const vault = require('./vault');
					result = vault.verifyRecoveryCode(message.data.code);
				} catch (error) {
					console.error('[VaultWorker] Error in verifyRecoveryCode:', error);
					throw error;
				}
				break;

			case 'resetMasterPasswordViaRecovery':
				try {
					const vault = require('./vault');
					result = vault.resetMasterPasswordViaRecovery(
						message.data.newPassword,
						message.data.recoveryMethod,
						message.data.recoveryData
					);
				} catch (error) {
					console.error('[VaultWorker] Error in resetMasterPasswordViaRecovery:', error);
					throw error;
				}
				break;

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
		console.error('[VaultWorker] Error processing message:', error);

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
	console.log('[VaultWorker] Worker thread shutting down');
	secureMemoryCleanup();
});

// Handle SIGTERM for graceful shutdown
process.on('SIGTERM', () => {
	console.log('[VaultWorker] Received SIGTERM, shutting down gracefully');
	secureMemoryCleanup();
	process.exit(0);
});

// Periodic memory cleanup
setInterval(() => {
	secureMemoryCleanup();
}, 300000); // Every 5 minutes
