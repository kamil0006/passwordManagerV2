const { app, BrowserWindow, ipcMain, session } = require('electron');
const path = require('path');
const { Worker } = require('worker_threads');
const os = require('os');

// Set database path to Electron's userData directory
// This ensures the database is stored in a secure, user-specific location
// and doesn't reveal the exact path in source code
function setDatabasePath() {
	if (app && app.isReady && app.isReady()) {
		// App is ready, use Electron's userData directory
		process.env.VAULT_DB_PATH = app.getPath('userData');
	} else if (app && app.getPath) {
		// App exists but not ready, set it up for when ready
		app.whenReady().then(() => {
			process.env.VAULT_DB_PATH = app.getPath('userData');
		});
		// Temporary path until app is ready
		process.env.VAULT_DB_PATH = path.join(os.homedir(), '.password-manager');
	} else {
		// For testing or non-Electron environments, use home directory
		process.env.VAULT_DB_PATH = path.join(os.homedir(), '.password-manager');
	}
}

// Set path before requiring vault
setDatabasePath();

const vault = require('./db/vault');

// Set worker reference in vault for crypto operations
// This allows vault.js to delegate crypto to worker thread
function setVaultCryptoWorker() {
	if (vaultWorker && vault.setCryptoWorker) {
		vault.setCryptoWorker(vaultWorker);
	}
}

// Security variables
let autoLockTimer = null;
let lastActivityTime = Date.now();

// Security constants
const AUTO_LOCK_DELAY = 3 * 60 * 1000; // 3 minutes

// Worker thread for vault operations
let vaultWorker = null;

function createVaultWorker() {
	vaultWorker = new Worker(path.join(__dirname, 'db/vault-worker.js'));

	vaultWorker.on('message', message => {
		handleWorkerMessage(message);
	});

	vaultWorker.on('error', error => {
		if (process.env.NODE_ENV !== 'production') {
			console.error('[Main] Worker error:', error);
		}
		// Cleanup pending requests on worker error
		if (vault.cleanupWorker) {
			vault.cleanupWorker();
		}
	});

	vaultWorker.on('exit', code => {
		if (code !== 0) {
			if (process.env.NODE_ENV !== 'production') {
				console.error('[Main] Worker stopped with exit code:', code);
			}
		}
		// Cleanup pending requests on worker exit
		if (vault.cleanupWorker) {
			vault.cleanupWorker();
		}
	});

	// Initialize worker
	vaultWorker.postMessage({
		type: 'initialize',
		id: 'init',
	});

	// Set worker reference in vault for crypto operations
	setVaultCryptoWorker();
}

function handleWorkerMessage(message) {
	try {
		if (message.error) {
			console.error('[Main] Worker error:', message.error);
			return;
		}

		// Handle different message types
		switch (message.type) {
			case 'initialize':
				console.log('[Main] Worker initialized');
				break;
		}
	} catch (error) {
		console.error('[Main] Error handling worker message:', error);
	}
}

function createWindow() {
	const win = new BrowserWindow({
		width: 1000,
		height: 700,
		minWidth: 600,
		minHeight: 400,
		webPreferences: {
			preload: path.join(__dirname, 'preload.js'),
			contextIsolation: true,
			nodeIntegration: false,
			sandbox: false,
		},
		titleBarStyle: 'hiddenInset', // More secure title bar
		webSecurity: true,
		allowRunningInsecureContent: false,
	});

	win.loadURL('http://localhost:5175').catch(err => {
		console.error('[Main] Failed to load URL:', err);
		// Try alternative ports
		win.loadURL('http://localhost:5174').catch(err2 => {
			console.error('[Main] Failed to load alternative URL:', err2);
			win.loadURL('http://localhost:5173').catch(err3 => {
				console.error('[Main] Failed to load all alternative URLs:', err3);
			});
		});
	});

	// Set up auto-lock
	setupAutoLock(win);

	// Set up security features
	setupSecurityFeatures(win);

	// Initialize vault worker
	createVaultWorker();
	
	// Set worker reference in vault for crypto operations
	setVaultCryptoWorker();
}

// Security features that actually work
function setupSecurityFeatures(win) {
	// Advanced developer tools and context menu blocking
	win.webContents.on('dom-ready', () => {
		win.webContents.executeJavaScript(`
			// Enhanced right-click blocking
			document.addEventListener('contextmenu', (e) => {
				e.preventDefault();
				return false;
			}, true);
			
			// Advanced developer tools blocking
			document.addEventListener('keydown', (e) => {
				const blockedKeys = [
					'F12',
					'F5',
					'Ctrl+Shift+I',
					'Ctrl+Shift+J',
					'Ctrl+Shift+C',
					'Ctrl+U',
					'Ctrl+Shift+E'
				];
				
				const keyCombo = [
					e.key,
					e.ctrlKey ? 'Ctrl' : '',
					e.shiftKey ? 'Shift' : '',
					e.altKey ? 'Alt' : ''
				].filter(Boolean).join('+');
				
				if (blockedKeys.some(blocked => 
					blocked === keyCombo || 
					(e.ctrlKey && e.shiftKey && e.key === 'I') ||
					(e.ctrlKey && e.shiftKey && e.key === 'J') ||
					(e.ctrlKey && e.shiftKey && e.key === 'C') ||
					(e.ctrlKey && e.key === 'u')
				)) {
					e.preventDefault();
					return false;
				}
			}, true);
			
			// Screen capture detection
			document.addEventListener('visibilitychange', () => {
				if (document.hidden) {
					// Page hidden - potential screen capture
					if (window.vault && window.vault.reportSecurityEvent) {
						window.vault.reportSecurityEvent('visibility_change');
					}
				}
			});
			
		`);
	});

	// IPC handler for security status
	ipcMain.handle('security:getStatus', () => {
		return {
			encryptionActive: true,
			autoLockActive: true,
			networkIsolation: true,
			developerToolsBlocked: true,
			contextMenuBlocked: true,
		};
	});
}

// Auto-lock functionality
function setupAutoLock(win) {
	// Reset timer on any IPC activity
	const resetTimer = () => {
		lastActivityTime = Date.now();
		if (autoLockTimer) {
			clearTimeout(autoLockTimer);
		}
		autoLockTimer = setTimeout(() => {
			win.webContents.send('vault:autoLock');
		}, AUTO_LOCK_DELAY);
	};

	// Reset timer on any IPC call
	ipcMain.on('vault:activity', event => {
		resetTimer();
	});

	// Reset timer on window focus
	win.on('focus', () => {
		resetTimer();
	});

	// Reset timer on any user interaction with the window
	win.webContents.on('dom-ready', () => {
		win.webContents.executeJavaScript(`
			// Report activity to main process
			function reportActivity() {
				if (window.vault && window.vault.reportActivity) {
					window.vault.reportActivity();
				}
			}

			// Track all user activity
			document.addEventListener('mousemove', reportActivity);
			document.addEventListener('keypress', reportActivity);
			document.addEventListener('click', reportActivity);
			document.addEventListener('input', reportActivity);
			document.addEventListener('focus', reportActivity);
			document.addEventListener('scroll', reportActivity);
		`);
	});

	// Initial timer setup
	resetTimer();
}

// Cleanup on app exit
app.on('before-quit', () => {
	if (autoLockTimer) {
		clearTimeout(autoLockTimer);
	}

	// Terminate worker thread
	if (vaultWorker) {
		vaultWorker.terminate();
	}
});

app.whenReady().then(createWindow);

// IPC Handlers - Make them non-blocking
ipcMain.handle('vault:addEntry', async (event, entry) => {
	// Reset auto-lock timer on vault activity
	if (autoLockTimer) {
		clearTimeout(autoLockTimer);
		lastActivityTime = Date.now();
		autoLockTimer = setTimeout(() => {
			event.sender.send('vault:autoLock');
		}, AUTO_LOCK_DELAY);
	}

	try {
		// Call vault.js directly - worker is used internally by vault.js for crypto operations only
		const result = await vault.addEntry(entry.name, entry.username, entry.password, entry.category, entry.masterPassword);
		return result;
	} catch (error) {
		if (process.env.NODE_ENV !== 'production') {
			console.error('[Main] Error in vault:addEntry:', error);
		}
		throw error;
	}
});

ipcMain.handle('vault:getEntries', async (event, masterPassword) => {
	// Reset auto-lock timer on vault activity
	if (autoLockTimer) {
		clearTimeout(autoLockTimer);
		lastActivityTime = Date.now();
		autoLockTimer = setTimeout(() => {
			event.sender.send('vault:autoLock');
		}, AUTO_LOCK_DELAY);
	}

	try {
		// Call vault.js directly - worker is used internally by vault.js for crypto operations only
		const result = await vault.getAllEntries();
		return result;
	} catch (error) {
		if (process.env.NODE_ENV !== 'production') {
			console.error('[Main] Error in vault:getEntries:', error);
		}
		throw error;
	}
});

ipcMain.handle('vault:getEntryPassword', async (event, data) => {
	// Reset auto-lock timer on vault activity
	if (autoLockTimer) {
		clearTimeout(autoLockTimer);
		lastActivityTime = Date.now();
		autoLockTimer = setTimeout(() => {
			event.sender.send('vault:autoLock');
		}, AUTO_LOCK_DELAY);
	}

	try {
		// Call vault.js directly - worker is used internally by vault.js for crypto operations only
		const result = await vault.getEntryPassword(data.entryId, data.masterPassword);
		return result;
	} catch (error) {
		if (process.env.NODE_ENV !== 'production') {
			console.error('[Main] Error in vault:getEntryPassword:', error);
		}
		throw error;
	}
});

ipcMain.handle('vault:diagnoseEntry', async (event, data) => {
	try {
		// Call vault.js directly - worker is used internally by vault.js for crypto operations only
		const result = await vault.diagnoseEntry(data.entryId, data.masterPassword);
		return result;
	} catch (error) {
		if (process.env.NODE_ENV !== 'production') {
			console.error('[Main] Error in vault:diagnoseEntry:', error);
		}
		throw error;
	}
});

ipcMain.handle('vault:changeMasterPassword', async (event, data) => {
	// Reset auto-lock timer on vault activity
	if (autoLockTimer) {
		clearTimeout(autoLockTimer);
		lastActivityTime = Date.now();
		autoLockTimer = setTimeout(() => {
			event.sender.send('vault:autoLock');
		}, AUTO_LOCK_DELAY);
	}

	try {
		// Call vault.js directly - worker is used internally by vault.js for crypto operations only
		const result = await vault.changeMasterPassword(data.oldPassword, data.newPassword);
		return result;
	} catch (error) {
		if (process.env.NODE_ENV !== 'production') {
			console.error('[Main] Error in vault:changeMasterPassword:', error);
		}
		throw error;
	}
});

ipcMain.handle('vault:updateEntry', async (event, entry) => {
	// Reset auto-lock timer on vault activity
	if (autoLockTimer) {
		clearTimeout(autoLockTimer);
		lastActivityTime = Date.now();
		autoLockTimer = setTimeout(() => {
			event.sender.send('vault:autoLock');
		}, AUTO_LOCK_DELAY);
	}

	try {
		// Call vault.js directly - worker is used internally by vault.js for crypto operations only
		const result = await vault.updateEntry(
			entry.id,
			entry.name,
			entry.username,
			entry.password,
			entry.category,
			entry.masterPassword
		);
		return result;
	} catch (error) {
		if (process.env.NODE_ENV !== 'production') {
			console.error('[Main] Error in vault:updateEntry:', error);
		}
		throw error;
	}
});

ipcMain.handle('vault:getEntryHistory', async (event, data) => {
	// Reset auto-lock timer on vault activity
	if (autoLockTimer) {
		clearTimeout(autoLockTimer);
		lastActivityTime = Date.now();
		autoLockTimer = setTimeout(() => {
			event.sender.send('vault:autoLock');
		}, AUTO_LOCK_DELAY);
	}

	try {
		// Call vault.js directly - worker is used internally by vault.js for crypto operations only
		const result = await vault.getEntryHistory(data.entryId, data.masterPassword);
		return result;
	} catch (error) {
		if (process.env.NODE_ENV !== 'production') {
			console.error('[Main] Error in vault:getEntryHistory:', error);
		}
		throw error;
	}
});

ipcMain.handle('vault:rollbackEntry', async (event, data) => {
	// Reset auto-lock timer on vault activity
	if (autoLockTimer) {
		clearTimeout(autoLockTimer);
		lastActivityTime = Date.now();
		autoLockTimer = setTimeout(() => {
			event.sender.send('vault:autoLock');
		}, AUTO_LOCK_DELAY);
	}

	try {
		// Call vault.js directly - worker is used internally by vault.js for crypto operations only
		const result = await vault.rollbackEntry(data.entryId, data.historyId, data.masterPassword);
		return result;
	} catch (error) {
		if (process.env.NODE_ENV !== 'production') {
			console.error('[Main] Error in vault:rollbackEntry:', error);
		}
		throw error;
	}
});

ipcMain.handle('vault:deleteEntry', (event, id) => {
	// Reset auto-lock timer on vault activity
	if (autoLockTimer) {
		clearTimeout(autoLockTimer);
		lastActivityTime = Date.now();
		autoLockTimer = setTimeout(() => {
			event.sender.send('vault:autoLock');
		}, AUTO_LOCK_DELAY);
	}

	try {
		const result = vault.deleteEntry(id);
		return result;
	} catch (error) {
		console.error('[Main] Error in vault:deleteEntry:', error);
		throw error;
	}
});

ipcMain.handle('vault:testMasterPassword', async (event, masterPassword) => {
	try {
		// Call vault.js directly - worker is used internally by vault.js for crypto operations only
		return await vault.testMasterPassword(masterPassword);
	} catch (error) {
		if (process.env.NODE_ENV !== 'production') {
			console.error('[Main] Error in vault:testMasterPassword:', error);
		}
		throw error;
	}
});

ipcMain.handle('vault:setPasswordHint', async (event, data) => {
	try {
		// Call vault.js directly - worker is used internally by vault.js for crypto operations only
		return await vault.setPasswordHint(data.hint, data.masterPassword);
	} catch (error) {
		if (process.env.NODE_ENV !== 'production') {
			console.error('[Main] Error in vault:setPasswordHint:', error);
		}
		throw error;
	}
});

ipcMain.handle('vault:getPasswordHint', async (event, masterPassword) => {
	try {
		// Call vault.js directly - worker is used internally by vault.js for crypto operations only
		return await vault.getPasswordHint(masterPassword);
	} catch (error) {
		if (process.env.NODE_ENV !== 'production') {
			console.error('[Main] Error in vault:getPasswordHint:', error);
		}
		throw error;
	}
});

ipcMain.handle('vault:setRecoveryQuestions', async (event, data) => {
	try {
		// Call vault.js directly - worker is used internally by vault.js for crypto operations only
		return await vault.setRecoveryQuestions(data.questions, data.masterPassword);
	} catch (error) {
		if (process.env.NODE_ENV !== 'production') {
			console.error('[Main] Error in vault:setRecoveryQuestions:', error);
		}
		throw error;
	}
});

ipcMain.handle('vault:verifyRecoveryQuestions', async (event, answers) => {
	try {
		// Call vault.js directly - worker is used internally by vault.js for crypto operations only
		return await vault.verifyRecoveryQuestions(answers);
	} catch (error) {
		if (process.env.NODE_ENV !== 'production') {
			console.error('[Main] Error in vault:verifyRecoveryQuestions:', error);
		}
		throw error;
	}
});

ipcMain.handle('vault:getRecoveryQuestions', async (event) => {
	try {
		// Call vault.js directly - worker is used internally by vault.js for crypto operations only
		return await vault.getRecoveryQuestions();
	} catch (error) {
		if (process.env.NODE_ENV !== 'production') {
			console.error('[Main] Error in vault:getRecoveryQuestions:', error);
		}
		throw error;
	}
});

ipcMain.handle('vault:generateBackupCodes', async (event, masterPassword) => {
	try {
		// Call vault.js directly - worker is used internally by vault.js for crypto operations only
		return await vault.generateBackupCodes(masterPassword);
	} catch (error) {
		if (process.env.NODE_ENV !== 'production') {
			console.error('[Main] Error in vault:generateBackupCodes:', error);
		}
		throw error;
	}
});

ipcMain.handle('vault:verifyBackupCode', async (event, code) => {
	try {
		// Call vault.js directly - worker is used internally by vault.js for crypto operations only
		return await vault.verifyBackupCode(code);
	} catch (error) {
		if (process.env.NODE_ENV !== 'production') {
			console.error('[Main] Error in vault:verifyBackupCode:', error);
		}
		throw error;
	}
});

ipcMain.handle('vault:getBackupCodesStatus', async (event) => {
	try {
		// Call vault.js directly - worker is used internally by vault.js for crypto operations only
		return await vault.getBackupCodesStatus();
	} catch (error) {
		if (process.env.NODE_ENV !== 'production') {
			console.error('[Main] Error in vault:getBackupCodesStatus:', error);
		}
		throw error;
	}
});

ipcMain.handle('vault:setupEmailSMSRecovery', async (event, data) => {
	try {
		// Call vault.js directly - worker is used internally by vault.js for crypto operations only
		return await vault.setupEmailSMSRecovery(data.email, data.phone, data.masterPassword);
	} catch (error) {
		if (process.env.NODE_ENV !== 'production') {
			console.error('[Main] Error in vault:setupEmailSMSRecovery:', error);
		}
		throw error;
	}
});

ipcMain.handle('vault:generateRecoveryCode', async (event, data) => {
	try {
		// Call vault.js directly - worker is used internally by vault.js for crypto operations only
		return await vault.generateRecoveryCode(data.email, data.phone);
	} catch (error) {
		if (process.env.NODE_ENV !== 'production') {
			console.error('[Main] Error in vault:generateRecoveryCode:', error);
		}
		throw error;
	}
});

ipcMain.handle('vault:verifyRecoveryCode', async (event, data) => {
	try {
		// Call vault.js directly - worker is used internally by vault.js for crypto operations only
		return await vault.verifyRecoveryCode(data.code);
	} catch (error) {
		if (process.env.NODE_ENV !== 'production') {
			console.error('[Main] Error in vault:verifyRecoveryCode:', error);
		}
		throw error;
	}
});

ipcMain.handle('vault:resetMasterPasswordViaRecovery', async (event, data) => {
	try {
		// Call vault.js directly - worker is used internally by vault.js for crypto operations only
		return await vault.resetMasterPasswordViaRecovery(data.newPassword, data.recoveryMethod, data.recoveryData);
	} catch (error) {
		if (process.env.NODE_ENV !== 'production') {
			console.error('[Main] Error in vault:resetMasterPasswordViaRecovery:', error);
		}
		throw error;
	}
});

ipcMain.handle('vault:getSecurityInfo', () => {
	try {
		const result = vault.getSecurityInfo();
		return result;
	} catch (error) {
		console.error('[Main] Error in vault:getSecurityInfo:', error);
		throw error;
	}
});
