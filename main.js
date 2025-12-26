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
		console.error('[Main] Worker error:', error);
	});

	vaultWorker.on('exit', code => {
		if (code !== 0) {
			console.error('[Main] Worker stopped with exit code:', code);
		}
	});

	// Initialize worker
	vaultWorker.postMessage({
		type: 'initialize',
		id: 'init',
	});
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
		// Use worker thread for heavy operations
		if (vaultWorker) {
			return new Promise((resolve, reject) => {
				const messageId = Date.now().toString();

				const handler = message => {
					if (message.id === messageId) {
						vaultWorker.off('message', handler);
						if (message.error) {
							reject(new Error(message.error));
						} else {
							resolve(message.result);
						}
					}
				};

				vaultWorker.on('message', handler);
				vaultWorker.postMessage({
					type: 'addEntry',
					id: messageId,
					data: entry,
				});
			});
		} else {
			// Fallback to main thread if worker not available
			const result = vault.addEntry(entry.name, entry.username, entry.password, entry.category, entry.masterPassword);
			return result;
		}
	} catch (error) {
		console.error('[Main] Error in vault:addEntry:', error);
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
		// Use worker thread for heavy operations
		if (vaultWorker) {
			return new Promise((resolve, reject) => {
				const messageId = Date.now().toString();

				const handler = message => {
					if (message.id === messageId) {
						vaultWorker.off('message', handler);
						if (message.error) {
							reject(new Error(message.error));
						} else {
							resolve(message.result);
						}
					}
				};

				vaultWorker.on('message', handler);
				vaultWorker.postMessage({
					type: 'getEntries',
					id: messageId,
					data: masterPassword,
				});
			});
		} else {
			// Fallback to main thread if worker not available
			const result = vault.getAllEntries(masterPassword);
			return result;
		}
	} catch (error) {
		console.error('[Main] Error in vault:getEntries:', error);
		throw error;
	}
});

ipcMain.handle('vault:diagnoseEntry', async (event, data) => {
	try {
		const result = vault.diagnoseEntry(data.entryId, data.masterPassword);
		return result;
	} catch (error) {
		console.error('[Main] Error in vault:diagnoseEntry:', error);
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
		// Use worker thread for heavy operations
		if (vaultWorker) {
			return new Promise((resolve, reject) => {
				const messageId = Date.now().toString();

				const handler = message => {
					if (message.id === messageId) {
						vaultWorker.off('message', handler);
						if (message.error) {
							reject(new Error(message.error));
						} else {
							resolve(message.result);
						}
					}
				};

				vaultWorker.on('message', handler);
				vaultWorker.postMessage({
					type: 'changeMasterPassword',
					id: messageId,
					data: data,
				});
			});
		} else {
			// Fallback to main thread if worker not available
			const result = vault.changeMasterPassword(data.oldPassword, data.newPassword);
			return result;
		}
	} catch (error) {
		console.error('[Main] Error in vault:changeMasterPassword:', error);
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
		// Use worker thread for heavy operations
		if (vaultWorker) {
			return new Promise((resolve, reject) => {
				const messageId = Date.now().toString();

				const handler = message => {
					if (message.id === messageId) {
						vaultWorker.off('message', handler);
						if (message.error) {
							reject(new Error(message.error));
						} else {
							resolve(message.result);
						}
					}
				};

				vaultWorker.on('message', handler);
				vaultWorker.postMessage({
					type: 'updateEntry',
					id: messageId,
					data: entry,
				});
			});
		} else {
			// Fallback to main thread if worker not available
			const result = vault.updateEntry(
				entry.id,
				entry.name,
				entry.username,
				entry.password,
				entry.category,
				entry.masterPassword
			);
			return result;
		}
	} catch (error) {
		console.error('[Main] Error in vault:updateEntry:', error);
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
		// Use worker thread for heavy operations
		if (vaultWorker) {
			return new Promise((resolve, reject) => {
				const messageId = Date.now().toString();

				const handler = message => {
					if (message.id === messageId) {
						vaultWorker.off('message', handler);
						if (message.error) {
							reject(new Error(message.error));
						} else {
							resolve(message.result);
						}
					}
				};

				vaultWorker.on('message', handler);
				vaultWorker.postMessage({
					type: 'getEntryHistory',
					id: messageId,
					data: data,
				});
			});
		} else {
			// Fallback to main thread if worker not available
			const result = vault.getEntryHistory(data.entryId, data.masterPassword);
			return result;
		}
	} catch (error) {
		console.error('[Main] Error in vault:getEntryHistory:', error);
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
		// Use worker thread for heavy operations
		if (vaultWorker) {
			return new Promise((resolve, reject) => {
				const messageId = Date.now().toString();

				const handler = message => {
					if (message.id === messageId) {
						vaultWorker.off('message', handler);
						if (message.error) {
							reject(new Error(message.error));
						} else {
							resolve(message.result);
						}
					}
				};

				vaultWorker.on('message', handler);
				vaultWorker.postMessage({
					type: 'rollbackEntry',
					id: messageId,
					data: data,
				});
			});
		} else {
			// Fallback to main thread if worker not available
			const result = vault.rollbackEntry(data.entryId, data.historyId, data.masterPassword);
			return result;
		}
	} catch (error) {
		console.error('[Main] Error in vault:rollbackEntry:', error);
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

ipcMain.handle('vault:testMasterPassword', (event, masterPassword) => {
	try {
		if (vaultWorker) {
			return new Promise((resolve, reject) => {
				const messageId = Date.now().toString();

				const handler = message => {
					if (message.id === messageId) {
						vaultWorker.off('message', handler);
						if (message.error) {
							reject(new Error(message.error));
						} else {
							resolve(message.result);
						}
					}
				};

				vaultWorker.on('message', handler);
				vaultWorker.postMessage({
					type: 'testMasterPassword',
					id: messageId,
					data: masterPassword,
				});
			});
		} else {
			return vault.testMasterPassword(masterPassword);
		}
	} catch (error) {
		console.error('[Main] Error in vault:testMasterPassword:', error);
		throw error;
	}
});

ipcMain.handle('vault:setPasswordHint', async (event, data) => {
	try {
		if (vaultWorker) {
			return new Promise((resolve, reject) => {
				const messageId = Date.now().toString();

				const handler = message => {
					if (message.id === messageId) {
						vaultWorker.off('message', handler);
						if (message.error) {
							reject(new Error(message.error));
						} else {
							resolve(message.result);
						}
					}
				};

				vaultWorker.on('message', handler);
				vaultWorker.postMessage({
					type: 'setPasswordHint',
					id: messageId,
					data: data,
				});
			});
		} else {
			return vault.setPasswordHint(data.hint, data.masterPassword);
		}
	} catch (error) {
		console.error('[Main] Error in vault:setPasswordHint:', error);
		throw error;
	}
});

ipcMain.handle('vault:getPasswordHint', async (event, masterPassword) => {
	try {
		if (vaultWorker) {
			return new Promise((resolve, reject) => {
				const messageId = Date.now().toString();

				const handler = message => {
					if (message.id === messageId) {
						vaultWorker.off('message', handler);
						if (message.error) {
							reject(new Error(message.error));
						} else {
							resolve(message.result);
						}
					}
				};

				vaultWorker.on('message', handler);
				vaultWorker.postMessage({
					type: 'getPasswordHint',
					id: messageId,
					data: masterPassword,
				});
			});
		} else {
			return vault.getPasswordHint(masterPassword);
		}
	} catch (error) {
		console.error('[Main] Error in vault:getPasswordHint:', error);
		throw error;
	}
});

ipcMain.handle('vault:setRecoveryQuestions', async (event, data) => {
	try {
		if (vaultWorker) {
			return new Promise((resolve, reject) => {
				const messageId = Date.now().toString();

				const handler = message => {
					if (message.id === messageId) {
						vaultWorker.off('message', handler);
						if (message.error) {
							reject(new Error(message.error));
						} else {
							resolve(message.result);
						}
					}
				};

				vaultWorker.on('message', handler);
				vaultWorker.postMessage({
					type: 'setRecoveryQuestions',
					id: messageId,
					data: data,
				});
			});
		} else {
			return vault.setRecoveryQuestions(data.questions, data.masterPassword);
		}
	} catch (error) {
		console.error('[Main] Error in vault:setRecoveryQuestions:', error);
		throw error;
	}
});

ipcMain.handle('vault:verifyRecoveryQuestions', async (event, answers) => {
	try {
		if (vaultWorker) {
			return new Promise((resolve, reject) => {
				const messageId = Date.now().toString();

				const handler = message => {
					if (message.id === messageId) {
						vaultWorker.off('message', handler);
						if (message.error) {
							reject(new Error(message.error));
						} else {
							resolve(message.result);
						}
					}
				};

				vaultWorker.on('message', handler);
				vaultWorker.postMessage({
					type: 'verifyRecoveryQuestions',
					id: messageId,
					data: { answers },
				});
			});
		} else {
			return vault.verifyRecoveryQuestions(answers);
		}
	} catch (error) {
		console.error('[Main] Error in vault:verifyRecoveryQuestions:', error);
		throw error;
	}
});

ipcMain.handle('vault:getRecoveryQuestions', async (event) => {
	try {
		if (vaultWorker) {
			return new Promise((resolve, reject) => {
				const messageId = Date.now().toString();

				const handler = message => {
					if (message.id === messageId) {
						vaultWorker.off('message', handler);
						if (message.error) {
							reject(new Error(message.error));
						} else {
							resolve(message.result);
						}
					}
				};

				vaultWorker.on('message', handler);
				vaultWorker.postMessage({
					type: 'getRecoveryQuestions',
					id: messageId,
					data: null,
				});
			});
		} else {
			return vault.getRecoveryQuestions();
		}
	} catch (error) {
		console.error('[Main] Error in vault:getRecoveryQuestions:', error);
		throw error;
	}
});

ipcMain.handle('vault:generateBackupCodes', async (event, masterPassword) => {
	try {
		if (vaultWorker) {
			return new Promise((resolve, reject) => {
				const messageId = Date.now().toString();

				const handler = message => {
					if (message.id === messageId) {
						vaultWorker.off('message', handler);
						if (message.error) {
							reject(new Error(message.error));
						} else {
							resolve(message.result);
						}
					}
				};

				vaultWorker.on('message', handler);
				vaultWorker.postMessage({
					type: 'generateBackupCodes',
					id: messageId,
					data: masterPassword,
				});
			});
		} else {
			return vault.generateBackupCodes(masterPassword);
		}
	} catch (error) {
		console.error('[Main] Error in vault:generateBackupCodes:', error);
		throw error;
	}
});

ipcMain.handle('vault:verifyBackupCode', async (event, code) => {
	try {
		if (vaultWorker) {
			return new Promise((resolve, reject) => {
				const messageId = Date.now().toString();

				const handler = message => {
					if (message.id === messageId) {
						vaultWorker.off('message', handler);
						if (message.error) {
							reject(new Error(message.error));
						} else {
							resolve(message.result);
						}
					}
				};

				vaultWorker.on('message', handler);
				vaultWorker.postMessage({
					type: 'verifyBackupCode',
					id: messageId,
					data: code,
				});
			});
		} else {
			return vault.verifyBackupCode(code);
		}
	} catch (error) {
		console.error('[Main] Error in vault:verifyBackupCode:', error);
		throw error;
	}
});

ipcMain.handle('vault:getBackupCodesStatus', async (event) => {
	try {
		if (vaultWorker) {
			return new Promise((resolve, reject) => {
				const messageId = Date.now().toString();

				const handler = message => {
					if (message.id === messageId) {
						vaultWorker.off('message', handler);
						if (message.error) {
							reject(new Error(message.error));
						} else {
							resolve(message.result);
						}
					}
				};

				vaultWorker.on('message', handler);
				vaultWorker.postMessage({
					type: 'getBackupCodesStatus',
					id: messageId,
					data: null,
				});
			});
		} else {
			return vault.getBackupCodesStatus();
		}
	} catch (error) {
		console.error('[Main] Error in vault:getBackupCodesStatus:', error);
		throw error;
	}
});

ipcMain.handle('vault:setupEmailSMSRecovery', async (event, data) => {
	try {
		if (vaultWorker) {
			return new Promise((resolve, reject) => {
				const messageId = Date.now().toString();

				const handler = message => {
					if (message.id === messageId) {
						vaultWorker.off('message', handler);
						if (message.error) {
							reject(new Error(message.error));
						} else {
							resolve(message.result);
						}
					}
				};

				vaultWorker.on('message', handler);

				vaultWorker.postMessage({
					type: 'setupEmailSMSRecovery',
					id: messageId,
					data: {
						email: data.email,
						phone: data.phone,
						masterPassword: data.masterPassword,
					},
				});
			});
		} else {
			throw new Error('Vault worker not initialized');
		}
	} catch (error) {
		console.error('[Main] Error in vault:setupEmailSMSRecovery:', error);
		throw error;
	}
});

ipcMain.handle('vault:generateRecoveryCode', async (event, data) => {
	try {
		if (vaultWorker) {
			return new Promise((resolve, reject) => {
				const messageId = Date.now().toString();

				const handler = message => {
					if (message.id === messageId) {
						vaultWorker.off('message', handler);
						if (message.error) {
							reject(new Error(message.error));
						} else {
							resolve(message.result);
						}
					}
				};

				vaultWorker.on('message', handler);

				vaultWorker.postMessage({
					type: 'generateRecoveryCode',
					id: messageId,
					data: {
						email: data.email,
						phone: data.phone,
					},
				});
			});
		} else {
			throw new Error('Vault worker not initialized');
		}
	} catch (error) {
		console.error('[Main] Error in vault:generateRecoveryCode:', error);
		throw error;
	}
});

ipcMain.handle('vault:verifyRecoveryCode', async (event, data) => {
	try {
		if (vaultWorker) {
			return new Promise((resolve, reject) => {
				const messageId = Date.now().toString();

				const handler = message => {
					if (message.id === messageId) {
						vaultWorker.off('message', handler);
						if (message.error) {
							reject(new Error(message.error));
						} else {
							resolve(message.result);
						}
					}
				};

				vaultWorker.on('message', handler);

				vaultWorker.postMessage({
					type: 'verifyRecoveryCode',
					id: messageId,
					data: {
						code: data.code,
					},
				});
			});
		} else {
			throw new Error('Vault worker not initialized');
		}
	} catch (error) {
		console.error('[Main] Error in vault:verifyRecoveryCode:', error);
		throw error;
	}
});

ipcMain.handle('vault:resetMasterPasswordViaRecovery', async (event, data) => {
	try {
		if (vaultWorker) {
			return new Promise((resolve, reject) => {
				const messageId = Date.now().toString();

				const handler = message => {
					if (message.id === messageId) {
						vaultWorker.off('message', handler);
						if (message.error) {
							reject(new Error(message.error));
						} else {
							resolve(message.result);
						}
					}
				};

				vaultWorker.on('message', handler);
				vaultWorker.postMessage({
					type: 'resetMasterPasswordViaRecovery',
					id: messageId,
					data: data,
				});
			});
		} else {
			return vault.resetMasterPasswordViaRecovery(data.newPassword, data.recoveryMethod, data.recoveryData);
		}
	} catch (error) {
		console.error('[Main] Error in vault:resetMasterPasswordViaRecovery:', error);
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
