const { contextBridge, ipcRenderer } = require('electron');

// Expose vault API
contextBridge.exposeInMainWorld('vault', {
	addEntry: entry => ipcRenderer.invoke('vault:addEntry', entry),
	getEntries: masterPassword => ipcRenderer.invoke('vault:getEntries', masterPassword),
	updateEntry: entry => ipcRenderer.invoke('vault:updateEntry', entry),
	deleteEntry: id => ipcRenderer.invoke('vault:deleteEntry', id),
	getEntryHistory: (entryId, masterPassword) => ipcRenderer.invoke('vault:getEntryHistory', { entryId, masterPassword }),
	rollbackEntry: (entryId, historyId, masterPassword) => ipcRenderer.invoke('vault:rollbackEntry', { entryId, historyId, masterPassword }),
	changeMasterPassword: data => ipcRenderer.invoke('vault:changeMasterPassword', data),
	setPasswordHint: (hint, masterPassword) => ipcRenderer.invoke('vault:setPasswordHint', { hint, masterPassword }),
	getPasswordHint: masterPassword => ipcRenderer.invoke('vault:getPasswordHint', masterPassword),
	setRecoveryQuestions: (questions, masterPassword) => ipcRenderer.invoke('vault:setRecoveryQuestions', { questions, masterPassword }),
	verifyRecoveryQuestions: answers => ipcRenderer.invoke('vault:verifyRecoveryQuestions', answers),
	getRecoveryQuestions: () => ipcRenderer.invoke('vault:getRecoveryQuestions'),
	generateBackupCodes: masterPassword => ipcRenderer.invoke('vault:generateBackupCodes', masterPassword),
	verifyBackupCode: code => ipcRenderer.invoke('vault:verifyBackupCode', code),
	getBackupCodesStatus: () => ipcRenderer.invoke('vault:getBackupCodesStatus'),
	setupEmailSMSRecovery: (email, phone, masterPassword) => ipcRenderer.invoke('vault:setupEmailSMSRecovery', { email, phone, masterPassword }),
	generateRecoveryCode: (email, phone) => ipcRenderer.invoke('vault:generateRecoveryCode', { email, phone }),
	verifyRecoveryCode: code => ipcRenderer.invoke('vault:verifyRecoveryCode', { code }),
	resetMasterPasswordViaRecovery: (newPassword, recoveryMethod, recoveryData) => ipcRenderer.invoke('vault:resetMasterPasswordViaRecovery', { newPassword, recoveryMethod, recoveryData }),
	diagnoseEntry: (entryId, masterPassword) => ipcRenderer.invoke('vault:diagnoseEntry', { entryId, masterPassword }),
	testMasterPassword: masterPassword => ipcRenderer.invoke('vault:testMasterPassword', masterPassword),
	getSecurityInfo: () => ipcRenderer.invoke('vault:getSecurityInfo'),
	reportActivity: () => ipcRenderer.send('vault:activity'),
});

// Expose security API
contextBridge.exposeInMainWorld('security', {
	getStatus: () => ipcRenderer.invoke('security:getStatus'),
});

// Expose auto-lock listener
ipcRenderer.on('vault:autoLock', () => {
	// Dispatch custom event for the frontend to handle
	window.dispatchEvent(new CustomEvent('vault:autoLock'));
});
