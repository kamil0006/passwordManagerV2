const { contextBridge, ipcRenderer } = require('electron');

// Expose vault API
contextBridge.exposeInMainWorld('vault', {
	addEntry: entry => ipcRenderer.invoke('vault:addEntry', entry),
	getEntries: masterPassword => ipcRenderer.invoke('vault:getEntries', masterPassword),
	getEntryPassword: (entryId, masterPassword) =>
		ipcRenderer.invoke('vault:getEntryPassword', { entryId, masterPassword }),
	updateEntry: entry => ipcRenderer.invoke('vault:updateEntry', entry),
	deleteEntry: id => ipcRenderer.invoke('vault:deleteEntry', id),
	getEntryHistory: (entryId, masterPassword) =>
		ipcRenderer.invoke('vault:getEntryHistory', { entryId, masterPassword }),
	rollbackEntry: (entryId, historyId, masterPassword) =>
		ipcRenderer.invoke('vault:rollbackEntry', { entryId, historyId, masterPassword }),
	changeMasterPassword: data => ipcRenderer.invoke('vault:changeMasterPassword', data),
	hasAppAccount: () => ipcRenderer.invoke('vault:hasAppAccount'),
	createAppAccount: (username, password) => ipcRenderer.invoke('vault:createAppAccount', { username, password }),
	verifyAppLogin: (username, password) => ipcRenderer.invoke('vault:verifyAppLogin', { username, password }),
	isMasterPasswordSet: () => ipcRenderer.invoke('vault:isMasterPasswordSet'),
	setupEmailSMSRecovery: (email, phone, masterPassword) =>
		ipcRenderer.invoke('vault:setupEmailSMSRecovery', { email, phone, masterPassword }),
	generateRecoveryCode: (email, phone) => ipcRenderer.invoke('vault:generateRecoveryCode', { email, phone }),
	verifyRecoveryCode: code => ipcRenderer.invoke('vault:verifyRecoveryCode', { code }),
	resetMasterPasswordViaRecovery: (newPassword, recoveryMethod, recoveryData) =>
		ipcRenderer.invoke('vault:resetMasterPasswordViaRecovery', { newPassword, recoveryMethod, recoveryData }),
	diagnoseEntry: (entryId, masterPassword) => ipcRenderer.invoke('vault:diagnoseEntry', { entryId, masterPassword }),
	testMasterPassword: masterPassword => ipcRenderer.invoke('vault:testMasterPassword', masterPassword),
	getSecurityInfo: () => ipcRenderer.invoke('vault:getSecurityInfo'),
	reportActivity: () => ipcRenderer.send('vault:activity'),
	exportBackup: () => ipcRenderer.invoke('vault:exportBackup'),
	restoreBackup: () => ipcRenderer.invoke('vault:restoreBackup'),
});

// Expose app utilities
contextBridge.exposeInMainWorld('app', {
	openExternal: url => ipcRenderer.invoke('app:openExternal', url),
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
