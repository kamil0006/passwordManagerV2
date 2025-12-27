export type Entry = {
	id: number;
	name: string;
	username?: string;
	password: string;
	category: string;
	created_at?: string;
};

export type EntryHistory = {
	id: number;
	entry_id: number;
	name: string;
	username?: string;
	password: string;
	category: string;
	change_type: string;
	created_at: string;
};

export type Category = {
	id: string;
	name: string;
	color: string;
	icon: string;
};

export type SecurityInfo = {
	totalEntries: number;
	encryption: string;
	keyDerivation: string;
	iterations: number;
	saltLength: number;
	ivLength: number;
	securityLevel: string;
	failedAttempts: number;
	isLocked: boolean;
	lockTimeRemaining: number;
	encryptionVersion: string;
	databaseEncrypted: boolean;
};

declare global {
	interface Window {
		vault: {
			addEntry: (entry: {
				name: string;
				username: string;
				password: string;
				category: string;
				masterPassword: string;
			}) => Promise<void>;
			getEntries: (masterPassword: string) => Promise<Entry[]>;
			getEntryPassword: (entryId: number, masterPassword: string) => Promise<string>;
			updateEntry: (entry: {
				id: number;
				name: string;
				username: string;
				password: string;
				category: string;
				masterPassword: string;
			}) => Promise<boolean>;
			deleteEntry: (id: number) => Promise<boolean>;
			getEntryHistory: (entryId: number, masterPassword: string) => Promise<EntryHistory[]>;
			rollbackEntry: (entryId: number, historyId: number, masterPassword: string) => Promise<boolean>;
			changeMasterPassword: (data: { oldPassword: string; newPassword: string }) => Promise<
				| boolean
				| {
						success: boolean;
						reEncrypted: number;
						skipped: number;
						skippedEntries?: Array<{ id: number; name: string; reason?: string }>;
				  }
			>;
			setPasswordHint: (hint: string, masterPassword: string) => Promise<boolean>;
			getPasswordHint: (masterPassword: string) => Promise<{ hint: string | null; error?: string } | null>;
			setRecoveryQuestions: (questions: Array<{ question: string; answer: string }>, masterPassword: string) => Promise<boolean>;
			verifyRecoveryQuestions: (answers: string[]) => Promise<{ verified: boolean; error?: string }>;
			getRecoveryQuestions: () => Promise<Array<{ number: number; question: string }>>;
		generateBackupCodes: (masterPassword: string) => Promise<string[]>;
		verifyBackupCode: (code: string) => Promise<{ verified: boolean; error?: string }>;
		getBackupCodesStatus: () => Promise<{ total: number; unused: number; used: number }>;
		setupEmailSMSRecovery: (email: string, phone: string, masterPassword: string) => Promise<boolean>;
		generateRecoveryCode: (email: string, phone: string) => Promise<{ success: boolean; code?: string }>;
		verifyRecoveryCode: (code: string) => Promise<{ verified: boolean; error?: string }>;
		resetMasterPasswordViaRecovery: (newPassword: string, recoveryMethod: 'questions' | 'backup_code' | 'email_sms', recoveryData: any) => Promise<{ success: boolean; message?: string; warning?: string }>;
			diagnoseEntry: (entryId: number, masterPassword: string) => Promise<any>;
			testMasterPassword: (password: string) => Promise<boolean>;
			getSecurityInfo: () => Promise<SecurityInfo>;
			reportActivity: () => void;
			onAutoLock: (callback: () => void) => void;
		};
	}
}
