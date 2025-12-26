import React, { useEffect, useState } from 'react';
import './VaultScreen.css';
import type { Entry, EntryHistory } from '../types/vault';
import {
	Check,
	Copy,
	Trash2,
	Briefcase,
	Home,
	Building2,
	Smartphone,
	ShoppingCart,
	Gamepad2,
	Zap,
	Key,
	Search,
	Shuffle,
	Edit2,
	Lock,
	History,
	RotateCcw,
	Menu,
	X,
	Shield,
	Sun,
	Moon,
	CheckCircle,
	AlertTriangle,
} from 'lucide-react';
import { useTheme } from '../contexts/ThemeContext';
import PasswordGeneratorModal from './PasswordGeneratorModal';
import { DEFAULT_CATEGORIES, suggestCategory } from '../config/categories';
import { analyzePasswordStrength, type PasswordStrength } from '../utils/passwordGenerator';

type Props = {
	masterPassword: string;
	onAutoLock: () => void;
};

const VaultScreen: React.FC<Props> = ({ masterPassword, onAutoLock }) => {
	const { theme, toggleTheme } = useTheme();
	const [entries, setEntries] = useState<Entry[]>([]);
	const [form, setForm] = useState({ name: '', username: '', password: '', category: 'personal' });
	const [isLoading, setIsLoading] = useState(false);
	const [isAdding, setIsAdding] = useState(false);
	const [timeUntilLock, setTimeUntilLock] = useState(180); // 3 minutes
	const [copiedItem, setCopiedItem] = useState<string | null>(null); // Track what was copied
	const [searchQuery, setSearchQuery] = useState(''); // Search functionality
	const [selectedCategory, setSelectedCategory] = useState('all'); // Category filter
	const [showCategoryModal, setShowCategoryModal] = useState(false); // Category selection modal
	const [showFilterModal, setShowFilterModal] = useState(false); // Category filter modal
	const [showDeleteModal, setShowDeleteModal] = useState(false); // Delete confirmation modal
	const [entryToDelete, setEntryToDelete] = useState<number | null>(null); // Entry ID to delete
	const [showEditModal, setShowEditModal] = useState(false); // Edit modal
	const [entryToEdit, setEntryToEdit] = useState<Entry | null>(null); // Entry being edited
	const [editForm, setEditForm] = useState({ name: '', username: '', password: '', category: 'personal' }); // Edit form state
	const [isEditing, setIsEditing] = useState(false); // Editing in progress
	const [editCategoryManuallySelected, setEditCategoryManuallySelected] = useState(false); // Track if user manually selected category in edit form
	const [editPasswordStrength, setEditPasswordStrength] = useState<PasswordStrength | null>(null); // Password strength for edit form
	const [categoryManuallySelected, setCategoryManuallySelected] = useState(false); // Track if user manually selected category
	const [showPasswordGenerator, setShowPasswordGenerator] = useState(false); // Password generator modal
	const [passwordStrength, setPasswordStrength] = useState<PasswordStrength | null>(null); // Password strength analysis
	const [showChangePasswordModal, setShowChangePasswordModal] = useState(false); // Change master password modal
	const [changePasswordForm, setChangePasswordForm] = useState({
		currentPassword: '',
		newPassword: '',
		confirmPassword: '',
		passwordHint: '',
	}); // Change password form state
	const [isChangingPassword, setIsChangingPassword] = useState(false); // Changing password in progress
	const [newPasswordStrength, setNewPasswordStrength] = useState<PasswordStrength | null>(null); // New password strength
	const [showHistoryModal, setShowHistoryModal] = useState(false); // Entry history modal
	const [entryHistory, setEntryHistory] = useState<EntryHistory[]>([]); // History for selected entry
	const [entryForHistory, setEntryForHistory] = useState<Entry | null>(null); // Entry being viewed for history
	const [isLoadingHistory, setIsLoadingHistory] = useState(false); // Loading history
	const [isRollingBack, setIsRollingBack] = useState(false); // Rolling back entry
	const [bulkMode, setBulkMode] = useState(false); // Bulk selection mode
	const [selectedEntries, setSelectedEntries] = useState<Set<number>>(new Set()); // Selected entry IDs for bulk operations
	const [showBulkDeleteModal, setShowBulkDeleteModal] = useState(false); // Bulk delete confirmation
	const [showBulkEditModal, setShowBulkEditModal] = useState(false); // Bulk edit modal
	const [isBulkDeleting, setIsBulkDeleting] = useState(false); // Bulk delete in progress
	const [isBulkEditing, setIsBulkEditing] = useState(false); // Bulk edit in progress
	const [bulkEditForm, setBulkEditForm] = useState({ category: 'personal' }); // Bulk edit form (only category for now)
	const [showRecoverySettings, setShowRecoverySettings] = useState(false); // Recovery settings modal
	const [recoveryQuestions, setRecoveryQuestions] = useState<Array<{ question: string; answer: string }>>([
		{ question: '', answer: '' },
	]); // Recovery questions form
	const [isSavingRecoveryQuestions, setIsSavingRecoveryQuestions] = useState(false); // Saving recovery questions
	const [backupCodesStatus, setBackupCodesStatus] = useState({ total: 0, unused: 0, used: 0 }); // Backup codes status
	const [generatedBackupCodes, setGeneratedBackupCodes] = useState<string[]>([]); // Generated backup codes to display
	const [isGeneratingCodes, setIsGeneratingCodes] = useState(false); // Generating backup codes
	const [_existingRecoveryQuestions, setExistingRecoveryQuestions] = useState<
		Array<{ number: number; question: string }>
	>([]); // Existing recovery questions (set in loadRecoverySettings, kept for potential future use)
	const [emailSMSRecovery, setEmailSMSRecovery] = useState({ email: '', phone: '' }); // Email/SMS recovery setup
	const [isSettingUpEmailSMS, setIsSettingUpEmailSMS] = useState(false); // Setting up email/SMS recovery
	const [showMenu, setShowMenu] = useState(false); // Burger menu open/close
	const [showSecurityInfo, setShowSecurityInfo] = useState(false); // Security info modal
	const [securityStatus, setSecurityStatus] = useState<any>(null); // Security status for modal

	// Helper function to render category icon
	const renderCategoryIcon = (iconName: string, size: number = 16) => {
		const iconProps = { size, className: 'category-icon' };
		switch (iconName) {
			case 'Briefcase':
				return <Briefcase {...iconProps} />;
			case 'Home':
				return <Home {...iconProps} />;
			case 'Building2':
				return <Building2 {...iconProps} />;
			case 'Smartphone':
				return <Smartphone {...iconProps} />;
			case 'ShoppingCart':
				return <ShoppingCart {...iconProps} />;
			case 'Gamepad2':
				return <Gamepad2 {...iconProps} />;
			case 'Zap':
				return <Zap {...iconProps} />;
			case 'Key':
				return <Key {...iconProps} />;
			default:
				return <Key {...iconProps} />;
		}
	};

	const loadEntries = async () => {
		try {
			setIsLoading(true);
			if (!window.vault) {
				console.error('[VaultScreen] window.vault is undefined!');
				alert('Vault API not available. Please restart the app.');
				return;
			}

			if (!masterPassword) {
				console.error('[VaultScreen] masterPassword is missing!');
				alert('Master password is required to load entries.');
				return;
			}

			const result = await window.vault.getEntries(masterPassword);
			console.log('[VaultScreen] Loaded', result?.length || 0, 'entries');

			if (result && Array.isArray(result)) {
				setEntries(result);

				// Show warning if no entries loaded but user is logged in
				if (result.length === 0) {
					console.warn('[VaultScreen] No entries loaded. This might indicate:');
					console.warn('[VaultScreen] 1. No entries in database');
					console.warn('[VaultScreen] 2. All entries failed to decrypt (check console for details)');
				}
			} else {
				console.error('[VaultScreen] Invalid result from getEntries:', result);
				setEntries([]);
			}
		} catch (error) {
			console.error('[VaultScreen] Error loading entries:', error);
			const errorMessage = error instanceof Error ? error.message : 'Unknown error';
			console.error('[VaultScreen] Full error:', error);
			// Don't show alert on every load - just log it
			// Only show alert if it's a critical error
			if (errorMessage.includes('required') || errorMessage.includes('undefined')) {
				alert(`Failed to load entries: ${errorMessage}\n\nPlease check the console (F12) for more details.`);
			}
			setEntries([]);
		} finally {
			setIsLoading(false);
		}
	};

	const loadSecurityInfo = async () => {
		try {
			if (!window.vault) {
				console.error('[VaultScreen] window.vault is undefined!');
				return;
			}
			await window.vault.getSecurityInfo();
		} catch (error) {
			console.error('[VaultScreen] Error loading security info:', error);
		}
	};

	useEffect(() => {
		loadEntries();
		loadSecurityInfo();
		loadRecoverySettings();

		// Load security status for menu
		const loadSecurityStatus = async () => {
			try {
				if (window.security && (window.security as any).getStatus) {
					const status = await (window.security as any).getStatus();
					setSecurityStatus(status);
				}
			} catch (error) {
				console.error('[VaultScreen] Error loading security status:', error);
			}
		};
		loadSecurityStatus();
	}, [masterPassword]);

	// Auto-lock functionality
	useEffect(() => {
		const handleAutoLock = () => {
			console.log('[VaultScreen] Auto-lock triggered');
			// Clear entries and trigger auto-lock callback
			setEntries([]);
			onAutoLock();
		};

		// Countdown timer for auto-lock
		const countdownInterval = setInterval(() => {
			setTimeUntilLock(prev => {
				if (prev <= 1) {
					// Auto-lock triggered
					handleAutoLock();
					return 180;
				}
				return prev - 1;
			});
		}, 1000);

		// Set up auto-lock listener using the custom event
		window.addEventListener('vault:autoLock', handleAutoLock);

		// Activity tracking
		const updateActivity = () => {
			if (window.vault && window.vault.reportActivity) {
				window.vault.reportActivity();
			}
			// Reset auto-lock timer on activity
			setTimeUntilLock(180);
		};

		// Track user activity (desktop app - no click tracking to avoid interference)
		document.addEventListener('mousemove', updateActivity);
		document.addEventListener('keypress', updateActivity);
		document.addEventListener('input', updateActivity);
		document.addEventListener('focus', updateActivity);

		return () => {
			clearInterval(countdownInterval);
			window.removeEventListener('vault:autoLock', handleAutoLock);
			document.removeEventListener('mousemove', updateActivity);
			document.removeEventListener('keypress', updateActivity);
			document.removeEventListener('input', updateActivity);
			document.removeEventListener('focus', updateActivity);
		};
	}, []);

	const resetForm = () => {
		setForm({ name: '', username: '', password: '', category: 'personal' });
		setCategoryManuallySelected(false);
	};

	const handleAdd = async () => {
		if (!form.name.trim() || !form.password.trim()) {
			alert('Service name and password are required!');
			return;
		}

		try {
			if (!window.vault) {
				console.error('[VaultScreen] window.vault is undefined!');
				alert('Vault API not available. Please restart the app.');
				return;
			}

			setIsAdding(true);
			await window.vault.addEntry({
				name: form.name,
				username: form.username,
				password: form.password,
				category: form.category,
				masterPassword,
			});
			resetForm();
			await loadEntries(); // Reload entries after adding
			await loadSecurityInfo(); // Reload security info
		} catch (error) {
			console.error('[VaultScreen] Error adding entry:', error);
			const errorMessage = error instanceof Error ? error.message : 'Unknown error';
			alert(`Failed to add entry: ${errorMessage}`);
		} finally {
			setIsAdding(false);
		}
	};

	const handleDeleteClick = (id: number) => {
		setEntryToDelete(id);
		setShowDeleteModal(true);
	};

	const handleDeleteConfirm = async () => {
		if (entryToDelete === null) return;

		try {
			if (!window.vault) {
				console.error('[VaultScreen] window.vault is undefined!');
				alert('Vault API not available. Please restart the app.');
				return;
			}

			const success = await window.vault.deleteEntry(entryToDelete);

			if (success) {
				// Clear form and reload entries
				resetForm();
				await loadEntries();
				await loadSecurityInfo(); // Reload security info
				setShowDeleteModal(false);
				setEntryToDelete(null);
			} else {
				console.error('[VaultScreen] Delete operation returned false');
				alert('Failed to delete entry. Please try again.');
			}
		} catch (error) {
			console.error('[VaultScreen] Error deleting entry:', error);
			const errorMessage = error instanceof Error ? error.message : 'Unknown error';
			alert(`Failed to delete entry: ${errorMessage}`);
		}
	};

	const handleDeleteCancel = () => {
		setShowDeleteModal(false);
		setEntryToDelete(null);
	};

	const handleEditClick = (entry: Entry) => {
		setEntryToEdit(entry);
		setEditForm({
			name: entry.name,
			username: entry.username || '',
			password: entry.password,
			category: entry.category || 'personal',
		});
		setEditCategoryManuallySelected(false);
		// Analyze password strength for the existing password
		const strength = analyzePasswordStrength(entry.password);
		setEditPasswordStrength(strength);
		setShowEditModal(true);
	};

	const handleHistoryClick = async (entry: Entry) => {
		setEntryForHistory(entry);
		setShowHistoryModal(true);
		setIsLoadingHistory(true);
		setEntryHistory([]);

		try {
			if (!window.vault) {
				console.error('[VaultScreen] window.vault is undefined!');
				alert('Vault API not available. Please restart the app.');
				return;
			}

			if (typeof window.vault.getEntryHistory !== 'function') {
				console.error('[VaultScreen] window.vault.getEntryHistory is not a function!');
				alert('History function not available. Please restart the app to apply updates.');
				return;
			}

			const history = await window.vault.getEntryHistory(entry.id, masterPassword);
			setEntryHistory(history);
		} catch (error) {
			console.error('[VaultScreen] Error loading entry history:', error);
			const errorMessage = error instanceof Error ? error.message : 'Unknown error';
			alert(`Failed to load entry history: ${errorMessage}`);
		} finally {
			setIsLoadingHistory(false);
		}
	};

	const toggleBulkMode = () => {
		setBulkMode(!bulkMode);
		setSelectedEntries(new Set()); // Clear selection when toggling
	};

	const toggleEntrySelection = (entryId: number) => {
		setSelectedEntries(prev => {
			const newSet = new Set(prev);
			if (newSet.has(entryId)) {
				newSet.delete(entryId);
			} else {
				newSet.add(entryId);
			}
			return newSet;
		});
	};

	const selectAllEntries = () => {
		if (selectedEntries.size === filteredEntries.length) {
			setSelectedEntries(new Set());
		} else {
			setSelectedEntries(new Set(filteredEntries.map(e => e.id)));
		}
	};

	const handleBulkDelete = async () => {
		if (selectedEntries.size === 0) {
			alert('Please select at least one entry to delete');
			return;
		}

		try {
			if (!window.vault) {
				console.error('[VaultScreen] window.vault is undefined!');
				alert('Vault API not available. Please restart the app.');
				return;
			}

			setIsBulkDeleting(true);
			const entryIds = Array.from(selectedEntries);
			let successCount = 0;
			let failCount = 0;

			for (const id of entryIds) {
				try {
					const success = await window.vault.deleteEntry(id);
					if (success) {
						successCount++;
					} else {
						failCount++;
					}
				} catch (error) {
					console.error(`[VaultScreen] Error deleting entry ${id}:`, error);
					failCount++;
				}
			}

			// Reload entries
			await loadEntries();
			await loadSecurityInfo();

			// Clear selection and exit bulk mode
			setSelectedEntries(new Set());
			setBulkMode(false);
			setShowBulkDeleteModal(false);

			if (failCount === 0) {
				alert(`Successfully deleted ${successCount} entry/entries`);
			} else {
				alert(`Deleted ${successCount} entry/entries. ${failCount} failed.`);
			}
		} catch (error) {
			console.error('[VaultScreen] Error in bulk delete:', error);
			alert('An error occurred during bulk delete');
		} finally {
			setIsBulkDeleting(false);
		}
	};

	const handleBulkEdit = async () => {
		if (selectedEntries.size === 0) {
			alert('Please select at least one entry to edit');
			return;
		}

		try {
			if (!window.vault) {
				console.error('[VaultScreen] window.vault is undefined!');
				alert('Vault API not available. Please restart the app.');
				return;
			}

			if (typeof window.vault.updateEntry !== 'function') {
				console.error('[VaultScreen] window.vault.updateEntry is not a function!');
				alert('Update entry function not available. Please restart the app to apply updates.');
				return;
			}

			setIsBulkEditing(true);
			let successCount = 0;
			let failCount = 0;

			// Get all selected entries to update
			const entriesToUpdate = entries.filter(e => selectedEntries.has(e.id));

			for (const entry of entriesToUpdate) {
				try {
					const success = await window.vault.updateEntry({
						id: entry.id,
						name: entry.name,
						username: entry.username || '',
						password: entry.password, // Keep existing password
						category: bulkEditForm.category,
						masterPassword,
					});
					if (success) {
						successCount++;
					} else {
						failCount++;
					}
				} catch (error) {
					console.error(`[VaultScreen] Error updating entry ${entry.id}:`, error);
					failCount++;
				}
			}

			// Reload entries
			await loadEntries();
			await loadSecurityInfo();

			// Clear selection and exit bulk mode
			setSelectedEntries(new Set());
			setBulkMode(false);
			setShowBulkEditModal(false);

			if (failCount === 0) {
				alert(`Successfully updated ${successCount} entry/entries`);
			} else {
				alert(`Updated ${successCount} entry/entries. ${failCount} failed.`);
			}
		} catch (error) {
			console.error('[VaultScreen] Error in bulk edit:', error);
			alert('An error occurred during bulk edit');
		} finally {
			setIsBulkEditing(false);
		}
	};

	const handleRollback = async (historyId: number) => {
		if (!entryForHistory) return;

		if (
			!confirm(
				`Are you sure you want to rollback this entry to this previous version? The current version will be saved to history.`
			)
		) {
			return;
		}

		try {
			if (!window.vault) {
				console.error('[VaultScreen] window.vault is undefined!');
				alert('Vault API not available. Please restart the app.');
				return;
			}

			if (typeof window.vault.rollbackEntry !== 'function') {
				console.error('[VaultScreen] window.vault.rollbackEntry is not a function!');
				alert('Rollback function not available. Please restart the app to apply updates.');
				return;
			}

			setIsRollingBack(true);
			const success = await window.vault.rollbackEntry(entryForHistory.id, historyId, masterPassword);

			if (success) {
				alert('Entry rolled back successfully!');
				// Reload entries and history
				await loadEntries();
				await handleHistoryClick(entryForHistory); // Reload history
			} else {
				alert('Failed to rollback entry. Please try again.');
			}
		} catch (error) {
			console.error('[VaultScreen] Error rolling back entry:', error);
			const errorMessage = error instanceof Error ? error.message : 'Unknown error';
			alert(`Failed to rollback entry: ${errorMessage}`);
		} finally {
			setIsRollingBack(false);
		}
	};

	const handleEditCancel = () => {
		setShowEditModal(false);
		setEntryToEdit(null);
		setEditForm({ name: '', username: '', password: '', category: 'personal' });
		setEditPasswordStrength(null);
		setEditCategoryManuallySelected(false);
	};

	const handleEdit = async () => {
		if (!entryToEdit) return;

		if (!editForm.name.trim() || !editForm.password.trim()) {
			alert('Service name and password are required!');
			return;
		}

		try {
			if (!window.vault) {
				console.error('[VaultScreen] window.vault is undefined!');
				alert('Vault API not available. Please restart the app.');
				return;
			}

			if (typeof window.vault.updateEntry !== 'function') {
				console.error('[VaultScreen] window.vault.updateEntry is not a function!');
				alert('Update entry function not available. Please restart the app to apply updates.');
				return;
			}

			setIsEditing(true);
			const success = await window.vault.updateEntry({
				id: entryToEdit.id,
				name: editForm.name,
				username: editForm.username,
				password: editForm.password,
				category: editForm.category,
				masterPassword,
			});

			if (success) {
				await loadEntries(); // Reload entries after editing
				await loadSecurityInfo(); // Reload security info
				handleEditCancel(); // Close modal and reset form
			} else {
				alert('Failed to update entry. Please try again.');
			}
		} catch (error) {
			console.error('[VaultScreen] Error updating entry:', error);
			const errorMessage = error instanceof Error ? error.message : 'Unknown error';
			alert(`Failed to update entry: ${errorMessage}`);
		} finally {
			setIsEditing(false);
		}
	};

	// Handle password change in edit form
	const handleEditPasswordChange = (password: string) => {
		setEditForm({ ...editForm, password });
		if (password.length > 0) {
			const strength = analyzePasswordStrength(password);
			setEditPasswordStrength(strength);
		} else {
			setEditPasswordStrength(null);
		}
	};

	// Handle service name change in edit form
	const handleEditServiceNameChange = (name: string) => {
		setEditForm(prev => {
			// Only auto-suggest if the user hasn't manually selected a category yet
			if (!editCategoryManuallySelected) {
				const suggestedCategory = suggestCategory(name);
				return { ...prev, name, category: suggestedCategory };
			}
			// If user has manually selected a category, keep it and only update the name
			return { ...prev, name };
		});
	};

	// Handle password generated in edit form
	const handleEditPasswordGenerated = (password: string) => {
		setEditForm({ ...editForm, password });
		// Analyze the generated password strength
		const strength = analyzePasswordStrength(password);
		setEditPasswordStrength(strength);
	};

	// Handle change master password
	const handleChangePassword = async () => {
		if (!changePasswordForm.currentPassword || !changePasswordForm.newPassword || !changePasswordForm.confirmPassword) {
			alert('Please fill in all fields');
			return;
		}

		if (changePasswordForm.newPassword !== changePasswordForm.confirmPassword) {
			alert('New password and confirm password do not match');
			return;
		}

		if (changePasswordForm.newPassword === changePasswordForm.currentPassword) {
			alert('New password must be different from current password');
			return;
		}

		try {
			if (!window.vault) {
				console.error('[VaultScreen] window.vault is undefined!');
				alert('Vault API not available. Please restart the app.');
				return;
			}

			if (typeof window.vault.changeMasterPassword !== 'function') {
				console.error('[VaultScreen] window.vault.changeMasterPassword is not a function!');
				alert('Change password function not available. Please restart the app to apply updates.');
				return;
			}

			setIsChangingPassword(true);
			const result = await window.vault.changeMasterPassword({
				oldPassword: changePasswordForm.currentPassword,
				newPassword: changePasswordForm.newPassword,
			});

			if (result) {
				// Save password hint if provided
				if (changePasswordForm.passwordHint.trim() && typeof window.vault.setPasswordHint === 'function') {
					try {
						await window.vault.setPasswordHint(changePasswordForm.passwordHint.trim(), changePasswordForm.newPassword);
					} catch (error) {
						console.error('[VaultScreen] Error setting password hint:', error);
						// Don't fail the password change if hint fails
					}
				} else if (!changePasswordForm.passwordHint.trim() && typeof window.vault.setPasswordHint === 'function') {
					// Clear hint if empty
					try {
						await window.vault.setPasswordHint('', changePasswordForm.newPassword);
					} catch (error) {
						console.error('[VaultScreen] Error clearing password hint:', error);
					}
				}

				let message = 'Master password changed successfully!';

				// Check if some entries were skipped (result is an object with details)
				if (typeof result === 'object' && 'success' in result && result.success) {
					if (result.skipped > 0 && result.skippedEntries) {
						const skippedDetails = result.skippedEntries
							.map(
								(e: { id: number; name: string; reason?: string }) =>
									`ID ${e.id} (${e.name})${e.reason ? ': ' + e.reason : ''}`
							)
							.join('\n');
						message += `\n\nWarning: ${result.skipped} entry/entries could not be decrypted and were skipped:\n${skippedDetails}\n\nThese entries will remain encrypted with the old password. You may need to delete and recreate them, or they may be corrupted.`;
					}
				}

				if (changePasswordForm.passwordHint.trim()) {
					message += '\n\nPassword hint has been saved.';
				}

				message += '\n\nYou will need to log in again with your new password.';

				alert(message);
				// Reset form and close modal
				setChangePasswordForm({ currentPassword: '', newPassword: '', confirmPassword: '', passwordHint: '' });
				setNewPasswordStrength(null);
				setShowChangePasswordModal(false);
				// Trigger auto-lock to force re-login
				onAutoLock();
			} else {
				alert('Failed to change master password. Please try again.');
			}
		} catch (error) {
			console.error('[VaultScreen] Error changing master password:', error);
			const errorMessage = error instanceof Error ? error.message : 'Unknown error';
			alert(`Failed to change master password: ${errorMessage}`);
		} finally {
			setIsChangingPassword(false);
		}
	};

	// Handle new password change in change password form
	const handleNewPasswordChange = (password: string) => {
		setChangePasswordForm({ ...changePasswordForm, newPassword: password });
		if (password.length > 0) {
			const strength = analyzePasswordStrength(password);
			setNewPasswordStrength(strength);
		} else {
			setNewPasswordStrength(null);
		}
	};

	// Load recovery settings
	const loadRecoverySettings = async () => {
		try {
			if (!window.vault) return;

			// Load existing recovery questions
			if (typeof window.vault.getRecoveryQuestions === 'function') {
				const questions = await window.vault.getRecoveryQuestions();
				setExistingRecoveryQuestions(questions); // Store for reference
				if (questions.length > 0) {
					setRecoveryQuestions(questions.map(q => ({ question: q.question, answer: '' })));
				}
			}

			// Load backup codes status
			if (typeof window.vault.getBackupCodesStatus === 'function') {
				const status = await window.vault.getBackupCodesStatus();
				setBackupCodesStatus(status);
			}
		} catch (error) {
			console.error('[VaultScreen] Error loading recovery settings:', error);
		}
	};

	// Handle save recovery questions
	const handleSaveRecoveryQuestions = async () => {
		// Validate
		const validQuestions = recoveryQuestions.filter(q => q.question.trim() && q.answer.trim());
		if (validQuestions.length === 0) {
			alert('Please add at least one recovery question with both question and answer');
			return;
		}

		if (validQuestions.length > 5) {
			alert('Maximum 5 recovery questions allowed');
			return;
		}

		try {
			if (!window.vault) {
				console.error('[VaultScreen] window.vault is undefined!');
				alert('Vault API not available. Please restart the app.');
				return;
			}

			// Check if function exists
			if (typeof window.vault.setRecoveryQuestions !== 'function') {
				console.error('[VaultScreen] setRecoveryQuestions is not a function!');
				alert('Recovery questions feature not available. Please restart the app to apply updates.');
				return;
			}

			setIsSavingRecoveryQuestions(true);
			await window.vault.setRecoveryQuestions(validQuestions, masterPassword);
			alert(`Successfully saved ${validQuestions.length} recovery question${validQuestions.length === 1 ? '' : 's'}`);
			await loadRecoverySettings();
		} catch (error) {
			console.error('[VaultScreen] Error saving recovery questions:', error);
			const errorMessage = error instanceof Error ? error.message : 'Unknown error';
			alert(`Failed to save recovery questions: ${errorMessage}`);
		} finally {
			setIsSavingRecoveryQuestions(false);
		}
	};

	// Handle generate backup codes
	const handleGenerateBackupCodes = async () => {
		if (!confirm('Generating new backup codes will invalidate all existing unused codes. Continue?')) {
			return;
		}

		try {
			if (!window.vault) {
				console.error('[VaultScreen] window.vault is undefined!');
				alert('Vault API not available. Please restart the app.');
				return;
			}

			// Check if function exists
			if (typeof window.vault.generateBackupCodes !== 'function') {
				console.error('[VaultScreen] generateBackupCodes is not a function!');
				alert('Backup codes feature not available. Please restart the app to apply updates.');
				return;
			}

			setIsGeneratingCodes(true);
			const codes = await window.vault.generateBackupCodes(masterPassword);
			setGeneratedBackupCodes(codes);
			await loadRecoverySettings();
		} catch (error) {
			console.error('[VaultScreen] Error generating backup codes:', error);
			const errorMessage = error instanceof Error ? error.message : 'Unknown error';
			alert(`Failed to generate backup codes: ${errorMessage}`);
		} finally {
			setIsGeneratingCodes(false);
		}
	};

	// Password generator functions
	const handlePasswordGenerated = (password: string) => {
		setForm({ ...form, password });
		// Analyze the generated password strength
		const strength = analyzePasswordStrength(password);
		setPasswordStrength(strength);
	};

	// Analyze password strength when user types
	const handlePasswordChange = (password: string) => {
		setForm({ ...form, password });
		if (password.length > 0) {
			const strength = analyzePasswordStrength(password);
			setPasswordStrength(strength);
		} else {
			setPasswordStrength(null);
		}
	};

	const getPasswordStrengthColor = (level: string) => {
		switch (level) {
			case 'weak':
				return '#ef4444';
			case 'medium':
				return '#f59e0b';
			case 'strong':
				return '#10b981';
			case 'very-strong':
				return '#059669';
			default:
				return '#6b7280';
		}
	};

	// Enhanced clipboard protection with feedback
	const copyToClipboard = async (text: string, type: string, id: string) => {
		try {
			if (!navigator.clipboard) {
				console.warn('[VaultScreen] Clipboard API not available');
				return;
			}

			await navigator.clipboard.writeText(text);
			console.log(`[VaultScreen] ${type} copied to clipboard`);

			// Show "Copied!" feedback
			setCopiedItem(id);
			setTimeout(() => setCopiedItem(null), 2000); // Hide after 2 seconds

			// Clear clipboard after 30 seconds for security
			setTimeout(async () => {
				try {
					await navigator.clipboard.writeText('');
					console.log('[VaultScreen] Clipboard cleared for security');
				} catch (e) {
					console.warn('[VaultScreen] Could not clear clipboard:', e);
				}
			}, 30000);
		} catch (error) {
			console.error('[VaultScreen] Failed to copy to clipboard:', error);
		}
	};

	// Filter entries based on search query and category (only service name and username for security)
	const filteredEntries = entries.filter(entry => {
		// Category filter
		if (selectedCategory !== 'all' && entry.category !== selectedCategory) {
			return false;
		}

		// Search filter
		if (!searchQuery.trim()) return true;

		const query = searchQuery.toLowerCase();
		return entry.name.toLowerCase().includes(query) || (entry.username && entry.username.toLowerCase().includes(query));
	});

	// Auto-suggest category when service name changes (only if category hasn't been manually changed)
	const handleServiceNameChange = (name: string) => {
		setForm(prev => {
			// Only auto-suggest if the user hasn't manually selected a category yet
			if (!categoryManuallySelected) {
				const suggestedCategory = suggestCategory(name);
				return { ...prev, name, category: suggestedCategory };
			}
			// If user has manually selected a category, keep it and only update the name
			return { ...prev, name };
		});
	};

	const formatDate = (dateString?: string) => {
		if (!dateString) return 'Unknown';
		try {
			const date = new Date(dateString);
			return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
		} catch {
			return 'Unknown';
		}
	};

	// Close menu when clicking outside
	useEffect(() => {
		if (showMenu) {
			const handleClickOutside = (e: MouseEvent) => {
				const target = e.target as HTMLElement;
				if (!target.closest('.menu-toggle-button') && !target.closest('.menu-dropdown')) {
					setShowMenu(false);
				}
			};
			document.addEventListener('mousedown', handleClickOutside);
			return () => document.removeEventListener('mousedown', handleClickOutside);
		}
	}, [showMenu]);

	return (
		<div className='vault-container'>
			<div className='vault-header'>
				<div className='auto-lock-display'>
					<span className='auto-lock-label'>Auto-lock in:</span>
					<span
						className='auto-lock-timer'
						style={{
							color: timeUntilLock <= 30 ? '#ef4444' : timeUntilLock <= 60 ? '#f59e0b' : '#10b981',
						}}>
						{Math.floor(timeUntilLock / 60)}:{(timeUntilLock % 60).toString().padStart(2, '0')}
					</span>
				</div>
				<div style={{ position: 'relative' }}>
					<button className='menu-toggle-button' onClick={() => setShowMenu(!showMenu)} title='Menu'>
						{showMenu ? <X size={20} /> : <Menu size={20} />}
					</button>
					{showMenu && (
						<div className='menu-dropdown' onClick={e => e.stopPropagation()}>
							<button
								className='menu-item'
								onClick={() => {
									setShowChangePasswordModal(true);
									setShowMenu(false);
								}}>
								<Lock size={16} />
								<span>Change Password</span>
							</button>
							<button
								className='menu-item'
								onClick={() => {
									setShowRecoverySettings(true);
									loadRecoverySettings();
									setShowMenu(false);
								}}>
								<Key size={16} />
								<span>Recovery Settings</span>
							</button>
							<button
								className='menu-item'
								onClick={() => {
									toggleTheme();
									setShowMenu(false);
								}}
								style={{ borderTop: '1px solid var(--border-color)' }}>
								{theme === 'light' ? <Moon size={16} /> : <Sun size={16} />}
								<span>Switch to {theme === 'light' ? 'Dark' : 'Light'} Theme</span>
							</button>
							<button
								className='menu-item'
								onClick={async () => {
									setShowSecurityInfo(true);
									setShowMenu(false);
									// Load security status
									try {
										if (window.security && (window.security as any).getStatus) {
											const status = await (window.security as any).getStatus();
											setSecurityStatus(status);
										}
									} catch (error) {
										console.error('[VaultScreen] Error loading security status:', error);
									}
								}}>
								<Shield size={16} />
								<span>Security Info</span>
							</button>
						</div>
					)}
				</div>
			</div>

			<div className='vault-card'>
				<h1 className='vault-title'>Password Manager</h1>

				{/* Add Entry Section */}
				<div className='add-entry-section'>
					{isAdding && (
						<div className='loading-indicator'>
							<div className='spinner'></div>
							<span>Encrypting and saving entry...</span>
						</div>
					)}
					<form
						className='entry-form'
						onSubmit={e => {
							e.preventDefault();
							handleAdd();
						}}>
						<div className='form-row'>
							<input
								type='text'
								placeholder='Service (required)'
								value={form.name}
								onChange={e => handleServiceNameChange(e.target.value)}
								className='form-input'
								disabled={isAdding}
								required
							/>
							<input
								type='text'
								placeholder='Username (optional)'
								value={form.username}
								onChange={e => setForm({ ...form, username: e.target.value })}
								className='form-input'
								disabled={isAdding}
							/>
						</div>
						<div className='form-row'>
							<div className='password-input-group'>
								<input
									type='password'
									placeholder='Password (required)'
									value={form.password}
									onChange={e => handlePasswordChange(e.target.value)}
									className='form-input'
									disabled={isAdding}
									required
								/>
								<button
									type='button'
									className='password-generator-btn'
									onClick={() => setShowPasswordGenerator(true)}
									disabled={isAdding}
									title='Generate secure password'>
									<Shuffle size={16} />
								</button>
							</div>
							{passwordStrength && (
								<div className='password-strength-indicator'>
									<div className='strength-bar'>
										<div
											className='strength-fill'
											style={{
												width: `${passwordStrength.score}%`,
												backgroundColor: getPasswordStrengthColor(passwordStrength.level),
											}}
										/>
									</div>
									<span className='strength-text' style={{ color: getPasswordStrengthColor(passwordStrength.level) }}>
										{passwordStrength.level.replace('-', ' ').toUpperCase()} ({passwordStrength.score}/100)
									</span>
								</div>
							)}
						</div>
						<div className='form-row'>
							<button
								type='button'
								className='category-selector-button'
								onClick={() => setShowCategoryModal(true)}
								disabled={isAdding}>
								{renderCategoryIcon(DEFAULT_CATEGORIES.find(cat => cat.id === form.category)?.icon || 'Key', 16)}
								<span>{DEFAULT_CATEGORIES.find(cat => cat.id === form.category)?.name || 'Select Category'}</span>
								<span className='selector-arrow'>▼</span>
							</button>
						</div>
						<button type='submit' className='submit-button' disabled={isAdding}>
							{isAdding ? 'Adding...' : 'Add Entry'}
						</button>
					</form>
				</div>

				{/* Category Selection Modal */}
				{showCategoryModal && (
					<div
						className={`modal-overlay ${showEditModal || showBulkEditModal ? 'modal-overlay-nested' : ''}`}
						onClick={() => setShowCategoryModal(false)}>
						<div className='category-modal' onClick={e => e.stopPropagation()}>
							<div className='modal-header'>
								<h3>Select Category</h3>
								<button className='modal-close' onClick={() => setShowCategoryModal(false)} title='Close'>
									×
								</button>
							</div>
							<div className='category-grid'>
								{DEFAULT_CATEGORIES.map(category => (
									<div
										key={category.id}
										className={`category-option ${
											showBulkEditModal
												? bulkEditForm.category === category.id
													? 'selected'
													: ''
												: showEditModal
												? editForm.category === category.id
													? 'selected'
													: ''
												: form.category === category.id
												? 'selected'
												: ''
										}`}
										onClick={() => {
											if (showBulkEditModal) {
												setBulkEditForm({ ...bulkEditForm, category: category.id });
											} else if (showEditModal) {
												setEditForm({ ...editForm, category: category.id });
												setEditCategoryManuallySelected(true);
											} else {
												setForm({ ...form, category: category.id });
												setCategoryManuallySelected(true);
											}
											setShowCategoryModal(false);
										}}>
										<div className='category-icon-wrapper' style={{ backgroundColor: category.color }}>
											{renderCategoryIcon(category.icon, 24)}
										</div>
										<span className='category-name'>{category.name}</span>
									</div>
								))}
							</div>
						</div>
					</div>
				)}

				{/* Category Filter Modal */}
				{showFilterModal && (
					<div className='modal-overlay' onClick={() => setShowFilterModal(false)}>
						<div className='category-modal' onClick={e => e.stopPropagation()}>
							<div className='modal-header'>
								<h3>Filter by Category</h3>
								<button className='modal-close' onClick={() => setShowFilterModal(false)} title='Close'>
									×
								</button>
							</div>
							<div className='category-grid'>
								{/* All Categories Option */}
								<div
									className={`category-option ${selectedCategory === 'all' ? 'selected' : ''}`}
									onClick={() => {
										setSelectedCategory('all');
										setShowFilterModal(false);
									}}>
									<div className='category-icon-wrapper' style={{ backgroundColor: '#6b7280' }}>
										<Search size={24} />
									</div>
									<span className='category-name'>All Categories</span>
								</div>

								{/* Individual Categories */}
								{DEFAULT_CATEGORIES.map(category => (
									<div
										key={category.id}
										className={`category-option ${selectedCategory === category.id ? 'selected' : ''}`}
										onClick={() => {
											setSelectedCategory(category.id);
											setShowFilterModal(false);
										}}>
										<div className='category-icon-wrapper' style={{ backgroundColor: category.color }}>
											{renderCategoryIcon(category.icon, 24)}
										</div>
										<span className='category-name'>{category.name}</span>
									</div>
								))}
							</div>
						</div>
					</div>
				)}

				{/* Password Generator Modal */}
				<PasswordGeneratorModal
					isOpen={showPasswordGenerator}
					onClose={() => setShowPasswordGenerator(false)}
					onPasswordGenerated={password => {
						// Determine if we're in edit mode or add mode
						if (showEditModal && entryToEdit) {
							handleEditPasswordGenerated(password);
						} else {
							handlePasswordGenerated(password);
						}
					}}
					isNested={showEditModal}
				/>

				{/* Delete Confirmation Modal */}
				{showDeleteModal && (
					<div className='modal-overlay' onClick={handleDeleteCancel}>
						<div className='delete-modal' onClick={e => e.stopPropagation()}>
							<div className='modal-header'>
								<h3>Delete Entry</h3>
								<button className='modal-close' onClick={handleDeleteCancel} title='Close'>
									×
								</button>
							</div>
							<div className='delete-content'>
								<div className='delete-icon'>
									<Trash2 size={48} />
								</div>
								<p className='delete-message'>
									Are you sure you want to delete this entry? This action cannot be undone.
								</p>
								<div className='delete-actions'>
									<button className='delete-cancel' onClick={handleDeleteCancel}>
										Cancel
									</button>
									<button className='delete-confirm' onClick={handleDeleteConfirm}>
										Delete
									</button>
								</div>
							</div>
						</div>
					</div>
				)}

				{/* Edit Entry Modal */}
				{showEditModal && entryToEdit && (
					<div className='modal-overlay' onClick={handleEditCancel}>
						<div className='category-modal' onClick={e => e.stopPropagation()} style={{ maxWidth: '600px' }}>
							<div className='modal-header'>
								<h3>Edit Entry</h3>
								<button className='modal-close' onClick={handleEditCancel} title='Close'>
									×
								</button>
							</div>
							{isEditing && (
								<div className='loading-indicator'>
									<div className='spinner'></div>
									<span>Encrypting and updating entry...</span>
								</div>
							)}
							<form
								className='entry-form'
								onSubmit={e => {
									e.preventDefault();
									handleEdit();
								}}
								style={{ marginTop: '20px' }}>
								<div className='form-row'>
									<input
										type='text'
										placeholder='Service (required)'
										value={editForm.name}
										onChange={e => handleEditServiceNameChange(e.target.value)}
										className='form-input'
										disabled={isEditing}
										required
									/>
									<input
										type='text'
										placeholder='Username (optional)'
										value={editForm.username}
										onChange={e => setEditForm({ ...editForm, username: e.target.value })}
										className='form-input'
										disabled={isEditing}
									/>
								</div>
								<div className='form-row'>
									<div className='password-input-group'>
										<input
											type='password'
											placeholder='Password (required)'
											value={editForm.password}
											onChange={e => handleEditPasswordChange(e.target.value)}
											className='form-input'
											disabled={isEditing}
											required
										/>
										<button
											type='button'
											className='password-generator-btn'
											onClick={() => {
												// Open password generator with callback for edit form
												setShowPasswordGenerator(true);
											}}
											disabled={isEditing}
											title='Generate secure password'>
											<Shuffle size={16} />
										</button>
									</div>
									{editPasswordStrength && (
										<div className='password-strength-indicator'>
											<div className='strength-bar'>
												<div
													className='strength-fill'
													style={{
														width: `${editPasswordStrength.score}%`,
														backgroundColor: getPasswordStrengthColor(editPasswordStrength.level),
													}}
												/>
											</div>
											<span
												className='strength-text'
												style={{ color: getPasswordStrengthColor(editPasswordStrength.level) }}>
												{editPasswordStrength.level.replace('-', ' ').toUpperCase()} ({editPasswordStrength.score}/100)
											</span>
										</div>
									)}
								</div>
								<div className='form-row'>
									<button
										type='button'
										className='category-selector-button'
										onClick={() => {
											// We'll handle category selection inline for edit modal
											// For now, use the same category modal but track it differently
											setShowCategoryModal(true);
										}}
										disabled={isEditing}>
										{renderCategoryIcon(
											DEFAULT_CATEGORIES.find(cat => cat.id === editForm.category)?.icon || 'Key',
											16
										)}
										<span>
											{DEFAULT_CATEGORIES.find(cat => cat.id === editForm.category)?.name || 'Select Category'}
										</span>
										<span className='selector-arrow'>▼</span>
									</button>
								</div>
								<div className='form-actions' style={{ display: 'flex', gap: '10px', marginTop: '20px' }}>
									<button type='button' className='delete-cancel' onClick={handleEditCancel} disabled={isEditing}>
										Cancel
									</button>
									<button type='submit' className='submit-button' disabled={isEditing}>
										{isEditing ? 'Updating...' : 'Update Entry'}
									</button>
								</div>
							</form>
						</div>
					</div>
				)}

				{/* Change Master Password Modal */}
				{showChangePasswordModal && (
					<div className='modal-overlay' onClick={() => setShowChangePasswordModal(false)}>
						<div className='category-modal' onClick={e => e.stopPropagation()} style={{ maxWidth: '500px' }}>
							<div className='modal-header'>
								<h3>Change Master Password</h3>
								<button
									className='modal-close'
									onClick={() => {
										setShowChangePasswordModal(false);
										setChangePasswordForm({
											currentPassword: '',
											newPassword: '',
											confirmPassword: '',
											passwordHint: '',
										});
										setNewPasswordStrength(null);
									}}
									title='Close'>
									×
								</button>
							</div>
							{isChangingPassword && (
								<div className='loading-indicator'>
									<div className='spinner'></div>
									<span>Re-encrypting all entries with new password...</span>
								</div>
							)}
							<form
								className='entry-form'
								onSubmit={e => {
									e.preventDefault();
									handleChangePassword();
								}}
								style={{ marginTop: '20px' }}>
								<div className='form-row'>
									<input
										type='password'
										placeholder='Current Master Password (required)'
										value={changePasswordForm.currentPassword}
										onChange={e => setChangePasswordForm({ ...changePasswordForm, currentPassword: e.target.value })}
										className='form-input'
										disabled={isChangingPassword}
										required
									/>
								</div>
								<div className='form-row'>
									<input
										type='password'
										placeholder='New Master Password (required)'
										value={changePasswordForm.newPassword}
										onChange={e => handleNewPasswordChange(e.target.value)}
										className='form-input'
										disabled={isChangingPassword}
										required
									/>
									{newPasswordStrength && (
										<div className='password-strength-indicator'>
											<div className='strength-bar'>
												<div
													className='strength-fill'
													style={{
														width: `${newPasswordStrength.score}%`,
														backgroundColor: getPasswordStrengthColor(newPasswordStrength.level),
													}}
												/>
											</div>
											<span
												className='strength-text'
												style={{ color: getPasswordStrengthColor(newPasswordStrength.level) }}>
												{newPasswordStrength.level.replace('-', ' ').toUpperCase()} ({newPasswordStrength.score}/100)
											</span>
										</div>
									)}
								</div>
								<div className='form-row'>
									<input
										type='password'
										placeholder='Confirm New Password (required)'
										value={changePasswordForm.confirmPassword}
										onChange={e => setChangePasswordForm({ ...changePasswordForm, confirmPassword: e.target.value })}
										className='form-input'
										disabled={isChangingPassword}
										required
									/>
									{changePasswordForm.confirmPassword &&
										changePasswordForm.newPassword !== changePasswordForm.confirmPassword && (
											<span style={{ color: '#ef4444', fontSize: '12px' }}>Passwords do not match</span>
										)}
								</div>
								<div className='form-row'>
									<input
										type='text'
										placeholder='Password Hint (optional) - Helps you remember your password'
										value={changePasswordForm.passwordHint}
										onChange={e => setChangePasswordForm({ ...changePasswordForm, passwordHint: e.target.value })}
										className='form-input'
										disabled={isChangingPassword}
										maxLength={200}
									/>
									<div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '4px' }}>
										This hint will be encrypted and can help you remember your password if you forget it.
									</div>
								</div>
								<div
									className='form-actions'
									style={{
										display: 'flex',
										gap: '12px',
										marginTop: '32px',
										marginBottom: '20px',
										justifyContent: 'center',
										alignItems: 'center',
									}}>
									<button
										type='button'
										className='delete-cancel'
										onClick={() => {
											setShowChangePasswordModal(false);
											setChangePasswordForm({
												currentPassword: '',
												newPassword: '',
												confirmPassword: '',
												passwordHint: '',
											});
											setNewPasswordStrength(null);
										}}
										disabled={isChangingPassword}>
										Cancel
									</button>
									<button type='submit' className='submit-button' disabled={isChangingPassword}>
										{isChangingPassword ? 'Changing...' : 'Change Password'}
									</button>
								</div>
							</form>
						</div>
					</div>
				)}

				{/* Recovery Settings Modal */}
				{showRecoverySettings && (
					<div className='modal-overlay' onClick={() => setShowRecoverySettings(false)}>
						<div
							className='category-modal'
							onClick={e => e.stopPropagation()}
							style={{ maxWidth: '700px', maxHeight: '90vh' }}>
							<div className='modal-header'>
								<h3>Recovery Settings</h3>
								<button className='modal-close' onClick={() => setShowRecoverySettings(false)} title='Close'>
									×
								</button>
							</div>
							<div style={{ padding: '20px', overflowY: 'auto', maxHeight: 'calc(90vh - 100px)' }}>
								{/* Email/SMS Recovery Section */}
								<div
									style={{
										marginBottom: '32px',
										padding: '16px',
										background: 'rgba(16, 185, 129, 0.1)',
										border: '1px solid #10b981',
										borderRadius: '8px',
									}}>
									<h4 style={{ marginBottom: '8px', color: 'var(--text-primary)' }}>
										📧 Email/SMS Recovery (Recommended)
									</h4>
									<p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '16px' }}>
										Set up email or phone recovery to reset your password while preserving all your password entries.
										This is the safest recovery method.
									</p>
									<div style={{ marginBottom: '12px' }}>
										<input
											type='email'
											placeholder='Email address'
											value={emailSMSRecovery.email}
											onChange={e => setEmailSMSRecovery({ ...emailSMSRecovery, email: e.target.value })}
											className='form-input'
											disabled={isSettingUpEmailSMS}
											style={{ marginBottom: '12px' }}
										/>
										<input
											type='tel'
											placeholder='Phone number (optional)'
											value={emailSMSRecovery.phone}
											onChange={e => setEmailSMSRecovery({ ...emailSMSRecovery, phone: e.target.value })}
											className='form-input'
											disabled={isSettingUpEmailSMS}
										/>
									</div>
									<button
										type='button'
										onClick={async () => {
											if (!emailSMSRecovery.email && !emailSMSRecovery.phone) {
												alert('Please enter at least an email address or phone number');
												return;
											}
											if (!window.vault || typeof (window.vault as any).setupEmailSMSRecovery !== 'function') {
												alert('Email/SMS recovery feature not available. Please restart the app.');
												return;
											}
											setIsSettingUpEmailSMS(true);
											try {
												await (window.vault as any).setupEmailSMSRecovery(
													emailSMSRecovery.email,
													emailSMSRecovery.phone,
													masterPassword
												);
												alert(
													'Email/SMS recovery set up successfully! You can now use this method to recover your password.'
												);
												setEmailSMSRecovery({ email: '', phone: '' });
											} catch (error) {
												const errorMessage = error instanceof Error ? error.message : 'Unknown error';
												alert(`Failed to set up email/SMS recovery: ${errorMessage}`);
											} finally {
												setIsSettingUpEmailSMS(false);
											}
										}}
										disabled={isSettingUpEmailSMS || (!emailSMSRecovery.email && !emailSMSRecovery.phone)}
										className='submit-button'
										style={{ width: '100%', background: '#10b981' }}>
										{isSettingUpEmailSMS ? 'Setting up...' : 'Set Up Email/SMS Recovery'}
									</button>
								</div>

								{/* Recovery Questions Section */}
								<div style={{ marginBottom: '32px', borderTop: '1px solid var(--border-color)', paddingTop: '32px' }}>
									<h4 style={{ marginBottom: '16px', color: 'var(--text-primary)' }}>Security Questions</h4>
									<p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '16px' }}>
										Set up security questions to recover your password if you forget it. You can set 1-5 questions.
									</p>

									{recoveryQuestions.map((q, index) => (
										<div
											key={index}
											style={{
												marginBottom: '16px',
												padding: '16px',
												background: 'var(--bg-secondary)',
												borderRadius: '8px',
											}}>
											<div className='form-row' style={{ marginBottom: '12px' }}>
												<input
													type='text'
													placeholder={`Question ${index + 1} (e.g., "What city were you born in?")`}
													value={q.question}
													onChange={e => {
														const newQuestions = [...recoveryQuestions];
														newQuestions[index].question = e.target.value;
														setRecoveryQuestions(newQuestions);
													}}
													className='form-input'
													disabled={isSavingRecoveryQuestions}
												/>
											</div>
											<div className='form-row'>
												<input
													type='password'
													placeholder={`Answer ${index + 1}`}
													value={q.answer}
													onChange={e => {
														const newQuestions = [...recoveryQuestions];
														newQuestions[index].answer = e.target.value;
														setRecoveryQuestions(newQuestions);
													}}
													className='form-input'
													disabled={isSavingRecoveryQuestions}
												/>
											</div>
											{recoveryQuestions.length > 1 && (
												<button
													type='button'
													onClick={() => {
														setRecoveryQuestions(recoveryQuestions.filter((_, i) => i !== index));
													}}
													style={{
														marginTop: '8px',
														padding: '4px 8px',
														background: '#dc2626',
														color: 'white',
														border: 'none',
														borderRadius: '4px',
														fontSize: '12px',
														cursor: 'pointer',
													}}>
													Remove
												</button>
											)}
										</div>
									))}

									{recoveryQuestions.length < 5 && (
										<button
											type='button'
											onClick={() => setRecoveryQuestions([...recoveryQuestions, { question: '', answer: '' }])}
											style={{
												marginBottom: '16px',
												padding: '8px 16px',
												background: 'var(--bg-primary)',
												border: '1px solid var(--border-color)',
												borderRadius: '4px',
												color: 'var(--text-primary)',
												cursor: 'pointer',
											}}>
											+ Add Question
										</button>
									)}

									<button
										type='button'
										onClick={handleSaveRecoveryQuestions}
										disabled={isSavingRecoveryQuestions}
										className='submit-button'
										style={{ width: '100%' }}>
										{isSavingRecoveryQuestions ? 'Saving...' : 'Save Recovery Questions'}
									</button>
								</div>

								{/* Backup Codes Section */}
								<div style={{ borderTop: '1px solid var(--border-color)', paddingTop: '32px' }}>
									<h4 style={{ marginBottom: '16px', color: 'var(--text-primary)' }}>Backup Codes</h4>
									<p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '16px' }}>
										Backup codes are one-time use codes that can help you recover your password. Generate new codes and
										save them in a safe place.
									</p>

									{backupCodesStatus.total > 0 && (
										<div
											style={{
												marginBottom: '16px',
												padding: '12px',
												background: 'var(--bg-secondary)',
												borderRadius: '8px',
											}}>
											<div style={{ fontSize: '14px', color: 'var(--text-primary)' }}>
												<strong>Status:</strong> {backupCodesStatus.unused} unused, {backupCodesStatus.used} used out of{' '}
												{backupCodesStatus.total} total codes
											</div>
										</div>
									)}

									{generatedBackupCodes.length > 0 && (
										<div
											style={{
												marginBottom: '16px',
												padding: '16px',
												background: 'rgba(59, 130, 246, 0.1)',
												border: '1px solid var(--accent-color)',
												borderRadius: '8px',
											}}>
											<div style={{ fontWeight: '600', marginBottom: '12px', color: 'var(--accent-color)' }}>
												⚠️ Save these codes now! They will not be shown again.
											</div>
											<div
												style={{
													display: 'grid',
													gridTemplateColumns: 'repeat(2, 1fr)',
													gap: '8px',
													fontFamily: 'monospace',
													fontSize: '14px',
												}}>
												{generatedBackupCodes.map((code, i) => (
													<div
														key={i}
														style={{
															padding: '8px',
															background: 'var(--bg-primary)',
															borderRadius: '4px',
															textAlign: 'center',
														}}>
														{code}
													</div>
												))}
											</div>
										</div>
									)}

									<button
										type='button'
										onClick={handleGenerateBackupCodes}
										disabled={isGeneratingCodes}
										className='submit-button'
										style={{ width: '100%' }}>
										{isGeneratingCodes ? 'Generating...' : 'Generate New Backup Codes'}
									</button>
								</div>
							</div>
						</div>
					</div>
				)}

				{/* Security Info Modal */}
				{showSecurityInfo && (
					<div className='modal-overlay' onClick={() => setShowSecurityInfo(false)}>
						<div className='category-modal' onClick={e => e.stopPropagation()} style={{ maxWidth: '600px' }}>
							<div className='modal-header'>
								<h3>Security Status</h3>
								<button className='modal-close' onClick={() => setShowSecurityInfo(false)} title='Close'>
									×
								</button>
							</div>
							<div style={{ padding: '20px' }}>
								{securityStatus ? (
									<>
										<div
											style={{
												display: 'grid',
												gridTemplateColumns: 'repeat(2, 1fr)',
												gap: '16px',
												marginBottom: '20px',
											}}>
											<div style={{ padding: '16px', background: 'var(--bg-secondary)', borderRadius: '8px' }}>
												<div
													style={{
														display: 'flex',
														justifyContent: 'space-between',
														alignItems: 'center',
														marginBottom: '8px',
													}}>
													<span style={{ fontSize: '14px', fontWeight: '500', color: 'var(--text-primary)' }}>
														AES-256 Encryption
													</span>
													{securityStatus.encryptionActive ? (
														<CheckCircle size={16} style={{ color: '#10b981' }} />
													) : (
														<AlertTriangle size={16} style={{ color: '#ef4444' }} />
													)}
												</div>
												<div
													style={{ fontSize: '12px', color: securityStatus.encryptionActive ? '#10b981' : '#ef4444' }}>
													{securityStatus.encryptionActive ? 'Active' : 'Inactive'}
												</div>
											</div>

											<div style={{ padding: '16px', background: 'var(--bg-secondary)', borderRadius: '8px' }}>
												<div
													style={{
														display: 'flex',
														justifyContent: 'space-between',
														alignItems: 'center',
														marginBottom: '8px',
													}}>
													<span style={{ fontSize: '14px', fontWeight: '500', color: 'var(--text-primary)' }}>
														Auto-Lock (3 min)
													</span>
													{securityStatus.autoLockActive ? (
														<CheckCircle size={16} style={{ color: '#10b981' }} />
													) : (
														<AlertTriangle size={16} style={{ color: '#ef4444' }} />
													)}
												</div>
												<div style={{ fontSize: '12px', color: securityStatus.autoLockActive ? '#10b981' : '#ef4444' }}>
													{securityStatus.autoLockActive ? 'Active' : 'Inactive'}
												</div>
											</div>

											<div style={{ padding: '16px', background: 'var(--bg-secondary)', borderRadius: '8px' }}>
												<div
													style={{
														display: 'flex',
														justifyContent: 'space-between',
														alignItems: 'center',
														marginBottom: '8px',
													}}>
													<span style={{ fontSize: '14px', fontWeight: '500', color: 'var(--text-primary)' }}>
														Offline Operation
													</span>
													{securityStatus.networkIsolation ? (
														<CheckCircle size={16} style={{ color: '#10b981' }} />
													) : (
														<AlertTriangle size={16} style={{ color: '#ef4444' }} />
													)}
												</div>
												<div
													style={{ fontSize: '12px', color: securityStatus.networkIsolation ? '#10b981' : '#ef4444' }}>
													{securityStatus.networkIsolation ? 'Active' : 'Inactive'}
												</div>
											</div>

											<div style={{ padding: '16px', background: 'var(--bg-secondary)', borderRadius: '8px' }}>
												<div
													style={{
														display: 'flex',
														justifyContent: 'space-between',
														alignItems: 'center',
														marginBottom: '8px',
													}}>
													<span style={{ fontSize: '14px', fontWeight: '500', color: 'var(--text-primary)' }}>
														Dev Tools Blocked
													</span>
													{securityStatus.developerToolsBlocked ? (
														<CheckCircle size={16} style={{ color: '#10b981' }} />
													) : (
														<AlertTriangle size={16} style={{ color: '#ef4444' }} />
													)}
												</div>
												<div
													style={{
														fontSize: '12px',
														color: securityStatus.developerToolsBlocked ? '#10b981' : '#ef4444',
													}}>
													{securityStatus.developerToolsBlocked ? 'Active' : 'Inactive'}
												</div>
											</div>

											<div style={{ padding: '16px', background: 'var(--bg-secondary)', borderRadius: '8px' }}>
												<div
													style={{
														display: 'flex',
														justifyContent: 'space-between',
														alignItems: 'center',
														marginBottom: '8px',
													}}>
													<span style={{ fontSize: '14px', fontWeight: '500', color: 'var(--text-primary)' }}>
														Context Menu Blocked
													</span>
													{securityStatus.contextMenuBlocked ? (
														<CheckCircle size={16} style={{ color: '#10b981' }} />
													) : (
														<AlertTriangle size={16} style={{ color: '#ef4444' }} />
													)}
												</div>
												<div
													style={{
														fontSize: '12px',
														color: securityStatus.contextMenuBlocked ? '#10b981' : '#ef4444',
													}}>
													{securityStatus.contextMenuBlocked ? 'Active' : 'Inactive'}
												</div>
											</div>
										</div>
										<div
											style={{
												padding: '12px',
												background: 'var(--bg-secondary)',
												borderRadius: '8px',
												fontSize: '13px',
												color: 'var(--text-secondary)',
											}}>
											<strong>Security:</strong> AES-256 encryption with offline-first operation
										</div>
									</>
								) : (
									<div style={{ textAlign: 'center', padding: '40px', color: 'var(--text-secondary)' }}>
										<div className='spinner' style={{ margin: '0 auto 16px' }}></div>
										<span>Loading security status...</span>
									</div>
								)}
							</div>
						</div>
					</div>
				)}

				{/* Entry History Modal */}
				{showHistoryModal && entryForHistory && (
					<div className='modal-overlay' onClick={() => setShowHistoryModal(false)}>
						<div
							className='category-modal'
							onClick={e => e.stopPropagation()}
							style={{ maxWidth: '700px', maxHeight: '80vh' }}>
							<div className='modal-header'>
								<h3>Entry History: {entryForHistory.name}</h3>
								<button
									className='modal-close'
									onClick={() => {
										setShowHistoryModal(false);
										setEntryForHistory(null);
										setEntryHistory([]);
									}}
									title='Close'>
									×
								</button>
							</div>
							<div style={{ padding: '20px', overflowY: 'auto', maxHeight: 'calc(80vh - 100px)' }}>
								{isLoadingHistory ? (
									<div className='loading-indicator'>
										<div className='spinner'></div>
										<span>Loading history...</span>
									</div>
								) : entryHistory.length === 0 ? (
									<div style={{ textAlign: 'center', padding: '40px', color: 'var(--text-secondary)' }}>
										<History size={48} style={{ opacity: 0.3, marginBottom: '16px' }} />
										<p>No history available for this entry.</p>
										<p style={{ fontSize: '13px', marginTop: '8px' }}>History is saved when you edit an entry.</p>
									</div>
								) : (
									<>
										<div style={{ marginBottom: '16px', fontSize: '14px', color: 'var(--text-secondary)' }}>
											{entryHistory.length} previous version{entryHistory.length !== 1 ? 's' : ''} available
										</div>
										<div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
											{/* Current version */}
											<div
												style={{
													padding: '16px',
													background: 'var(--bg-secondary)',
													border: '2px solid var(--accent-color)',
													borderRadius: '8px',
												}}>
												<div
													style={{
														display: 'flex',
														justifyContent: 'space-between',
														alignItems: 'center',
														marginBottom: '12px',
													}}>
													<div>
														<div style={{ fontWeight: '600', color: 'var(--text-primary)' }}>Current Version</div>
														<div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '4px' }}>
															{formatDate(entryForHistory.created_at)}
														</div>
													</div>
													<div
														style={{
															padding: '4px 8px',
															background: 'var(--accent-color)',
															color: 'white',
															borderRadius: '4px',
															fontSize: '11px',
															fontWeight: '600',
														}}>
														CURRENT
													</div>
												</div>
												<div style={{ fontSize: '13px', color: 'var(--text-primary)' }}>
													<div>
														<strong>Service:</strong> {entryForHistory.name}
													</div>
													<div style={{ marginTop: '4px' }}>
														<strong>Username:</strong> {entryForHistory.username || 'None'}
													</div>
													<div style={{ marginTop: '4px' }}>
														<strong>Password:</strong> <span className='password-mask'>••••••••</span>
													</div>
													<div style={{ marginTop: '4px' }}>
														<strong>Category:</strong>{' '}
														{DEFAULT_CATEGORIES.find(cat => cat.id === entryForHistory.category)?.name ||
															entryForHistory.category}
													</div>
												</div>
											</div>

											{/* History versions */}
											{entryHistory.map((historyItem, index) => (
												<div
													key={historyItem.id}
													style={{
														padding: '16px',
														background: 'var(--bg-secondary)',
														border: '1px solid var(--border-color)',
														borderRadius: '8px',
													}}>
													<div
														style={{
															display: 'flex',
															justifyContent: 'space-between',
															alignItems: 'center',
															marginBottom: '12px',
														}}>
														<div>
															<div style={{ fontWeight: '600', color: 'var(--text-primary)' }}>
																Version {entryHistory.length - index}
															</div>
															<div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '4px' }}>
																{formatDate(historyItem.created_at)}
															</div>
														</div>
														<button
															onClick={() => handleRollback(historyItem.id)}
															disabled={isRollingBack}
															style={{
																display: 'flex',
																alignItems: 'center',
																gap: '6px',
																padding: '6px 12px',
																background: 'var(--accent-color)',
																color: 'white',
																border: 'none',
																borderRadius: '4px',
																fontSize: '12px',
																fontWeight: '500',
																cursor: isRollingBack ? 'not-allowed' : 'pointer',
																opacity: isRollingBack ? 0.6 : 1,
															}}
															title='Restore this version'>
															<RotateCcw size={14} />
															Restore
														</button>
													</div>
													<div style={{ fontSize: '13px', color: 'var(--text-primary)' }}>
														<div>
															<strong>Service:</strong> {historyItem.name}
														</div>
														<div style={{ marginTop: '4px' }}>
															<strong>Username:</strong> {historyItem.username || 'None'}
														</div>
														<div style={{ marginTop: '4px' }}>
															<strong>Password:</strong> <span className='password-mask'>••••••••</span>
														</div>
														<div style={{ marginTop: '4px' }}>
															<strong>Category:</strong>{' '}
															{DEFAULT_CATEGORIES.find(cat => cat.id === historyItem.category)?.name ||
																historyItem.category}
														</div>
													</div>
												</div>
											))}
										</div>
									</>
								)}
							</div>
						</div>
					</div>
				)}

				{/* Bulk Delete Confirmation Modal */}
				{showBulkDeleteModal && (
					<div className='modal-overlay' onClick={() => setShowBulkDeleteModal(false)}>
						<div className='delete-modal' onClick={e => e.stopPropagation()}>
							<div className='modal-header'>
								<h3>Delete Selected Entries</h3>
								<button className='modal-close' onClick={() => setShowBulkDeleteModal(false)} title='Close'>
									×
								</button>
							</div>
							<div className='delete-content'>
								<div className='delete-icon'>
									<Trash2 size={48} />
								</div>
								<p className='delete-message'>
									Are you sure you want to delete {selectedEntries.size} selected entr
									{selectedEntries.size === 1 ? 'y' : 'ies'}? This action cannot be undone.
								</p>
								<div className='delete-actions'>
									<button
										className='delete-cancel'
										onClick={() => setShowBulkDeleteModal(false)}
										disabled={isBulkDeleting}>
										Cancel
									</button>
									<button className='delete-confirm' onClick={handleBulkDelete} disabled={isBulkDeleting}>
										{isBulkDeleting ? 'Deleting...' : 'Delete'}
									</button>
								</div>
							</div>
						</div>
					</div>
				)}

				{/* Bulk Edit Modal */}
				{showBulkEditModal && (
					<div className='modal-overlay' onClick={() => setShowBulkEditModal(false)}>
						<div className='category-modal' onClick={e => e.stopPropagation()} style={{ maxWidth: '500px' }}>
							<div className='modal-header'>
								<h3>
									Bulk Edit: {selectedEntries.size} Entr{selectedEntries.size === 1 ? 'y' : 'ies'}
								</h3>
								<button className='modal-close' onClick={() => setShowBulkEditModal(false)} title='Close'>
									×
								</button>
							</div>
							{isBulkEditing && (
								<div className='loading-indicator'>
									<div className='spinner'></div>
									<span>Updating entries...</span>
								</div>
							)}
							<div style={{ padding: '20px' }}>
								<p style={{ marginBottom: '16px', color: 'var(--text-secondary)', fontSize: '14px' }}>
									Update category for {selectedEntries.size} selected entr{selectedEntries.size === 1 ? 'y' : 'ies'}.
								</p>
								<div className='form-row'>
									<button
										type='button'
										className='category-selector-button'
										onClick={() => setShowCategoryModal(true)}
										disabled={isBulkEditing}>
										{renderCategoryIcon(
											DEFAULT_CATEGORIES.find(cat => cat.id === bulkEditForm.category)?.icon || 'Key',
											16
										)}
										<span>
											{DEFAULT_CATEGORIES.find(cat => cat.id === bulkEditForm.category)?.name || 'Select Category'}
										</span>
										<span className='selector-arrow'>▼</span>
									</button>
								</div>
								<div className='form-actions' style={{ display: 'flex', gap: '10px', marginTop: '20px' }}>
									<button
										type='button'
										className='delete-cancel'
										onClick={() => setShowBulkEditModal(false)}
										disabled={isBulkEditing}>
										Cancel
									</button>
									<button type='button' className='submit-button' onClick={handleBulkEdit} disabled={isBulkEditing}>
										{isBulkEditing ? 'Updating...' : 'Update Entries'}
									</button>
								</div>
							</div>
						</div>
					</div>
				)}

				{/* Entries List */}
				<div className='entries-section'>
					<div className='entries-header'>
						{/* Bulk Mode Toggle */}
						<button
							className='category-filter-button'
							onClick={toggleBulkMode}
							style={{
								background: bulkMode ? 'var(--accent-color)' : 'var(--bg-primary)',
								color: bulkMode ? 'white' : 'var(--text-primary)',
							}}>
							{bulkMode ? (
								<>
									<Check size={16} />
									<span>Bulk Mode ({selectedEntries.size} selected)</span>
								</>
							) : (
								<>
									<Check size={16} />
									<span>Select Multiple</span>
								</>
							)}
						</button>

						{/* Bulk Actions (shown when in bulk mode with selections) */}
						{bulkMode && selectedEntries.size > 0 && (
							<div style={{ display: 'flex', gap: '8px' }}>
								<button
									className='category-filter-button'
									onClick={() => setShowBulkEditModal(true)}
									style={{ background: 'var(--bg-primary)' }}>
									<Edit2 size={16} />
									<span>Edit ({selectedEntries.size})</span>
								</button>
								<button
									className='category-filter-button'
									onClick={() => setShowBulkDeleteModal(true)}
									style={{ background: '#dc2626', color: 'white' }}>
									<Trash2 size={16} />
									<span>Delete ({selectedEntries.size})</span>
								</button>
							</div>
						)}

						{/* Category Filter */}
						<button className='category-filter-button' onClick={() => setShowFilterModal(true)}>
							{selectedCategory === 'all' ? (
								<>
									<Search size={16} />
									<span>All Categories</span>
								</>
							) : (
								<>
									{renderCategoryIcon(DEFAULT_CATEGORIES.find(cat => cat.id === selectedCategory)?.icon || 'Key', 16)}
									<span>{DEFAULT_CATEGORIES.find(cat => cat.id === selectedCategory)?.name || 'Category'}</span>
								</>
							)}
							<span className='filter-arrow'>▼</span>
						</button>

						{/* Search Bar */}
						<div className='search-container'>
							<input
								type='text'
								placeholder='Search by service or username...'
								value={searchQuery}
								onChange={e => setSearchQuery(e.target.value)}
								className='search-input'
							/>
							{searchQuery && (
								<button onClick={() => setSearchQuery('')} className='search-clear' title='Clear search'>
									×
								</button>
							)}
						</div>
					</div>
					{isLoading ? (
						<div className='loading-indicator'>
							<div className='spinner'></div>
							<span>Decrypting passwords... This may take a few seconds.</span>
						</div>
					) : entries.length === 0 ? (
						<div className='no-entries'>No passwords saved yet. Add your first entry above!</div>
					) : (
						<>
							{/* Search Results Info */}
							{searchQuery && (
								<div className='search-results-info'>
									<span>
										Found {filteredEntries.length} of {entries.length} entries
									</span>
								</div>
							)}
							{/* Select All (shown in bulk mode) */}
							{bulkMode && filteredEntries.length > 0 && (
								<div
									style={{
										padding: '12px 16px',
										borderBottom: '1px solid var(--border-color)',
										display: 'flex',
										alignItems: 'center',
										gap: '12px',
									}}>
									<input
										type='checkbox'
										checked={selectedEntries.size === filteredEntries.length && filteredEntries.length > 0}
										onChange={selectAllEntries}
										style={{ width: '18px', height: '18px', cursor: 'pointer' }}
									/>
									<span style={{ fontSize: '14px', color: 'var(--text-secondary)' }}>
										Select All ({filteredEntries.length} entries)
									</span>
								</div>
							)}
							<div className='entries-list'>
								{filteredEntries.map(entry => {
									const category =
										DEFAULT_CATEGORIES.find(cat => cat.id === entry.category) ||
										DEFAULT_CATEGORIES[DEFAULT_CATEGORIES.length - 1];
									return (
										<div key={entry.id} className='entry-card' style={{ position: 'relative' }}>
											{/* Bulk selection checkbox */}
											{bulkMode && (
												<div
													style={{
														position: 'absolute',
														top: '12px',
														left: '12px',
														zIndex: 10,
														background: 'var(--bg-primary)',
														borderRadius: '4px',
														padding: '4px',
													}}>
													<input
														type='checkbox'
														checked={selectedEntries.has(entry.id)}
														onChange={() => toggleEntrySelection(entry.id)}
														style={{ width: '18px', height: '18px', cursor: 'pointer' }}
													/>
												</div>
											)}
											<div className='entry-header' style={{ paddingLeft: bulkMode ? '40px' : '0' }}>
												<div className='entry-name'>{entry.name}</div>
												<div
													className='category-badge'
													style={{ backgroundColor: category.color }}
													title={category.name}>
													{renderCategoryIcon(category.icon, 16)}
												</div>
											</div>
											<div className='entry-username'>
												{entry.username || 'No username'}
												<button
													onClick={() => copyToClipboard(entry.username || '', 'Username', `username-${entry.id}`)}
													className='copy-button'
													title='Copy username'>
													{copiedItem === `username-${entry.id}` ? <Check size={16} /> : <Copy size={16} />}
												</button>
											</div>
											<div className='entry-password'>
												<span className='password-mask'>••••••••</span>
												<button
													onClick={() => copyToClipboard(entry.password, 'Password', `password-${entry.id}`)}
													className='copy-button'
													title='Copy password'>
													{copiedItem === `password-${entry.id}` ? <Check size={16} /> : <Copy size={16} />}
												</button>
											</div>
											<div className='entry-date'>{formatDate(entry.created_at)}</div>
											<div className='entry-actions'>
												{!bulkMode && (
													<>
														<button
															onClick={() => handleHistoryClick(entry)}
															className='history-button'
															title='View entry history'>
															<History size={16} />
														</button>
														<button
															onClick={() => handleDeleteClick(entry.id)}
															className='delete-button'
															title='Delete this entry'>
															<Trash2 size={16} />
														</button>
													</>
												)}
												<button
													onClick={() => handleEditClick(entry)}
													className='edit-button'
													title='Edit this entry'
													style={bulkMode ? { opacity: 0.7 } : {}}>
													<Edit2 size={16} />
												</button>
											</div>
										</div>
									);
								})}
							</div>
						</>
					)}
				</div>
			</div>
		</div>
	);
};

export default VaultScreen;
