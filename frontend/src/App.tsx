import { useState, useEffect } from 'react';
import { ThemeProvider } from './contexts/ThemeContext';
import CreateAccountScreen from './components/CreateAccountScreen';
import AppLoginScreen from './components/AppLoginScreen';
import MasterPasswordScreen from './components/MasterPasswordScreen';
import VaultScreen from './components/VaultScreen';

function App() {
	const [hasAppAccount, setHasAppAccount] = useState<boolean | null>(null);
	const [isMasterPasswordSet, setIsMasterPasswordSet] = useState<boolean | null>(null);
	const [appLoggedIn, setAppLoggedIn] = useState(false);
	const [masterPassword, setMasterPassword] = useState<string | null>(null);
	const [pendingCreateAccountAfterRestore, setPendingCreateAccountAfterRestore] = useState(false);

	useEffect(() => {
		const load = async () => {
			try {
				if (window.vault?.hasAppAccount && window.vault?.isMasterPasswordSet) {
					const [hasAccount, masterSet] = await Promise.all([
						window.vault.hasAppAccount(),
						window.vault.isMasterPasswordSet(),
					]);
					setHasAppAccount(hasAccount);
					setIsMasterPasswordSet(masterSet);
				} else {
					setHasAppAccount(false);
					setIsMasterPasswordSet(false);
				}
			} catch (err) {
				console.error('[App] Error loading state:', err);
				setHasAppAccount(false);
				setIsMasterPasswordSet(false);
			}
		};
		load();
	}, []);

	const handleAutoLock = () => {
		console.log('[App] Auto-lock triggered, returning to master password screen');
		setMasterPassword(null);
	};

	// Still loading
	if (hasAppAccount === null || isMasterPasswordSet === null) {
		return (
			<ThemeProvider>
				<div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--bg-secondary)' }}>
					<span style={{ color: 'var(--text-secondary)' }}>Loading...</span>
				</div>
			</ThemeProvider>
		);
	}

	// 1a. Restore: unlocked with master password, now need to create app account
	if (pendingCreateAccountAfterRestore && masterPassword) {
		return (
			<ThemeProvider>
				<CreateAccountScreen
					onAccountCreated={() => {
						setHasAppAccount(true);
						setAppLoggedIn(true);
						setPendingCreateAccountAfterRestore(false);
					}}
					title="Password Manager"
					subtitle="Backup restored. Set up your app login (username + password) for future access."
				/>
			</ThemeProvider>
		);
	}

	// 1b. No app account
	if (!hasAppAccount) {
		// Legacy backup: has vault data (master password set) but no app credentials
		// → Ask for master password first, then create app account
		if (isMasterPasswordSet) {
			return (
				<ThemeProvider>
					<MasterPasswordScreen
						onLogin={(pwd) => {
							setMasterPassword(pwd);
							setPendingCreateAccountAfterRestore(true);
						}}
						isMasterPasswordSet={true}
						restoreMode={true}
					/>
				</ThemeProvider>
			);
		}
		// Fresh install: create account first
		return (
			<ThemeProvider>
				<CreateAccountScreen onAccountCreated={() => { setHasAppAccount(true); setAppLoggedIn(true); }} />
			</ThemeProvider>
		);
	}

	// 2. Has account but not logged in → App login (username + password)
	if (!appLoggedIn) {
		return (
			<ThemeProvider>
				<AppLoginScreen onLogin={() => setAppLoggedIn(true)} />
			</ThemeProvider>
		);
	}

	// 3. Logged in but no master password entered → Master password (set or enter)
	if (!masterPassword) {
		return (
			<ThemeProvider>
				<MasterPasswordScreen
					onLogin={setMasterPassword}
					isMasterPasswordSet={isMasterPasswordSet ?? false}
				/>
			</ThemeProvider>
		);
	}

	// 4. Full access → Vault
	return (
		<ThemeProvider>
			<VaultScreen masterPassword={masterPassword} onAutoLock={handleAutoLock} />
		</ThemeProvider>
	);
}

export default App;
