import { useState } from 'react';
import { ThemeProvider } from './contexts/ThemeContext';
import LoginScreen from './components/LoginScreen';
import VaultScreen from './components/VaultScreen';

function App() {
	const [masterPassword, setMasterPassword] = useState<string | null>(null);

	const handleAutoLock = () => {
		console.log('[App] Auto-lock triggered, returning to login screen');
		setMasterPassword(null);
	};

	return (
		<ThemeProvider>
			{!masterPassword ? (
				<LoginScreen onLogin={setMasterPassword} />
			) : (
				<VaultScreen masterPassword={masterPassword} onAutoLock={handleAutoLock} />
			)}
		</ThemeProvider>
	);
}

export default App;
