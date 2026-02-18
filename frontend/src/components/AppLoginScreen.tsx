import React, { useState } from 'react';
import './LoginScreen.css';

type Props = {
	onLogin: () => void;
};

const AppLoginScreen: React.FC<Props> = ({ onLogin }) => {
	const [username, setUsername] = useState('');
	const [password, setPassword] = useState('');
	const [isValidating, setIsValidating] = useState(false);
	const [error, setError] = useState('');

	const handleSubmit = async (e: React.FormEvent) => {
		e.preventDefault();

		if (!username.trim()) {
			setError('Please enter your username');
			return;
		}

		if (!password) {
			setError('Please enter your password');
			return;
		}

		setIsValidating(true);
		setError('');

		try {
			if (!window.vault || typeof window.vault.verifyAppLogin !== 'function') {
				setError('App not ready. Please restart.');
				return;
			}
			const isValid = await window.vault.verifyAppLogin(username.trim(), password);

			if (isValid) {
				onLogin();
			} else {
				setError('Incorrect username or password.');
			}
		} catch (err) {
			const msg = err instanceof Error ? err.message : 'Login failed';
			setError(msg);
		} finally {
			setIsValidating(false);
		}
	};

	return (
		<div className='login-container'>
			<div className='login-card'>
				<h1 className='login-title'>Password Manager</h1>
				<p style={{ textAlign: 'center', color: 'var(--text-secondary)', fontSize: '14px', marginBottom: '24px' }}>
					Sign in to continue
				</p>

				<form onSubmit={handleSubmit} className='login-form'>
					<div className='form-group'>
						<input
							type='text'
							placeholder='Username'
							value={username}
							onChange={e => {
								setUsername(e.target.value);
								if (error) setError('');
							}}
							className='login-input'
							disabled={isValidating}
							autoComplete='username'
						/>
					</div>
					<div className='form-group'>
						<input
							type='password'
							placeholder='Password'
							value={password}
							onChange={e => {
								setPassword(e.target.value);
								if (error) setError('');
							}}
							className='login-input'
							disabled={isValidating}
							autoComplete='current-password'
						/>
					</div>

					{error && <div className='error-message'>{error}</div>}

					<button type='submit' className='login-button' disabled={isValidating}>
						{isValidating ? 'Signing in...' : 'Sign In'}
					</button>
				</form>
			</div>
		</div>
	);
};

export default AppLoginScreen;
