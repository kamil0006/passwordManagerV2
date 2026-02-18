import React, { useState } from 'react';
import './LoginScreen.css';

type Props = {
	onAccountCreated: () => void;
	title?: string;
	subtitle?: string;
};

const CreateAccountScreen: React.FC<Props> = ({ onAccountCreated, title = 'Password Manager', subtitle = 'Create your account' }) => {
	const [username, setUsername] = useState('');
	const [password, setPassword] = useState('');
	const [confirmPassword, setConfirmPassword] = useState('');
	const [isCreating, setIsCreating] = useState(false);
	const [error, setError] = useState('');

	const handleSubmit = async (e: React.FormEvent) => {
		e.preventDefault();

		if (username.trim().length < 3) {
			setError('Username must be at least 3 characters');
			return;
		}

		if (password.length < 8) {
			setError('Password must be at least 8 characters long');
			return;
		}

		if (!/[A-Z]/.test(password)) {
			setError('Password must contain at least one uppercase letter');
			return;
		}

		if (!/[a-z]/.test(password)) {
			setError('Password must contain at least one lowercase letter');
			return;
		}

		if (!/\d/.test(password)) {
			setError('Password must contain at least one number');
			return;
		}

		if (password !== confirmPassword) {
			setError('Passwords do not match');
			return;
		}

		setIsCreating(true);
		setError('');

		try {
			if (!window.vault || typeof window.vault.createAppAccount !== 'function') {
				setError('App not ready. Please restart.');
				return;
			}
			await window.vault.createAppAccount(username.trim(), password);
			onAccountCreated();
		} catch (err) {
			const msg = err instanceof Error ? err.message : 'Failed to create account';
			setError(msg);
		} finally {
			setIsCreating(false);
		}
	};

	return (
		<div className='login-container'>
			<div className='login-card'>
				<h1 className='login-title'>{title}</h1>
				<p style={{ textAlign: 'center', color: 'var(--text-secondary)', fontSize: '14px', marginBottom: '24px' }}>
					{subtitle}
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
							disabled={isCreating}
							autoComplete='username'
						/>
					</div>
					<div className='form-group'>
						<input
							type='password'
							placeholder='Password (min 8 chars, upper, lower, number)'
							value={password}
							onChange={e => {
								setPassword(e.target.value);
								if (error) setError('');
							}}
							className='login-input'
							disabled={isCreating}
							autoComplete='new-password'
						/>
					</div>
					<div className='form-group'>
						<input
							type='password'
							placeholder='Confirm password'
							value={confirmPassword}
							onChange={e => {
								setConfirmPassword(e.target.value);
								if (error) setError('');
							}}
							className='login-input'
							disabled={isCreating}
							autoComplete='new-password'
						/>
					</div>

					{error && <div className='error-message'>{error}</div>}

					<button type='submit' className='login-button' disabled={isCreating}>
						{isCreating ? 'Creating...' : 'Create Account'}
					</button>
				</form>
			</div>
		</div>
	);
};

export default CreateAccountScreen;
