import React, { useState } from 'react';
import './LoginScreen.css';

type Props = {
	onLogin: (masterPassword: string) => void;
};

const LoginScreen: React.FC<Props> = ({ onLogin }) => {
	const [password, setPassword] = useState('');
	const [isValidating, setIsValidating] = useState(false);
	const [error, setError] = useState('');
	const [showForgotPassword, setShowForgotPassword] = useState(false); // Forgot password modal
	const [recoveryMethod, setRecoveryMethod] = useState<'email_sms' | null>(null); // Recovery method selected
	const [recoveryCode, setRecoveryCode] = useState(''); // Email/SMS recovery code
	const [verifiedRecoveryCode, setVerifiedRecoveryCode] = useState<string | null>(null); // Verified recovery code (stored after verification)
	const [recoveryEmail, setRecoveryEmail] = useState(''); // Email for recovery
	const [recoveryPhone, setRecoveryPhone] = useState(''); // Phone for recovery
	const [isGeneratingCode, setIsGeneratingCode] = useState(false); // Generating recovery code
	const [generatedCode, setGeneratedCode] = useState<string | null>(null); // Generated code (for dev)
	const [isVerifyingRecovery, setIsVerifyingRecovery] = useState(false); // Verifying recovery
	const [recoveryVerified, setRecoveryVerified] = useState(false); // Recovery verified
	const [newPassword, setNewPassword] = useState(''); // New password for reset
	const [confirmNewPassword, setConfirmNewPassword] = useState(''); // Confirm new password
	const [isResettingPassword, setIsResettingPassword] = useState(false); // Resetting password

	const handleSubmit = async (e: React.FormEvent) => {
		e.preventDefault();

		// Enhanced password validation
		if (password.length < 12) {
			setError('Master password must be at least 12 characters long');
			return;
		}

		if (!/[A-Z]/.test(password)) {
			setError('Master password must contain at least one uppercase letter');
			return;
		}

		if (!/[a-z]/.test(password)) {
			setError('Master password must contain at least one lowercase letter');
			return;
		}

		if (!/\d/.test(password)) {
			setError('Master password must contain at least one number');
			return;
		}

		if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
			setError('Master password must contain at least one special character');
			return;
		}

		setIsValidating(true);
		setError('');

		try {
			// Test the master password
			const isValid = await window.vault.testMasterPassword(password);

			if (isValid) {
				onLogin(password);
			} else {
				setError('Incorrect master password. Please try again.');
			}
		} catch (error) {
			console.error('[LoginScreen] Error validating password:', error);
			const errorMessage = error instanceof Error ? error.message : 'Unknown error';
			setError(errorMessage);
		} finally {
			setIsValidating(false);
		}
	};

	return (
		<div className='login-container'>
			<div className='login-card'>
				<h1 className='login-title'>Password Manager</h1>

				<form onSubmit={handleSubmit} className='login-form'>
					<div className='form-group'>
						<input
							type='password'
							placeholder='Master password'
							value={password}
							onChange={e => {
								setPassword(e.target.value);
								if (error) setError('');
							}}
							className='login-input'
							disabled={isValidating}
						/>
					</div>

					{error && <div className='error-message'>{error}</div>}

					<div style={{ display: 'flex', gap: '10px', flexDirection: 'column' }}>
						<button type='submit' className='login-button' disabled={isValidating}>
							{isValidating ? 'Validating...' : 'Unlock'}
						</button>
						<button
							type='button'
							onClick={async () => {
								setShowForgotPassword(true);
								setRecoveryMethod(null);
								setRecoveryVerified(false);
							}}
							disabled={isValidating}
							style={{
								padding: '10px',
								background: 'transparent',
								border: '1px solid var(--border-color)',
								borderRadius: '8px',
								color: 'var(--text-secondary)',
								cursor: 'pointer',
								fontSize: '13px',
							}}>
							Forgot Password?
						</button>
					</div>
				</form>
			</div>

			{/* Forgot Password / Recovery Modal */}
			{showForgotPassword && (
				<div className='modal-overlay' onClick={() => !recoveryVerified && setShowForgotPassword(false)}>
					<div className='category-modal' onClick={e => {
						// Only close if clicking directly on the modal background, not on inputs
						if (e.target === e.currentTarget) {
							// Don't close on background click
						}
						e.stopPropagation();
					}} style={{ maxWidth: '600px', pointerEvents: 'auto', position: 'relative', zIndex: 10001 }}>
						<div className='modal-header'>
							<h3>{recoveryVerified ? 'Reset Password' : 'Password Recovery'}</h3>
							{!recoveryVerified && (
								<button className='modal-close' onClick={() => setShowForgotPassword(false)} title='Close'>
									×
								</button>
							)}
						</div>
						<div style={{ padding: '20px' }}>
							{!recoveryVerified ? (
								<>
									{!recoveryMethod ? (
										<>
											<p style={{ marginBottom: '20px', color: 'var(--text-secondary)' }}>
												Choose a recovery method to reset your password:
											</p>
											<button
												type='button'
												onClick={() => setRecoveryMethod('email_sms')}
												className='submit-button'
												style={{ width: '100%', background: '#10b981' }}>
												📧 Email/SMS Recovery (Preserves Data)
											</button>
										</>
									) : (
										<>
											{!generatedCode ? (
												<>
													<p style={{ marginBottom: '20px', color: 'var(--text-secondary)' }}>
														Enter your email or phone number to receive a recovery code:
													</p>
													<input
														type='email'
														placeholder='Email address'
														value={recoveryEmail}
														onChange={e => setRecoveryEmail(e.target.value)}
														className='login-input'
														disabled={isGeneratingCode}
														style={{ marginBottom: '12px', pointerEvents: 'auto' }}
													/>
													<input
														type='tel'
														placeholder='Phone number (optional)'
														value={recoveryPhone}
														onChange={e => setRecoveryPhone(e.target.value)}
														className='login-input'
														disabled={isGeneratingCode}
														style={{ pointerEvents: 'auto' }}
													/>
													{error && <div className='error-message' style={{ marginTop: '12px' }}>{error}</div>}
													<div style={{ display: 'flex', gap: '10px', marginTop: '20px' }}>
														<button
															type='button'
															onClick={() => setRecoveryMethod(null)}
															className='delete-cancel'
															disabled={isGeneratingCode}>
															Back
														</button>
														<button
															type='button'
															onClick={async () => {
																if (!recoveryEmail && !recoveryPhone) {
																	setError('Please enter email or phone number');
																	return;
																}
																if (!window.vault || typeof (window.vault as any).generateRecoveryCode !== 'function') {
																	setError('Recovery code feature not available');
																	return;
																}
																setIsGeneratingCode(true);
																setError('');
																try {
																	const result = await (window.vault as any).generateRecoveryCode(recoveryEmail, recoveryPhone);
																	if (result.success) {
																		// In development, show the code. In production, this would be sent via email/SMS
																		setGeneratedCode(result.code || null);
																		if (result.code) {
																			alert(`Recovery code: ${result.code}\n\nIn production, this would be sent to your email/phone.`);
																		}
																	}
																} catch (error) {
																	setError(error instanceof Error ? error.message : 'Failed to generate recovery code');
																} finally {
																	setIsGeneratingCode(false);
																}
															}}
															disabled={isGeneratingCode || (!recoveryEmail && !recoveryPhone)}
															className='submit-button'>
															{isGeneratingCode ? 'Generating...' : 'Send Code'}
														</button>
													</div>
												</>
											) : (
												<>
													<p style={{ marginBottom: '20px', color: 'var(--text-secondary)' }}>
														Enter the 6-digit code sent to your email/phone:
													</p>
													{error && error.includes('expired') && (
														<div style={{ 
															marginBottom: '16px', 
															padding: '12px', 
															background: 'rgba(239, 68, 68, 0.1)', 
															border: '1px solid #ef4444', 
															borderRadius: '8px',
															fontSize: '13px',
															color: '#ef4444'
														}}>
															<strong>Code Expired:</strong> The recovery code has expired. Please generate a new code.
															<button
																type='button'
																onClick={async () => {
																	setError('');
																	setRecoveryCode('');
																	setVerifiedRecoveryCode(null);
																	setRecoveryVerified(false);
																	setIsGeneratingCode(true);
																	try {
																		if (!window.vault || typeof (window.vault as any).generateRecoveryCode !== 'function') {
																			setError('Recovery code generation not available');
																			return;
																		}
																		const result = await (window.vault as any).generateRecoveryCode(recoveryEmail, recoveryPhone);
																		if (result.success) {
																			setGeneratedCode(result.code);
																			if (result.code) {
																				alert(`New recovery code: ${result.code}\n\nIn production, this would be sent to your email/phone.`);
																			}
																		}
																	} catch (error) {
																		setError(error instanceof Error ? error.message : 'Failed to generate recovery code');
																	} finally {
																		setIsGeneratingCode(false);
																	}
																}}
																style={{
																	marginTop: '8px',
																	padding: '8px 16px',
																	background: '#ef4444',
																	color: 'white',
																	border: 'none',
																	borderRadius: '4px',
																	cursor: 'pointer',
																	fontSize: '13px'
																}}>
																Generate New Code
															</button>
														</div>
													)}
													<input
														type='text'
														inputMode='numeric'
														pattern='[0-9]*'
														placeholder='Recovery Code (6 digits)'
														value={recoveryCode}
														onChange={e => {
															const code = e.target.value.replace(/\D/g, '').slice(0, 6);
															setRecoveryCode(code);
														}}
														onClick={e => {
															e.stopPropagation();
															e.currentTarget.focus();
														}}
														onFocus={e => {
															e.stopPropagation();
														}}
														onKeyDown={e => e.stopPropagation()}
														onKeyUp={e => e.stopPropagation()}
														onInput={e => e.stopPropagation()}
														className='login-input recovery-code-input'
														disabled={isVerifyingRecovery}
														autoFocus
														style={{ 
															fontFamily: 'monospace', 
															textAlign: 'center', 
															letterSpacing: '2px', 
															fontSize: '18px',
															position: 'relative',
															zIndex: 10003,
															width: '100%',
															padding: '12px 16px',
															border: '1px solid var(--border-color)',
															borderRadius: '4px',
															background: 'var(--bg-primary)',
															color: 'var(--text-primary)',
															pointerEvents: 'auto',
															cursor: 'text',
															WebkitUserSelect: 'text',
															userSelect: 'text'
														}}
													/>
													{error && <div className='error-message' style={{ marginTop: '12px' }}>{error}</div>}
													<div style={{ display: 'flex', gap: '10px', marginTop: '20px' }}>
														<button
															type='button'
															onClick={() => {
															setGeneratedCode(null);
															setRecoveryCode('');
															setVerifiedRecoveryCode(null);
															setError('');
														}}
															className='delete-cancel'
															disabled={isVerifyingRecovery}>
															Back
														</button>
														<button
															type='button'
															onClick={async () => {
																if (!window.vault || typeof (window.vault as any).verifyRecoveryCode !== 'function') {
																	setError('Recovery code verification not available');
																	return;
																}
																if (recoveryCode.length !== 6) {
																	setError('Recovery code must be 6 digits');
																	return;
																}
																setIsVerifyingRecovery(true);
																setError('');
																try {
																	const result = await (window.vault as any).verifyRecoveryCode(recoveryCode);
																	if (result.verified) {
																		setRecoveryVerified(true);
																		setVerifiedRecoveryCode(recoveryCode); // Store the verified code
																		console.log('[LoginScreen] Recovery code verified and stored');
																	} else {
																		// Show specific error message
																		const errorMsg = result.error || 'Invalid recovery code';
																		setError(errorMsg);
																		setVerifiedRecoveryCode(null);
																		// If code expired, suggest generating a new one
																		if (errorMsg.includes('expired')) {
																			console.log('[LoginScreen] Recovery code expired, user should generate a new one');
																		}
																	}
																} catch (error) {
																	setError(error instanceof Error ? error.message : 'Verification failed');
																	setVerifiedRecoveryCode(null);
																} finally {
																	setIsVerifyingRecovery(false);
																}
															}}
															disabled={isVerifyingRecovery || recoveryCode.length !== 6}
															className='submit-button'>
															{isVerifyingRecovery ? 'Verifying...' : 'Verify'}
														</button>
													</div>
												</>
											)}
										</>
									)}
								</>
							) : (
								<>
									<div style={{ 
										padding: '16px', 
										background: 'rgba(16, 185, 129, 0.1)', 
										border: '1px solid #10b981', 
										borderRadius: '8px',
										marginBottom: '20px',
										fontSize: '13px',
										color: '#10b981',
										lineHeight: '1.6'
									}}>
										<div style={{ marginBottom: '8px' }}>
											<strong>✅ Email/SMS Recovery:</strong>
										</div>
										<div>
											All your password entries will be <strong>preserved and accessible</strong> after password reset. Your data will be automatically re-encrypted with your new password.
										</div>
									</div>
									<div style={{ marginBottom: '16px' }}>
										<input
											type='password'
											placeholder='New Master Password (required)'
											value={newPassword}
											onChange={e => setNewPassword(e.target.value)}
											className='login-input'
											disabled={isResettingPassword}
											required
										/>
									</div>
									<div style={{ marginBottom: '16px' }}>
										<input
											type='password'
											placeholder='Confirm New Password (required)'
											value={confirmNewPassword}
											onChange={e => setConfirmNewPassword(e.target.value)}
											className='login-input'
											disabled={isResettingPassword}
											required
										/>
										{confirmNewPassword && newPassword !== confirmNewPassword && (
											<span style={{ color: '#ef4444', fontSize: '12px', display: 'block', marginTop: '4px' }}>
												Passwords do not match
											</span>
										)}
									</div>
									{error && <div className='error-message' style={{ marginBottom: '16px' }}>{error}</div>}
									<div style={{ display: 'flex', gap: '10px' }}>
										<button
											type='button'
											onClick={() => {
												setRecoveryVerified(false);
												setNewPassword('');
												setConfirmNewPassword('');
												setError('');
											}}
											className='delete-cancel'
											disabled={isResettingPassword}>
											Back
										</button>
										<button
											type='button'
											onClick={async () => {
												if (newPassword.length < 12) {
													setError('Master password must be at least 12 characters long');
													return;
												}
												if (newPassword !== confirmNewPassword) {
													setError('Passwords do not match');
													return;
												}
												if (!/[A-Z]/.test(newPassword) || !/[a-z]/.test(newPassword) || !/\d/.test(newPassword) || !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(newPassword)) {
													setError('Password must contain uppercase, lowercase, number, and special character');
													return;
												}
												if (!window.vault || typeof (window.vault as any).resetMasterPasswordViaRecovery !== 'function') {
													setError('Password reset feature not available');
													return;
												}
												setIsResettingPassword(true);
												setError('');
												try {
													const codeToUse = verifiedRecoveryCode || recoveryCode;
													if (!codeToUse || codeToUse.length !== 6) {
														setError('Recovery code is required. Please verify your code again.');
														setIsResettingPassword(false);
														return;
													}
													const recoveryData = { code: codeToUse };
													const result = await (window.vault as any).resetMasterPasswordViaRecovery(
														newPassword,
														'email_sms',
														recoveryData
													);
													if (result.success) {
														const message = result.message || result.warning || 'Password reset successful!';
														alert(`${message}\n\nYou can now log in with your new password.`);
														setShowForgotPassword(false);
														setRecoveryVerified(false);
														setNewPassword('');
														setConfirmNewPassword('');
														setRecoveryMethod(null);
														setRecoveryCode('');
														setVerifiedRecoveryCode(null);
														setRecoveryEmail('');
														setRecoveryPhone('');
														setGeneratedCode(null);
													}
												} catch (error) {
													const errorMsg = error instanceof Error ? error.message : 'Password reset failed';
													setError(errorMsg);
													console.error('[LoginScreen] Password reset error:', errorMsg);
													
													// If code expired or invalid, reset verification state to allow generating a new code
													if (errorMsg.includes('expired') || errorMsg.includes('Invalid') || errorMsg.includes('recovery code')) {
														setRecoveryVerified(false);
														setVerifiedRecoveryCode(null);
														setRecoveryCode('');
													}
												} finally {
													setIsResettingPassword(false);
												}
											}}
											disabled={isResettingPassword || newPassword !== confirmNewPassword || newPassword.length < 12}
											className='submit-button'>
											{isResettingPassword ? 'Resetting...' : 'Reset Password'}
										</button>
									</div>
								</>
							)}
						</div>
					</div>
				</div>
			)}
		</div>
	);
};

export default LoginScreen;
