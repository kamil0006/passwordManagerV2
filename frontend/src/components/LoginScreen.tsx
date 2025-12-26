import React, { useState } from 'react';
import './LoginScreen.css';

type Props = {
	onLogin: (masterPassword: string) => void;
};

const LoginScreen: React.FC<Props> = ({ onLogin }) => {
	const [password, setPassword] = useState('');
	const [isValidating, setIsValidating] = useState(false);
	const [error, setError] = useState('');
	const [showHint, setShowHint] = useState(false);
	const [hint, setHint] = useState<string | null>(null);
	const [isLoadingHint, setIsLoadingHint] = useState(false);
	const [hintError, setHintError] = useState<string | null>(null);
	const [showForgotPassword, setShowForgotPassword] = useState(false); // Forgot password modal
	const [recoveryMethod, setRecoveryMethod] = useState<'questions' | 'backup_code' | 'email_sms' | null>(null); // Recovery method selected
	const [recoveryQuestions, setRecoveryQuestions] = useState<Array<{ number: number; question: string }>>([]); // Recovery questions
	const [recoveryAnswers, setRecoveryAnswers] = useState<string[]>([]); // Answers to recovery questions
	const [backupCode, setBackupCode] = useState(''); // Backup code input
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

	const handleShowHint = async () => {
		if (!password || password.length < 12) {
			setError('Please enter at least 12 characters of your password to view the hint');
			return;
		}

		setIsLoadingHint(true);
		setError('');
		setHintError(null);

		try {
			if (!window.vault || typeof window.vault.getPasswordHint !== 'function') {
				setError('Password hint feature not available');
				return;
			}

			const result = await window.vault.getPasswordHint(password);
			
			if (!result) {
				setHintError('Could not retrieve password hint.');
				return;
			}

			if (result.error === 'decryption_failed') {
				// Don't reveal if hint exists or not - same error for both cases
				setHintError('Could not decrypt hint. The password you entered may be incorrect, or no hint is set for this vault.');
				return;
			}

			if (result.hint) {
				setHint(result.hint);
				setShowHint(true);
				setHintError(null);
			} else {
				setHintError('Could not retrieve password hint.');
			}
		} catch (error) {
			console.error('[LoginScreen] Error getting password hint:', error);
			setHintError('Could not retrieve password hint. The password you entered may be incorrect.');
		} finally {
			setIsLoadingHint(false);
		}
	};

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
								if (error) setError(''); // Clear error when user types
								if (showHint) {
									setShowHint(false);
									setHint(null);
								}
							}}
							className='login-input'
							disabled={isValidating}
						/>
					</div>

					{showHint && hint && (
						<div style={{ 
							marginBottom: '16px', 
							padding: '12px', 
							background: 'var(--bg-secondary)', 
							border: '1px solid var(--border-color)', 
							borderRadius: '8px',
							fontSize: '14px',
							color: 'var(--text-primary)'
						}}>
							<div style={{ fontWeight: '600', marginBottom: '4px', color: 'var(--accent-color)' }}>Password Hint:</div>
							<div>{hint}</div>
						</div>
					)}

					{hintError && (
						<div style={{ 
							marginBottom: '16px', 
							padding: '12px', 
							background: 'rgba(239, 68, 68, 0.1)', 
							border: '1px solid #ef4444', 
							borderRadius: '8px',
							fontSize: '13px',
							color: '#ef4444'
						}}>
							{hintError}
						</div>
					)}

					{error && <div className='error-message'>{error}</div>}

					<div style={{ display: 'flex', gap: '10px', flexDirection: 'column' }}>
						<button type='submit' className='login-button' disabled={isValidating}>
							{isValidating ? 'Validating...' : 'Unlock'}
						</button>
						<button
							type='button'
							onClick={handleShowHint}
							disabled={isValidating || isLoadingHint || password.length < 12}
							style={{
								padding: '10px',
								background: 'transparent',
								border: '1px solid var(--border-color)',
								borderRadius: '8px',
								color: 'var(--text-secondary)',
								cursor: password.length < 12 ? 'not-allowed' : 'pointer',
								opacity: password.length < 12 ? 0.5 : 1,
								fontSize: '13px',
							}}
							title={password.length < 12 ? 'Enter at least 12 characters to view hint' : 'Show password hint'}>
							{isLoadingHint ? 'Loading...' : 'Show Password Hint'}
						</button>
						<button
							type='button'
							onClick={async () => {
								setShowForgotPassword(true);
								setRecoveryMethod(null);
								setRecoveryVerified(false);
								// Load recovery questions if available
								if (window.vault && typeof window.vault.getRecoveryQuestions === 'function') {
									try {
										const questions = await window.vault.getRecoveryQuestions();
										setRecoveryQuestions(questions);
										setRecoveryAnswers(new Array(questions.length).fill(''));
									} catch (error) {
										console.error('[LoginScreen] Error loading recovery questions:', error);
									}
								}
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
											<div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
												<button
													type='button'
													onClick={() => setRecoveryMethod('email_sms')}
													className='submit-button'
													style={{ width: '100%', background: '#10b981' }}>
													📧 Email/SMS Recovery (Preserves Data)
												</button>
												{recoveryQuestions.length > 0 && (
													<button
														type='button'
														onClick={() => setRecoveryMethod('questions')}
														className='submit-button'
														style={{ width: '100%' }}>
														Use Security Questions ({recoveryQuestions.length} questions)
													</button>
												)}
												<button
													type='button'
													onClick={() => setRecoveryMethod('backup_code')}
													className='submit-button'
													style={{ width: '100%' }}>
													Use Backup Code
												</button>
											</div>
										</>
									) : recoveryMethod === 'questions' ? (
										<>
											<p style={{ marginBottom: '20px', color: 'var(--text-secondary)' }}>
												Answer your security questions:
											</p>
											{recoveryQuestions.map((q, index) => (
												<div key={q.number} style={{ marginBottom: '16px' }}>
													<label style={{ display: 'block', marginBottom: '8px', color: 'var(--text-primary)' }}>
														{q.question}
													</label>
													<input
														type='password'
														placeholder='Your answer'
														value={recoveryAnswers[index] || ''}
														onChange={e => {
															const newAnswers = [...recoveryAnswers];
															newAnswers[index] = e.target.value;
															setRecoveryAnswers(newAnswers);
														}}
														className='login-input'
														disabled={isVerifyingRecovery}
													/>
												</div>
											))}
											<div style={{ display: 'flex', gap: '10px', marginTop: '20px' }}>
												<button
													type='button'
													onClick={() => setRecoveryMethod(null)}
													className='delete-cancel'
													disabled={isVerifyingRecovery}>
													Back
												</button>
												<button
													type='button'
													onClick={async () => {
														if (!window.vault || typeof window.vault.verifyRecoveryQuestions !== 'function') {
															setError('Recovery feature not available');
															return;
														}
														setIsVerifyingRecovery(true);
														setError('');
														try {
															const result = await window.vault.verifyRecoveryQuestions(recoveryAnswers);
															if (result.verified) {
																setRecoveryVerified(true);
															} else {
																setError(result.error || 'Verification failed');
															}
														} catch (error) {
															setError(error instanceof Error ? error.message : 'Verification failed');
														} finally {
															setIsVerifyingRecovery(false);
														}
													}}
													disabled={isVerifyingRecovery || recoveryAnswers.some(a => !a.trim())}
													className='submit-button'>
													{isVerifyingRecovery ? 'Verifying...' : 'Verify'}
												</button>
											</div>
										</>
									) : recoveryMethod === 'email_sms' ? (
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
									) : (
										<>
											<p style={{ marginBottom: '20px', color: 'var(--text-secondary)' }}>
												Enter your backup code:
											</p>
											<input
												type='text'
												placeholder='Backup Code (8 characters)'
												value={backupCode}
												onChange={e => {
													const code = e.target.value.toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 8);
													setBackupCode(code);
												}}
												className='login-input'
												disabled={isVerifyingRecovery}
												style={{ fontFamily: 'monospace', textAlign: 'center', letterSpacing: '2px', pointerEvents: 'auto' }}
											/>
											{error && <div className='error-message' style={{ marginTop: '12px' }}>{error}</div>}
											<div style={{ display: 'flex', gap: '10px', marginTop: '20px' }}>
												<button
													type='button'
													onClick={() => setRecoveryMethod(null)}
													className='delete-cancel'
													disabled={isVerifyingRecovery}>
													Back
												</button>
												<button
													type='button'
													onClick={async () => {
														if (!window.vault || typeof window.vault.verifyBackupCode !== 'function') {
															setError('Backup code feature not available');
															return;
														}
														if (backupCode.length !== 8) {
															setError('Backup code must be 8 characters');
															return;
														}
														setIsVerifyingRecovery(true);
														setError('');
														try {
															const result = await window.vault.verifyBackupCode(backupCode);
															if (result.verified) {
																setRecoveryVerified(true);
															} else {
																setError(result.error || 'Invalid backup code');
															}
														} catch (error) {
															setError(error instanceof Error ? error.message : 'Verification failed');
														} finally {
															setIsVerifyingRecovery(false);
														}
													}}
													disabled={isVerifyingRecovery || backupCode.length !== 8}
													className='submit-button'>
													{isVerifyingRecovery ? 'Verifying...' : 'Verify'}
												</button>
											</div>
										</>
									)}
								</>
							) : (
								<>
									{recoveryMethod === 'email_sms' ? (
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
									) : (
										<div style={{ 
											padding: '16px', 
											background: 'rgba(239, 68, 68, 0.1)', 
											border: '1px solid #ef4444', 
											borderRadius: '8px',
											marginBottom: '20px',
											fontSize: '13px',
											color: '#ef4444',
											lineHeight: '1.6'
										}}>
											<div style={{ marginBottom: '8px' }}>
												<strong>⚠️ Important Warning:</strong>
											</div>
											<div style={{ marginBottom: '8px' }}>
												When you reset your master password using this method, <strong>all your existing password entries will become permanently encrypted and unreadable</strong> because they were encrypted with your old password.
											</div>
											<div style={{ marginBottom: '8px' }}>
												<strong>What this means:</strong>
											</div>
											<ul style={{ marginLeft: '20px', marginTop: '8px', marginBottom: '8px' }}>
												<li>You will <strong>not be able to view or decrypt</strong> any of your saved passwords</li>
												<li>You will need to <strong>manually delete all entries</strong> and recreate them with your new password</li>
												<li>This is a <strong>one-way operation</strong> - there is no way to recover the old data</li>
											</ul>
											<div style={{ marginTop: '8px', fontStyle: 'italic' }}>
												<strong>Better option:</strong> Use Email/SMS Recovery to preserve all your data, or if you remember your old password, use "Change Password" from the menu after logging in.
											</div>
										</div>
									)}
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
													let recoveryData;
													if (recoveryMethod === 'questions') {
														recoveryData = { answers: recoveryAnswers, verified: true };
													} else if (recoveryMethod === 'backup_code') {
														if (!backupCode || backupCode.length !== 8) {
															setError('Backup code is required');
															setIsResettingPassword(false);
															return;
														}
														recoveryData = { code: backupCode };
													} else if (recoveryMethod === 'email_sms') {
														// Use verified code if available, otherwise fall back to current recoveryCode
														const codeToUse = verifiedRecoveryCode || recoveryCode;
														if (!codeToUse || codeToUse.length !== 6) {
															setError('Recovery code is required. Please verify your code again.');
															setIsResettingPassword(false);
															return;
														}
														console.log('[LoginScreen] Resetting password with recovery code:', codeToUse.substring(0, 2) + '****');
														recoveryData = { code: codeToUse };
													} else {
														setError('Invalid recovery method');
														setIsResettingPassword(false);
														return;
													}
													console.log('[LoginScreen] Calling resetMasterPasswordViaRecovery with method:', recoveryMethod);
													const result = await (window.vault as any).resetMasterPasswordViaRecovery(
														newPassword,
														recoveryMethod!,
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
														setBackupCode('');
														setRecoveryCode('');
														setVerifiedRecoveryCode(null);
														setRecoveryEmail('');
														setRecoveryPhone('');
														setGeneratedCode(null);
														setRecoveryAnswers([]);
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
