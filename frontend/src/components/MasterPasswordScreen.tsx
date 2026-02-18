import React, { useState } from 'react';
import './LoginScreen.css';

type Props = {
	onLogin: (masterPassword: string) => void;
	isMasterPasswordSet: boolean;
	restoreMode?: boolean;
};

const MasterPasswordScreen: React.FC<Props> = ({ onLogin, isMasterPasswordSet, restoreMode }) => {
	const [password, setPassword] = useState('');
	const [confirmPassword, setConfirmPassword] = useState('');
	const [isValidating, setIsValidating] = useState(false);
	const [error, setError] = useState('');
	const [showForgotPassword, setShowForgotPassword] = useState(false);
	const [recoveryMethod, setRecoveryMethod] = useState<'email_sms' | null>(null);
	const [recoveryCode, setRecoveryCode] = useState('');
	const [verifiedRecoveryCode, setVerifiedRecoveryCode] = useState<string | null>(null);
	const [recoveryEmail, setRecoveryEmail] = useState('');
	const [recoveryPhone, setRecoveryPhone] = useState('');
	const [isGeneratingCode, setIsGeneratingCode] = useState(false);
	const [generatedCode, setGeneratedCode] = useState<string | null>(null);
	const [isVerifyingRecovery, setIsVerifyingRecovery] = useState(false);
	const [recoveryVerified, setRecoveryVerified] = useState(false);
	const [newPassword, setNewPassword] = useState('');
	const [confirmNewPassword, setConfirmNewPassword] = useState('');
	const [isResettingPassword, setIsResettingPassword] = useState(false);

	const validateMasterPasswordComplexity = (pwd: string) => {
		if (pwd.length < 12) return 'Master password must be at least 12 characters long';
		if (!/[A-Z]/.test(pwd)) return 'Master password must contain at least one uppercase letter';
		if (!/[a-z]/.test(pwd)) return 'Master password must contain at least one lowercase letter';
		if (!/\d/.test(pwd)) return 'Master password must contain at least one number';
		if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(pwd)) return 'Master password must contain at least one special character';
		return null;
	};

	const handleSubmit = async (e: React.FormEvent) => {
		e.preventDefault();

		const complexityError = validateMasterPasswordComplexity(password);
		if (complexityError) {
			setError(complexityError);
			return;
		}

		if (isMasterPasswordSet === false) {
			if (password !== confirmPassword) {
				setError('Passwords do not match');
				return;
			}
		}

		setIsValidating(true);
		setError('');

		try {
			const isValid = await window.vault.testMasterPassword(password);

			if (isValid) {
				onLogin(password);
			} else {
				setError('Incorrect master password. Please try again.');
			}
		} catch (err) {
			const msg = err instanceof Error ? err.message : 'Unknown error';
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
					{restoreMode
						? 'Backup restored. Enter the master password that was used when this backup was created.'
						: isMasterPasswordSet
							? 'Enter your master password to unlock the vault'
							: 'Set your master password (encrypts your vault)'}
				</p>

				<form onSubmit={handleSubmit} className='login-form'>
					<div className='form-group'>
						<input
							type='password'
							placeholder={isMasterPasswordSet ? 'Master password' : 'Master password (12+ chars, upper, lower, number, special)'}
							value={password}
							onChange={e => {
								setPassword(e.target.value);
								if (error) setError('');
							}}
							className='login-input'
							disabled={isValidating}
							autoComplete={isMasterPasswordSet ? 'current-password' : 'new-password'}
						/>
					</div>
					{!isMasterPasswordSet && (
						<div className='form-group'>
							<input
								type='password'
								placeholder='Confirm master password'
								value={confirmPassword}
								onChange={e => {
									setConfirmPassword(e.target.value);
									if (error) setError('');
								}}
								className='login-input'
								disabled={isValidating}
								autoComplete='new-password'
							/>
						</div>
					)}

					{error && <div className='error-message'>{error}</div>}

					<div style={{ display: 'flex', gap: '10px', flexDirection: 'column' }}>
						<button
							type='submit'
							className='login-button'
							disabled={isValidating || (!isMasterPasswordSet && (password !== confirmPassword || password.length < 12))}>
							{isValidating ? 'Validating...' : isMasterPasswordSet ? 'Unlock' : 'Set Master Password'}
						</button>
						{isMasterPasswordSet && (
							<button
								type='button'
								onClick={() => {
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
								Forgot Master Password?
							</button>
						)}
					</div>
				</form>
			</div>

			{/* Forgot Password / Recovery Modal - same as LoginScreen */}
			{showForgotPassword && (
				<div className='modal-overlay' onClick={() => !recoveryVerified && setShowForgotPassword(false)}>
					<div
						className='category-modal'
						onClick={e => e.stopPropagation()}
						style={{ maxWidth: '600px', pointerEvents: 'auto', position: 'relative', zIndex: 10001 }}>
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
														<button type='button' onClick={() => setRecoveryMethod(null)} className='delete-cancel' disabled={isGeneratingCode}>
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
																		setGeneratedCode(result.code || null);
																		if (result.code) {
																			alert(`Recovery code: ${result.code}\n\nIn production, this would be sent to your email/phone.`);
																		}
																	}
																} catch (err) {
																	setError(err instanceof Error ? err.message : 'Failed to generate recovery code');
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
														<div style={{ marginBottom: '16px', padding: '12px', background: 'rgba(239, 68, 68, 0.1)', border: '1px solid #ef4444', borderRadius: '8px', fontSize: '13px', color: '#ef4444' }}>
															<strong>Code Expired:</strong> Please generate a new code.
															<button
																type='button'
																onClick={async () => {
																	setError('');
																	setRecoveryCode('');
																	setVerifiedRecoveryCode(null);
																	setRecoveryVerified(false);
																	setIsGeneratingCode(true);
																	try {
																		const result = await (window.vault as any).generateRecoveryCode(recoveryEmail, recoveryPhone);
																		if (result.success) {
																			setGeneratedCode(result.code);
																			if (result.code) alert(`New recovery code: ${result.code}`);
																		}
																	} finally {
																		setIsGeneratingCode(false);
																	}
																}}
																style={{ marginTop: '8px', padding: '8px 16px', background: '#ef4444', color: 'white', border: 'none', borderRadius: '4px', cursor: 'pointer', fontSize: '13px', display: 'block' }}>
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
														onChange={e => setRecoveryCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
														className='login-input recovery-code-input'
														disabled={isVerifyingRecovery}
														autoFocus
														style={{ fontFamily: 'monospace', textAlign: 'center', letterSpacing: '2px', fontSize: '18px', pointerEvents: 'auto' }}
													/>
													{error && <div className='error-message' style={{ marginTop: '12px' }}>{error}</div>}
													<div style={{ display: 'flex', gap: '10px', marginTop: '20px' }}>
														<button type='button' onClick={() => { setGeneratedCode(null); setRecoveryCode(''); setVerifiedRecoveryCode(null); setError(''); }} className='delete-cancel' disabled={isVerifyingRecovery}>
															Back
														</button>
														<button
															type='button'
															onClick={async () => {
																if (!window.vault || typeof (window.vault as any).verifyRecoveryCode !== 'function') return;
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
																		setVerifiedRecoveryCode(recoveryCode);
																	} else {
																		setError(result.error || 'Invalid recovery code');
																	}
																} catch (err) {
																	setError(err instanceof Error ? err.message : 'Verification failed');
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
									<div style={{ padding: '16px', background: 'rgba(16, 185, 129, 0.1)', border: '1px solid #10b981', borderRadius: '8px', marginBottom: '20px', fontSize: '13px', color: '#10b981' }}>
										<strong>✅ Email/SMS Recovery:</strong> Your data will be preserved.
									</div>
									<div style={{ marginBottom: '16px' }}>
										<input type='password' placeholder='New Master Password' value={newPassword} onChange={e => setNewPassword(e.target.value)} className='login-input' disabled={isResettingPassword} />
									</div>
									<div style={{ marginBottom: '16px' }}>
										<input type='password' placeholder='Confirm New Password' value={confirmNewPassword} onChange={e => setConfirmNewPassword(e.target.value)} className='login-input' disabled={isResettingPassword} />
										{confirmNewPassword && newPassword !== confirmNewPassword && <span style={{ color: '#ef4444', fontSize: '12px', display: 'block', marginTop: '4px' }}>Passwords do not match</span>}
									</div>
									{error && <div className='error-message' style={{ marginBottom: '16px' }}>{error}</div>}
									<div style={{ display: 'flex', gap: '10px' }}>
										<button type='button' onClick={() => { setRecoveryVerified(false); setNewPassword(''); setConfirmNewPassword(''); setError(''); }} className='delete-cancel' disabled={isResettingPassword}>Back</button>
										<button
											type='button'
											onClick={async () => {
												if (newPassword.length < 12) { setError('Master password must be at least 12 characters'); return; }
												if (newPassword !== confirmNewPassword) { setError('Passwords do not match'); return; }
												if (validateMasterPasswordComplexity(newPassword)) { setError(validateMasterPasswordComplexity(newPassword)!); return; }
												if (!window.vault?.resetMasterPasswordViaRecovery) { setError('Reset not available'); return; }
												setIsResettingPassword(true);
												setError('');
												try {
													const codeToUse = verifiedRecoveryCode || recoveryCode;
													if (!codeToUse || codeToUse.length !== 6) { setError('Recovery code required'); setIsResettingPassword(false); return; }
													const recoveryData = { code: codeToUse };
													const result = await (window.vault as any).resetMasterPasswordViaRecovery(newPassword, 'email_sms', recoveryData);
													if (result.success) {
														alert(`${result.warning || result.message || 'Password reset!'}\n\nLog in with your new password.`);
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
												} catch (err) {
													setError(err instanceof Error ? err.message : 'Reset failed');
													if (String(err).includes('expired')) { setRecoveryVerified(false); setVerifiedRecoveryCode(null); setRecoveryCode(''); }
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

export default MasterPasswordScreen;
