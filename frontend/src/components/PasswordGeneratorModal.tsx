import React, { useState, useEffect } from 'react';
import { X, RefreshCw, Copy, Check } from 'lucide-react';
import {
	generatePassword,
	analyzePasswordStrength,
	DEFAULT_OPTIONS,
	type PasswordOptions,
	type PasswordStrength,
} from '../utils/passwordGenerator';

interface PasswordGeneratorModalProps {
	isOpen: boolean;
	onClose: () => void;
	onPasswordGenerated: (password: string) => void;
	isNested?: boolean;
}

const PasswordGeneratorModal: React.FC<PasswordGeneratorModalProps> = ({
	isOpen,
	onClose,
	onPasswordGenerated,
	isNested = false,
}) => {
	const [options, setOptions] = useState<PasswordOptions>(DEFAULT_OPTIONS);
	const [generatedPassword, setGeneratedPassword] = useState('');
	const [strength, setStrength] = useState<PasswordStrength | null>(null);
	const [copied, setCopied] = useState(false);

	// Generate initial password
	useEffect(() => {
		if (isOpen) {
			generateNewPassword();
		}
	}, [isOpen]);

	// Update strength analysis when password changes
	useEffect(() => {
		if (generatedPassword) {
			setStrength(analyzePasswordStrength(generatedPassword));
		}
	}, [generatedPassword]);

	const generateNewPassword = () => {
		const newPassword = generatePassword(options);
		setGeneratedPassword(newPassword);
		setCopied(false);
	};

	const handleCopyPassword = async () => {
		try {
			await navigator.clipboard.writeText(generatedPassword);
			setCopied(true);
			setTimeout(() => setCopied(false), 2000);
		} catch (error) {
			console.error('Failed to copy password:', error);
		}
	};

	const handleUsePassword = () => {
		onPasswordGenerated(generatedPassword);
		onClose();
	};

	const updateOption = (key: keyof PasswordOptions, value: boolean | number) => {
		setOptions(prev => ({ ...prev, [key]: value }));
	};

	const getStrengthColor = (level: string) => {
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

	const getStrengthWidth = (score: number) => {
		return `${score}%`;
	};

	if (!isOpen) return null;

	return (
		<div className={`modal-overlay ${isNested ? 'modal-overlay-nested' : ''}`} onClick={onClose}>
			<div className='password-generator-modal' onClick={e => e.stopPropagation()}>
				<div className='modal-header'>
					<h3>Password Generator</h3>
					<button className='modal-close' onClick={onClose} title='Close'>
						<X size={16} />
					</button>
				</div>

				<div className='generator-content'>
					{/* Generated Password Display */}
					<div className='password-display'>
						<div className='password-field'>
							<input type='text' value={generatedPassword} readOnly className='generated-password-input' />
							<button className='copy-password-btn' onClick={handleCopyPassword} title='Copy password'>
								{copied ? <Check size={16} /> : <Copy size={16} />}
							</button>
							<button className='regenerate-btn' onClick={generateNewPassword} title='Generate new password'>
								<RefreshCw size={16} />
							</button>
						</div>

						{/* Strength Indicator */}
						{strength && (
							<div className='strength-indicator'>
								<div className='strength-header'>
									<span className='strength-label'>Strength:</span>
									<span className='strength-level' style={{ color: getStrengthColor(strength.level) }}>
										{strength.level.replace('-', ' ').toUpperCase()}
									</span>
									<span className='strength-score'>({strength.score}/100)</span>
								</div>
								<div className='strength-bar'>
									<div
										className='strength-fill'
										style={{
											width: getStrengthWidth(strength.score),
											backgroundColor: getStrengthColor(strength.level),
										}}
									/>
								</div>
								{strength.feedback.length > 0 && (
									<div className='strength-feedback'>
										{strength.feedback.map((feedback, index) => (
											<div key={index} className='feedback-item'>
												{feedback}
											</div>
										))}
									</div>
								)}
							</div>
						)}
					</div>

					{/* Generator Options */}
					<div className='generator-options'>
						<h4>Options</h4>

						<div className='option-group'>
							<label className='option-label'>
								<span>Length: {options.length}</span>
								<input
									type='range'
									min='8'
									max='64'
									value={options.length}
									onChange={e => updateOption('length', parseInt(e.target.value))}
									className='length-slider'
								/>
							</label>
						</div>

						<div className='option-group'>
							<label className='checkbox-label'>
								<input
									type='checkbox'
									checked={options.includeUppercase}
									onChange={e => updateOption('includeUppercase', e.target.checked)}
								/>
								<span>Include Uppercase (A-Z)</span>
							</label>
						</div>

						<div className='option-group'>
							<label className='checkbox-label'>
								<input
									type='checkbox'
									checked={options.includeLowercase}
									onChange={e => updateOption('includeLowercase', e.target.checked)}
								/>
								<span>Include Lowercase (a-z)</span>
							</label>
						</div>

						<div className='option-group'>
							<label className='checkbox-label'>
								<input
									type='checkbox'
									checked={options.includeNumbers}
									onChange={e => updateOption('includeNumbers', e.target.checked)}
								/>
								<span>Include Numbers (0-9)</span>
							</label>
						</div>

						<div className='option-group'>
							<label className='checkbox-label'>
								<input
									type='checkbox'
									checked={options.includeSymbols}
									onChange={e => updateOption('includeSymbols', e.target.checked)}
								/>
								<span>Include Symbols (!@#$...)</span>
							</label>
						</div>

						<div className='option-group'>
							<label className='checkbox-label'>
								<input
									type='checkbox'
									checked={options.excludeSimilar}
									onChange={e => updateOption('excludeSimilar', e.target.checked)}
								/>
								<span>Exclude Similar Characters (il1Lo0O)</span>
							</label>
						</div>

						<div className='option-group'>
							<label className='checkbox-label'>
								<input
									type='checkbox'
									checked={options.excludeAmbiguous}
									onChange={e => updateOption('excludeAmbiguous', e.target.checked)}
								/>
								<span>Exclude Ambiguous Characters (&#123; &#125; &#91; &#93; &#40; &#41; / \ ~ , ; . &lt; &gt;)</span>
							</label>
						</div>
					</div>

					{/* Action Buttons */}
					<div className='generator-actions'>
						<button className='use-password-btn' onClick={handleUsePassword}>
							Use This Password
						</button>
						<button className='cancel-btn' onClick={onClose}>
							Cancel
						</button>
					</div>
				</div>
			</div>
		</div>
	);
};

export default PasswordGeneratorModal;
