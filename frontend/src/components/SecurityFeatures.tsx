import React, { useState, useEffect, useRef } from 'react';
import './SecurityFeatures.css';
import { Shield, CheckCircle, AlertTriangle, X } from 'lucide-react';

interface SecurityStatus {
	encryptionActive: boolean;
	autoLockActive: boolean;
	networkIsolation: boolean;
	developerToolsBlocked: boolean;
	contextMenuBlocked: boolean;
}

const SecurityFeatures: React.FC = () => {
	const [securityStatus, setSecurityStatus] = useState<SecurityStatus | null>(null);
	const [isExpanded, setIsExpanded] = useState(false);
	const [timeUntilLock, setTimeUntilLock] = useState(180); // 3 minutes (180 seconds)
	const panelRef = useRef<HTMLDivElement>(null);
	const buttonRef = useRef<HTMLButtonElement>(null);

	// Reset timer when panel is opened
	useEffect(() => {
		if (isExpanded) {
			setTimeUntilLock(180);
		}
	}, [isExpanded]);

	// Countdown timer
	useEffect(() => {
		if (!isExpanded) return;

		const interval = setInterval(() => {
			setTimeUntilLock(prev => {
				if (prev <= 1) {
					// Auto-lock triggered
					setIsExpanded(false);
					return 180;
				}
				return prev - 1;
			});
		}, 1000);

		return () => clearInterval(interval);
	}, [isExpanded]);

	// Get security status from main process
	useEffect(() => {
		const getStatus = async () => {
			try {
				if (window.security && window.security.getStatus) {
					const status = await window.security.getStatus();
					setSecurityStatus(status);
				}
			} catch (error) {
				console.error('[SecurityFeatures] Error getting security status:', error);
			}
		};

		getStatus();
	}, []);

	// Click outside to close
	useEffect(() => {
		const handleClickOutside = (event: MouseEvent) => {
			if (
				panelRef.current &&
				!panelRef.current.contains(event.target as Node) &&
				buttonRef.current &&
				!buttonRef.current.contains(event.target as Node)
			) {
				setIsExpanded(false);
			}
		};

		document.addEventListener('mousedown', handleClickOutside);
		return () => document.removeEventListener('mousedown', handleClickOutside);
	}, []);

	const handleClose = () => {
		setIsExpanded(false);
	};

	const getStatusIcon = (status: boolean) => {
		return status ? (
			<CheckCircle size={16} className='status-icon status-active' />
		) : (
			<AlertTriangle size={16} className='status-icon status-inactive' />
		);
	};

	const getStatusText = (status: boolean) => {
		return status ? 'Active' : 'Inactive';
	};

	const getStatusClass = (status: boolean) => {
		return status ? 'status-active' : 'status-inactive';
	};

	const formatTime = (seconds: number) => {
		const minutes = Math.floor(seconds / 60);
		const remainingSeconds = seconds % 60;
		if (minutes > 0) {
			return `${minutes}:${remainingSeconds.toString().padStart(2, '0')}`;
		}
		return `${remainingSeconds}s`;
	};

	const getTimeUntilLockColor = (seconds: number) => {
		if (seconds <= 30) return '#ef4444'; // Red (last 30 seconds)
		if (seconds <= 60) return '#f59e0b'; // Yellow (last minute)
		return '#10b981'; // Green (more than 1 minute)
	};

	return (
		<div className='security-features'>
			<button
				ref={buttonRef}
				onClick={() => setIsExpanded(!isExpanded)}
				className='security-toggle'
				title='Security Status'>
				<Shield size={28} />
				{isExpanded && (
					<div className='auto-lock-indicator' style={{ color: getTimeUntilLockColor(timeUntilLock) }}>
						{formatTime(timeUntilLock)}
					</div>
				)}
			</button>

			{isExpanded && (
				<div ref={panelRef} className='security-panel'>
					<div className='security-header'>
						<h3>Security Status</h3>
						<button onClick={handleClose} className='close-button' title='Close'>
							<X size={16} />
						</button>
					</div>

					{securityStatus ? (
						<>
							<div className='security-grid'>
								<div className='security-info-item'>
									<div className='info-header'>
										<span>AES-256 Encryption</span>
										{getStatusIcon(securityStatus.encryptionActive)}
									</div>
									<div className={`status ${getStatusClass(securityStatus.encryptionActive)}`}>
										{getStatusText(securityStatus.encryptionActive)}
									</div>
								</div>

								<div className='security-info-item'>
									<div className='info-header'>
										<span>Auto-Lock (3 min)</span>
										{getStatusIcon(securityStatus.autoLockActive)}
									</div>
									<div className={`status ${getStatusClass(securityStatus.autoLockActive)}`}>
										{getStatusText(securityStatus.autoLockActive)}
									</div>
								</div>

								<div className='security-info-item'>
									<div className='info-header'>
										<span>Offline Operation</span>
										{getStatusIcon(securityStatus.networkIsolation)}
									</div>
									<div className={`status ${getStatusClass(securityStatus.networkIsolation)}`}>
										{getStatusText(securityStatus.networkIsolation)}
									</div>
								</div>

								<div className='security-info-item'>
									<div className='info-header'>
										<span>Dev Tools Blocked</span>
										{getStatusIcon(securityStatus.developerToolsBlocked)}
									</div>
									<div className={`status ${getStatusClass(securityStatus.developerToolsBlocked)}`}>
										{getStatusText(securityStatus.developerToolsBlocked)}
									</div>
								</div>

								<div className='security-info-item'>
									<div className='info-header'>
										<span>Context Menu Blocked</span>
										{getStatusIcon(securityStatus.contextMenuBlocked)}
									</div>
									<div className={`status ${getStatusClass(securityStatus.contextMenuBlocked)}`}>
										{getStatusText(securityStatus.contextMenuBlocked)}
									</div>
								</div>
							</div>

							<div className='security-footer'>
								<p className='security-note'>
									<strong>Auto-Lock Timer:</strong> {formatTime(timeUntilLock)} until vault locks
								</p>
								<p className='security-note'>
									<strong>Security:</strong> AES-256 encryption with offline-first operation
								</p>
							</div>
						</>
					) : (
						<div className='security-loading'>
							<div className='loading-icon'></div>
							<span>Loading security status...</span>
						</div>
					)}
				</div>
			)}
		</div>
	);
};

export default SecurityFeatures;

declare global {
	interface Window {
		security?: {
			getStatus: () => Promise<SecurityStatus>;
			reportEvent: (eventType: string) => Promise<{ success: boolean }>;
		};
	}
}
