import React from 'react';
import { Sun, Moon } from 'lucide-react';
import { useTheme } from '../contexts/ThemeContext';
import './ThemeToggle.css';

const ThemeToggle: React.FC = () => {
	const { theme, toggleTheme } = useTheme();

	return (
		<button
			className='theme-toggle'
			onClick={toggleTheme}
			title={`Switch to ${theme === 'light' ? 'dark' : 'light'} theme`}
			aria-label={`Switch to ${theme === 'light' ? 'dark' : 'light'} theme`}>
			{theme === 'light' ? <Moon size={36} className='theme-icon' /> : <Sun size={36} className='theme-icon' />}
		</button>
	);
};

export default ThemeToggle;
