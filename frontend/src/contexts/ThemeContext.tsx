import React, { createContext, useContext, useEffect, useState } from 'react';

type Theme = 'light' | 'dark';

interface ThemeContextType {
	theme: Theme;
	toggleTheme: () => void;
	syncWithSystem: () => void;
}

const ThemeContext = createContext<ThemeContextType | undefined>(undefined);

export const useTheme = () => {
	const context = useContext(ThemeContext);
	if (context === undefined) {
		throw new Error('useTheme must be used within a ThemeProvider');
	}
	return context;
};

interface ThemeProviderProps {
	children: React.ReactNode;
}

export const ThemeProvider: React.FC<ThemeProviderProps> = ({ children }) => {
	const [theme, setTheme] = useState<Theme>(() => {
		// Get theme from localStorage or default to system preference
		const savedTheme = localStorage.getItem('theme') as Theme;
		if (savedTheme) {
			return savedTheme;
		}

		// Check system preference
		if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
			return 'dark';
		}

		return 'light';
	});

	// Listen for system theme changes
	useEffect(() => {
		const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');

		const handleChange = (e: MediaQueryListEvent) => {
			// Only auto-switch if user hasn't manually set a preference
			if (!localStorage.getItem('theme')) {
				setTheme(e.matches ? 'dark' : 'light');
			}
		};

		mediaQuery.addEventListener('change', handleChange);

		return () => {
			mediaQuery.removeEventListener('change', handleChange);
		};
	}, []);

	useEffect(() => {
		// Save theme preference to localStorage
		localStorage.setItem('theme', theme);

		// Apply theme to document
		document.documentElement.setAttribute('data-theme', theme);

		// Update CSS custom properties
		if (theme === 'dark') {
			document.documentElement.style.setProperty('--bg-primary', '#1a1a1a');
			document.documentElement.style.setProperty('--bg-secondary', '#2d2d2d');
			document.documentElement.style.setProperty('--bg-tertiary', '#3d3d3d');
			document.documentElement.style.setProperty('--text-primary', '#ffffff');
			document.documentElement.style.setProperty('--text-secondary', '#b0b0b0');
			document.documentElement.style.setProperty('--border-color', '#404040');
			document.documentElement.style.setProperty('--shadow-color', 'rgba(0, 0, 0, 0.3)');
			document.documentElement.style.setProperty('--accent-color', '#3b82f6');
			document.documentElement.style.setProperty('--accent-hover', '#2563eb');
			document.documentElement.style.setProperty('--danger-color', '#ef4444');
			document.documentElement.style.setProperty('--success-color', '#10b981');
		} else {
			document.documentElement.style.setProperty('--bg-primary', '#ffffff');
			document.documentElement.style.setProperty('--bg-secondary', '#f8f9fa');
			document.documentElement.style.setProperty('--bg-tertiary', '#e9ecef');
			document.documentElement.style.setProperty('--text-primary', '#212529');
			document.documentElement.style.setProperty('--text-secondary', '#6c757d');
			document.documentElement.style.setProperty('--border-color', '#dee2e6');
			document.documentElement.style.setProperty('--shadow-color', 'rgba(0, 0, 0, 0.1)');
			document.documentElement.style.setProperty('--accent-color', '#0d6efd');
			document.documentElement.style.setProperty('--accent-hover', '#0b5ed7');
			document.documentElement.style.setProperty('--danger-color', '#dc3545');
			document.documentElement.style.setProperty('--success-color', '#198754');
		}
	}, [theme]);

	const toggleTheme = () => {
		setTheme(prev => (prev === 'light' ? 'dark' : 'light'));
	};

	const syncWithSystem = () => {
		// Remove manual preference and sync with system
		localStorage.removeItem('theme');
		if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
			setTheme('dark');
		} else {
			setTheme('light');
		}
	};

	return <ThemeContext.Provider value={{ theme, toggleTheme, syncWithSystem }}>{children}</ThemeContext.Provider>;
};
