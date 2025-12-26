import type { Category } from '../types/vault';

export const DEFAULT_CATEGORIES: Category[] = [
	{
		id: 'work',
		name: 'Work',
		color: '#3b82f6',
		icon: 'Briefcase',
	},
	{
		id: 'personal',
		name: 'Personal',
		color: '#10b981',
		icon: 'Home',
	},
	{
		id: 'banking',
		name: 'Banking',
		color: '#f59e0b',
		icon: 'Building2',
	},
	{
		id: 'social',
		name: 'Social Media',
		color: '#8b5cf6',
		icon: 'Smartphone',
	},
	{
		id: 'shopping',
		name: 'Shopping',
		color: '#ef4444',
		icon: 'ShoppingCart',
	},
	{
		id: 'entertainment',
		name: 'Entertainment',
		color: '#ec4899',
		icon: 'Gamepad2',
	},
	{
		id: 'utilities',
		name: 'Utilities',
		color: '#06b6d4',
		icon: 'Zap',
	},
	{
		id: 'other',
		name: 'Other',
		color: '#6b7280',
		icon: 'Key',
	},
];

export const getCategoryById = (id: string): Category | undefined => {
	return DEFAULT_CATEGORIES.find(cat => cat.id === id);
};

export const getCategoryByName = (name: string): Category | undefined => {
	return DEFAULT_CATEGORIES.find(cat => cat.name.toLowerCase() === name.toLowerCase());
};

export const suggestCategory = (serviceName: string): string => {
	const name = serviceName.toLowerCase();

	// Banking services
	if (name.includes('bank') || name.includes('paypal') || name.includes('stripe') || name.includes('venmo')) {
		return 'banking';
	}

	// Social media
	if (
		name.includes('facebook') ||
		name.includes('twitter') ||
		name.includes('instagram') ||
		name.includes('linkedin') ||
		name.includes('tiktok')
	) {
		return 'social';
	}

	// Shopping
	if (
		name.includes('amazon') ||
		name.includes('ebay') ||
		name.includes('shop') ||
		name.includes('store') ||
		name.includes('mall')
	) {
		return 'shopping';
	}

	// Entertainment
	if (
		name.includes('netflix') ||
		name.includes('spotify') ||
		name.includes('youtube') ||
		name.includes('game') ||
		name.includes('play')
	) {
		return 'entertainment';
	}

	// Utilities
	if (
		name.includes('gmail') ||
		name.includes('outlook') ||
		name.includes('icloud') ||
		name.includes('dropbox') ||
		name.includes('drive')
	) {
		return 'utilities';
	}

	// Work-related
	if (
		name.includes('office') ||
		name.includes('work') ||
		name.includes('company') ||
		name.includes('corp') ||
		name.includes('inc')
	) {
		return 'work';
	}

	// Default to personal
	return 'personal';
};
