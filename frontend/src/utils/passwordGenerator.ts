export interface PasswordOptions {
	length: number;
	includeUppercase: boolean;
	includeLowercase: boolean;
	includeNumbers: boolean;
	includeSymbols: boolean;
	excludeSimilar: boolean;
	excludeAmbiguous: boolean;
}

export interface PasswordStrength {
	score: number; // 0-100
	level: 'weak' | 'medium' | 'strong' | 'very-strong';
	feedback: string[];
}

const DEFAULT_OPTIONS: PasswordOptions = {
	length: 16,
	includeUppercase: true,
	includeLowercase: true,
	includeNumbers: true,
	includeSymbols: true,
	excludeSimilar: true,
	excludeAmbiguous: false,
};

const CHARACTER_SETS = {
	uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
	lowercase: 'abcdefghijklmnopqrstuvwxyz',
	numbers: '0123456789',
	symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?',
	similar: 'il1Lo0O', // Characters that look similar
	ambiguous: '{}[]()/\\~,;.<>', // Ambiguous characters
};

export function generatePassword(options: PasswordOptions = DEFAULT_OPTIONS): string {
	let charset = '';

	// Build character set based on options
	if (options.includeUppercase) {
		charset += CHARACTER_SETS.uppercase;
	}
	if (options.includeLowercase) {
		charset += CHARACTER_SETS.lowercase;
	}
	if (options.includeNumbers) {
		charset += CHARACTER_SETS.numbers;
	}
	if (options.includeSymbols) {
		charset += CHARACTER_SETS.symbols;
	}

	// Remove similar characters if requested
	if (options.excludeSimilar) {
		charset = charset
			.split('')
			.filter(char => !CHARACTER_SETS.similar.includes(char))
			.join('');
	}

	// Remove ambiguous characters if requested
	if (options.excludeAmbiguous) {
		charset = charset
			.split('')
			.filter(char => !CHARACTER_SETS.ambiguous.includes(char))
			.join('');
	}

	// Ensure we have at least one character from each required set
	const requiredChars = [];
	if (options.includeUppercase) {
		const upperChars = CHARACTER_SETS.uppercase.split('').filter(char => charset.includes(char));
		if (upperChars.length > 0) {
			requiredChars.push(upperChars[Math.floor(Math.random() * upperChars.length)]);
		}
	}
	if (options.includeLowercase) {
		const lowerChars = CHARACTER_SETS.lowercase.split('').filter(char => charset.includes(char));
		if (lowerChars.length > 0) {
			requiredChars.push(lowerChars[Math.floor(Math.random() * lowerChars.length)]);
		}
	}
	if (options.includeNumbers) {
		const numberChars = CHARACTER_SETS.numbers.split('').filter(char => charset.includes(char));
		if (numberChars.length > 0) {
			requiredChars.push(numberChars[Math.floor(Math.random() * numberChars.length)]);
		}
	}
	if (options.includeSymbols) {
		const symbolChars = CHARACTER_SETS.symbols.split('').filter(char => charset.includes(char));
		if (symbolChars.length > 0) {
			requiredChars.push(symbolChars[Math.floor(Math.random() * symbolChars.length)]);
		}
	}

	// Generate the rest of the password
	const remainingLength = options.length - requiredChars.length;
	let password = '';

	for (let i = 0; i < remainingLength; i++) {
		password += charset[Math.floor(Math.random() * charset.length)];
	}

	// Add required characters
	password += requiredChars.join('');

	// Shuffle the password
	return shuffleString(password);
}

export function analyzePasswordStrength(password: string): PasswordStrength {
	const feedback: string[] = [];
	let score = 0;

	// Length scoring
	if (password.length < 8) {
		score += 0;
		feedback.push('Password is too short (minimum 8 characters)');
	} else if (password.length < 12) {
		score += 20;
		feedback.push('Consider using a longer password (12+ characters)');
	} else if (password.length < 16) {
		score += 30;
	} else {
		score += 40;
	}

	// Character variety scoring
	let hasUppercase = false;
	let hasLowercase = false;
	let hasNumbers = false;
	let hasSymbols = false;

	for (const char of password) {
		if (CHARACTER_SETS.uppercase.includes(char)) hasUppercase = true;
		if (CHARACTER_SETS.lowercase.includes(char)) hasLowercase = true;
		if (CHARACTER_SETS.numbers.includes(char)) hasNumbers = true;
		if (CHARACTER_SETS.symbols.includes(char)) hasSymbols = true;
	}

	if (hasUppercase) score += 15;
	else feedback.push('Add uppercase letters for better security');

	if (hasLowercase) score += 15;
	else feedback.push('Add lowercase letters for better security');

	if (hasNumbers) score += 15;
	else feedback.push('Add numbers for better security');

	if (hasSymbols) score += 15;
	else feedback.push('Add symbols for better security');

	// Pattern detection
	if (hasRepeatingPatterns(password)) {
		score -= 10;
		feedback.push('Avoid repeating patterns');
	}

	if (hasSequentialPatterns(password)) {
		score -= 10;
		feedback.push('Avoid sequential patterns (123, abc)');
	}

	if (hasCommonPatterns(password)) {
		score -= 5;
		feedback.push('Avoid common patterns');
	}

	// Bonus for very long passwords
	if (password.length >= 20) {
		score += 10;
	}

	// Ensure score is between 0 and 100
	score = Math.max(0, Math.min(100, score));

	// Determine strength level
	let level: PasswordStrength['level'];
	if (score < 30) level = 'weak';
	else if (score < 60) level = 'medium';
	else if (score < 80) level = 'strong';
	else level = 'very-strong';

	// Add positive feedback for strong passwords
	if (score >= 80) {
		feedback.push('Excellent password strength!');
	} else if (score >= 60) {
		feedback.push('Good password strength');
	}

	return {
		score,
		level,
		feedback: feedback.length > 0 ? feedback : ['Password meets basic requirements'],
	};
}

function shuffleString(str: string): string {
	const array = str.split('');
	for (let i = array.length - 1; i > 0; i--) {
		const j = Math.floor(Math.random() * (i + 1));
		[array[i], array[j]] = [array[j], array[i]];
	}
	return array.join('');
}

function hasRepeatingPatterns(password: string): boolean {
	// Check for repeated characters
	for (let i = 0; i < password.length - 2; i++) {
		if (password[i] === password[i + 1] && password[i] === password[i + 2]) {
			return true;
		}
	}
	return false;
}

function hasSequentialPatterns(password: string): boolean {
	const sequences = ['123', '234', '345', '456', '567', '678', '789', '890'];
	const alphaSequences = [
		'abc',
		'bcd',
		'cde',
		'def',
		'efg',
		'fgh',
		'ghi',
		'hij',
		'ijk',
		'jkl',
		'klm',
		'lmn',
		'mno',
		'nop',
		'opq',
		'pqr',
		'qrs',
		'rst',
		'stu',
		'tuv',
		'uvw',
		'vwx',
		'wxy',
		'xyz',
	];

	const lowerPassword = password.toLowerCase();

	for (const seq of [...sequences, ...alphaSequences]) {
		if (lowerPassword.includes(seq)) {
			return true;
		}
	}
	return false;
}

function hasCommonPatterns(password: string): boolean {
	const commonPatterns = ['password', '123456', 'qwerty', 'admin', 'letmein', 'welcome', 'monkey', 'dragon'];
	const lowerPassword = password.toLowerCase();

	for (const pattern of commonPatterns) {
		if (lowerPassword.includes(pattern)) {
			return true;
		}
	}
	return false;
}

export { DEFAULT_OPTIONS };

// Word list for passphrase (subset of EFF short list - 256 words, ~8 bits/word)
const PASSPHRASE_WORDS = [
	'able', 'acid', 'also', 'apex', 'arch', 'atom', 'auto', 'axis', 'bake', 'bald', 'barn', 'belt', 'beta', 'bias', 'bird', 'blue', 'boat', 'body', 'bomb', 'bone', 'book', 'boot', 'bush', 'busy', 'cafe', 'cage', 'cake', 'calm', 'camp', 'card', 'care', 'cart', 'case', 'cash', 'cast', 'cell', 'cent', 'chip', 'city', 'clay', 'clip', 'club', 'coal', 'coat', 'code', 'cold', 'come', 'cook', 'cool', 'cope', 'copy', 'cord', 'core', 'cost', 'crew', 'crop', 'dark', 'data', 'date', 'dawn', 'days', 'dead', 'deal', 'dear', 'debt', 'deep', 'desk', 'dial', 'diet', 'dirt', 'disc', 'disk', 'door', 'dose', 'down', 'draw', 'drop', 'drug', 'drum', 'duck', 'dust', 'duty', 'each', 'earl', 'earn', 'ease', 'east', 'easy', 'echo', 'edge', 'else', 'even', 'ever', 'evil', 'exit', 'face', 'fact', 'fail', 'fair', 'fall', 'farm', 'fast', 'fate', 'fear', 'feed', 'feel', 'file', 'fill', 'film', 'find', 'fine', 'fire', 'firm', 'fish', 'five', 'flat', 'flow', 'flux', 'foam', 'fold', 'folk', 'food', 'foot', 'ford', 'form', 'fort', 'four', 'free', 'from', 'fuel', 'full', 'fund', 'gain', 'game', 'gate', 'gave', 'gear', 'gene', 'gift', 'girl', 'give', 'glad', 'glow', 'goal', 'goat', 'gold', 'golf', 'gone', 'good', 'gray', 'grew', 'grey', 'grow', 'gulf', 'hair', 'half', 'hall', 'hand', 'hang', 'hard', 'harm', 'hate', 'have', 'head', 'hear', 'heat', 'held', 'hell', 'help', 'hero', 'high', 'hill', 'hold', 'hole', 'holy', 'home', 'hope', 'horn', 'host', 'hour', 'huge', 'hung', 'hunt', 'hurt', 'idea', 'inch', 'into', 'iron', 'isle', 'item', 'jack', 'jane', 'java', 'john', 'join', 'jump', 'jury', 'just', 'keen', 'keep', 'kent', 'kept', 'kick', 'kill', 'kind', 'king', 'knee', 'knew', 'know', 'lack', 'lady', 'laid', 'lake', 'land', 'lane', 'last', 'late', 'lead', 'left', 'less', 'life', 'lift', 'like', 'line', 'link', 'list', 'live', 'load', 'loan', 'lock', 'long', 'look', 'lord', 'lose', 'loss', 'lost', 'love', 'luck', 'made', 'mail', 'main', 'make', 'male', 'many', 'mark', 'mass', 'matt', 'meal', 'mean', 'meat', 'meet', 'menu', 'mere', 'mike', 'mile', 'milk', 'mill', 'mind', 'mine', 'miss', 'mode', 'mood', 'moon', 'more', 'most', 'move', 'much', 'must', 'myth', 'name', 'navy', 'near', 'neck', 'need', 'news', 'next', 'nice', 'nine', 'none', 'nose', 'note', 'okay', 'once', 'only', 'onto', 'open', 'oral', 'over', 'pace', 'pack', 'page', 'paid', 'pain', 'pair', 'palm', 'park', 'part', 'pass', 'past', 'path', 'peak', 'pick', 'pile', 'pine', 'pink', 'pipe', 'plan', 'play', 'plot', 'plug', 'plus', 'poem', 'poet', 'pole', 'poll', 'pool', 'poor', 'port', 'post', 'pour', 'pray', 'prep', 'prev', 'prim', 'pros', 'pull', 'pure', 'push', 'quit', 'race', 'rail', 'rain', 'rank', 'rare', 'rate', 'read', 'real', 'rear', 'rely', 'rent', 'rest', 'rice', 'rich', 'ride', 'ring', 'rise', 'risk', 'road', 'rock', 'role', 'roll', 'roof', 'room', 'root', 'rope', 'rose', 'rule', 'rush', 'ruth', 'safe', 'sail', 'sale', 'salt', 'same', 'sand', 'save', 'seat', 'seed', 'seek', 'seem', 'seen', 'self', 'sell', 'send', 'sent', 'ship', 'shop', 'shot', 'show', 'shut', 'side', 'sign', 'site', 'size', 'skin', 'slip', 'slow', 'snow', 'soft', 'soil', 'sold', 'sole', 'some', 'song', 'soon', 'sort', 'soul', 'spot', 'star', 'stay', 'step', 'stop', 'such', 'suit', 'sure', 'take', 'tale', 'talk', 'tall', 'tank', 'tape', 'task', 'team', 'tech', 'tell', 'tend', 'term', 'test', 'text', 'than', 'that', 'thee', 'them', 'then', 'they', 'thin', 'this', 'thus', 'tide', 'tied', 'till', 'time', 'tiny', 'told', 'toll', 'tone', 'tony', 'took', 'tool', 'tour', 'town', 'tree', 'trip', 'true', 'tube', 'turn', 'twin', 'type', 'unit', 'upon', 'used', 'user', 'vary', 'vast', 'very', 'vice', 'view', 'vote', 'wage', 'wait', 'wake', 'walk', 'wall', 'want', 'ward', 'warm', 'wash', 'wave', 'ways', 'weak', 'wear', 'week', 'well', 'went', 'were', 'west', 'what', 'when', 'whom', 'wide', 'wife', 'wild', 'will', 'wind', 'wine', 'wing', 'wire', 'wise', 'wish', 'with', 'wood', 'word', 'wore', 'work', 'yard', 'year', 'your', 'zero', 'zone',
];

export interface PassphraseOptions {
	wordCount: number;
	separator: string;
}

const DEFAULT_PASSPHRASE_OPTIONS: PassphraseOptions = {
	wordCount: 5,
	separator: '-',
};

export function generatePassphrase(options: PassphraseOptions = DEFAULT_PASSPHRASE_OPTIONS): string {
	const { wordCount, separator } = options;
	const words: string[] = [];
	for (let i = 0; i < wordCount; i++) {
		words.push(PASSPHRASE_WORDS[Math.floor(Math.random() * PASSPHRASE_WORDS.length)]);
	}
	return words.join(separator);
}
