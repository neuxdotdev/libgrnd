import { randomInt } from 'crypto'
import { ValidationError } from '../../../error.js'
export const PASSWORD_GENERATOR_MIN_LENGTH = 4 as const
export const PASSWORD_GENERATOR_MAX_LENGTH = 128 as const
export const PASSWORD_GENERATOR_DEFAULT_LENGTH = 16 as const
export const PASSWORD_GENERATOR_SECURE_LENGTH = 20 as const
export const PASSWORD_GENERATOR_MIN_COUNT = 1 as const
export const PASSWORD_GENERATOR_MAX_COUNT = 25 as const
export const PASSWORD_GENERATOR_DEFAULT_COUNT = 1 as const
export const PASSWORD_GENERATOR_MAX_GENERATION_ATTEMPTS = 10000 as const
export const PASSWORD_GENERATOR_RATE_LIMIT_WINDOW_MS = 60000 as const
export const PASSWORD_GENERATOR_RATE_LIMIT_MAX_REQUESTS = 100 as const
export const PASSWORD_GENERATOR_MAX_PASSWORD_LENGTH = 4096 as const
export const PASSWORD_GENERATOR_UPPERCASE_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
export const PASSWORD_GENERATOR_LOWERCASE_CHARS = 'abcdefghijklmnopqrstuvwxyz'
export const PASSWORD_GENERATOR_NUMBER_CHARS = '0123456789'
export const PASSWORD_GENERATOR_SYMBOL_CHARS = '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
export const PASSWORD_GENERATOR_AMBIGUOUS_CHARS = '0O1lI'
export const PASSWORD_GENERATOR_WHITESPACE_CHARS = ' \t\n\r'
export const PASSWORD_GENERATOR_ENTROPY_THRESHOLDS = Object.freeze([
	{ min: 0, max: 39, label: 'weak' as const, recommendation: 'Not recommended for production' },
	{ min: 40, max: 79, label: 'medium' as const, recommendation: 'Minimum for internal use' },
	{
		min: 80,
		max: 119,
		label: 'strong' as const,
		recommendation: 'Recommended for most use cases',
	},
	{
		min: 120,
		max: 159,
		label: 'very_strong' as const,
		recommendation: 'Recommended for sensitive data',
	},
	{ min: 160, max: Infinity, label: 'very_strong' as const, recommendation: 'Maximum security' },
] as const)
export const PASSWORD_GENERATOR_SUPPORTED_EXPORT_FORMATS = Object.freeze([
	'json',
	'txt',
	'csv',
	'env',
] as const)
export const PASSWORD_GENERATOR_VALIDATION_PATTERNS = Object.freeze({
	hasUppercase: /[A-Z]/,
	hasLowercase: /[a-z]/,
	hasNumber: /[0-9]/,
	hasSymbol: /[!"#$%&'()*+,\-./:;<=>?@[\\\]^_`{|}~]/,
	hasWhitespace: /\s/,
	hasRepeatingChars: /(.)\1{2,}/,
	hasSequentialChars:
		/(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|012|123|234|345|456|567|678|789)/i,
} as const)
export const PASSWORD_GENERATOR_COMMON_PASSWORDS = Object.freeze([
	'password',
	'123456',
	'12345678',
	'qwerty',
	'abc123',
	'monkey',
	'1234567',
	'letmein',
	'trustno1',
	'dragon',
	'baseball',
	'iloveyou',
	'master',
	'sunshine',
	'ashley',
	'bailey',
	'shadow',
	'123123',
	'654321',
	'superman',
	'qazwsx',
	'michael',
	'football',
	'password1',
	'password123',
	'welcome',
	'welcome1',
	'admin',
	'admin123',
	'root',
	'toor',
	'pass',
	'test',
	'guest',
	'master',
] as const)
export const PASSWORD_GENERATOR_MIN_ENTROPY_FOR_PRODUCTION = 80 as const
export const PASSWORD_GENERATOR_MIN_ENTROPY_FOR_SENSITIVE = 120 as const
export type PasswordGeneratorStrength = 'weak' | 'medium' | 'strong' | 'very_strong'
export type PasswordGeneratorExportFormat =
	(typeof PASSWORD_GENERATOR_SUPPORTED_EXPORT_FORMATS)[number]
export type PasswordGeneratorCharacterSet = 'uppercase' | 'lowercase' | 'numbers' | 'symbols'
export type PasswordGeneratorPreset = 'basic' | 'standard' | 'strong' | 'maximum' | 'pin' | 'apiKey'
export type PasswordGeneratorSecurityLevel = 'low' | 'medium' | 'high' | 'critical'
export interface PasswordGeneratorGenerateOptions {
	readonly count?: number
	readonly length?: number
	readonly useUppercase?: boolean
	readonly useLowercase?: boolean
	readonly useNumbers?: boolean
	readonly useSymbols?: boolean
	readonly excludeSimilar?: boolean
	readonly excludeChars?: string | readonly string[]
	readonly requireAllTypes?: boolean
	readonly minUppercase?: number
	readonly minLowercase?: number
	readonly minNumbers?: number
	readonly minSymbols?: number
	readonly excludeWhitespace?: boolean
	readonly excludeSequential?: boolean
	readonly excludeRepeating?: number
	readonly excludeCommonPasswords?: boolean
	readonly securityLevel?: PasswordGeneratorSecurityLevel
	readonly includeTimestamp?: boolean
	readonly includeEntropy?: boolean
}
export interface PasswordGeneratorItem {
	readonly password: string
	readonly timestamp?: number | undefined
	readonly entropyBits?: number | undefined
	readonly strength?: PasswordGeneratorStrength | undefined
}
export interface PasswordGeneratorValidationResult {
	readonly isValid: boolean
	readonly strength: PasswordGeneratorStrength
	readonly entropyBits: number
	readonly length: number
	readonly hasUppercase: boolean
	readonly hasLowercase: boolean
	readonly hasNumber: boolean
	readonly hasSymbol: boolean
	readonly hasWhitespace: boolean
	readonly hasRepeatingChars: boolean
	readonly hasSequentialChars: boolean
	readonly isCommonPassword: boolean
	readonly errors: readonly string[]
	readonly warnings: readonly string[]
	readonly securityScore: number
	readonly isProductionReady: boolean
}
export interface PasswordGeneratorGenerateMetadata {
	readonly count: number
	readonly length: number
	readonly useUppercase: boolean
	readonly useLowercase: boolean
	readonly useNumbers: boolean
	readonly useSymbols: boolean
	readonly excludeSimilar: boolean
	readonly excludeChars?: string | undefined
	readonly poolSize: number
	readonly entropyBits: number
	readonly strength: PasswordGeneratorStrength
	readonly requireAllTypes: boolean
	readonly minUppercase: number
	readonly minLowercase: number
	readonly minNumbers: number
	readonly minSymbols: number
	readonly excludeSequential: boolean
	readonly excludeRepeating: number
	readonly excludeCommonPasswords: boolean
	readonly generatedAt: number
	readonly securityLevel: PasswordGeneratorSecurityLevel
}
export interface PasswordGeneratorGenerateResult {
	readonly passwords: readonly PasswordGeneratorItem[]
	readonly meta: PasswordGeneratorGenerateMetadata
}
export interface PasswordGeneratorValidationOptions {
	readonly minEntropy?: number
	readonly minLength?: number
	readonly requireUppercase?: boolean
	readonly requireLowercase?: boolean
	readonly requireNumber?: boolean
	readonly requireSymbol?: boolean
	readonly excludeCommonPasswords?: boolean
	readonly checkProductionReady?: boolean
	readonly allowedLengths?: readonly number[]
}
export interface PasswordGeneratorPresetConfig {
	readonly length: number
	readonly useUppercase: boolean
	readonly useLowercase: boolean
	readonly useNumbers: boolean
	readonly useSymbols: boolean
	readonly requireAllTypes: boolean
	readonly excludeSimilar: boolean
	readonly excludeSequential: boolean
	readonly excludeRepeating: number
	readonly minUppercase: number
	readonly minLowercase: number
	readonly minNumbers: number
	readonly minSymbols: number
	readonly excludeCommonPasswords: boolean
	readonly securityLevel: PasswordGeneratorSecurityLevel
}
export class PasswordGeneratorValidationError extends ValidationError {
	constructor(message: string, context?: Record<string, unknown>) {
		super(message, { ...context, errorType: 'PasswordGeneratorValidationError' })
	}
}
export class PasswordGeneratorSecurityError extends Error {
	constructor(message: string, context?: Record<string, unknown>) {
		super(message)
		this.name = 'PasswordGeneratorSecurityError'
		if (context) {
			;(this as any).context = context
		}
	}
}
export class PasswordGeneratorRateLimitError extends Error {
	constructor(message: string, context?: Record<string, unknown>) {
		super(message)
		this.name = 'PasswordGeneratorRateLimitError'
		if (context) {
			;(this as any).context = context
		}
	}
}
function assertIsNumber(value: unknown, fieldName: string): number {
	if (typeof value !== 'number' || !Number.isFinite(value)) {
		throw new PasswordGeneratorValidationError(`${fieldName} must be a finite number`, {
			fieldName,
			value,
		})
	}
	return value
}
function assertIsInteger(value: number, fieldName: string): number {
	if (!Number.isInteger(value)) {
		throw new PasswordGeneratorValidationError(`${fieldName} must be an integer`, {
			fieldName,
			value,
		})
	}
	return value
}
function assertIsBoolean(value: unknown, fieldName: string): boolean {
	if (typeof value !== 'boolean') {
		throw new PasswordGeneratorValidationError(`${fieldName} must be a boolean`, {
			fieldName,
			value,
		})
	}
	return value
}
function assertIsString(value: unknown, fieldName: string): string {
	if (typeof value !== 'string') {
		throw new PasswordGeneratorValidationError(`${fieldName} must be a string`, {
			fieldName,
			value,
		})
	}
	return value
}
function sanitizeString(value: string): string {
	return value.trim().normalize('NFC')
}
function validateCount(count: unknown): number {
	const value = assertIsInteger(assertIsNumber(count, 'count'), 'count')
	if (value < PASSWORD_GENERATOR_MIN_COUNT) {
		throw new PasswordGeneratorValidationError(
			`count must be at least ${PASSWORD_GENERATOR_MIN_COUNT}`,
			{ count: value, minimum: PASSWORD_GENERATOR_MIN_COUNT },
		)
	}
	if (value > PASSWORD_GENERATOR_MAX_COUNT) {
		throw new PasswordGeneratorValidationError(
			`count must not exceed ${PASSWORD_GENERATOR_MAX_COUNT} (rate limit protection)`,
			{ count: value, maximum: PASSWORD_GENERATOR_MAX_COUNT },
		)
	}
	return value
}
function validateLength(length: unknown): number {
	const value = assertIsInteger(assertIsNumber(length, 'length'), 'length')
	if (value < PASSWORD_GENERATOR_MIN_LENGTH) {
		throw new PasswordGeneratorValidationError(
			`length must be at least ${PASSWORD_GENERATOR_MIN_LENGTH}`,
			{ length: value, minimum: PASSWORD_GENERATOR_MIN_LENGTH },
		)
	}
	if (value > PASSWORD_GENERATOR_MAX_LENGTH) {
		throw new PasswordGeneratorValidationError(
			`length must not exceed ${PASSWORD_GENERATOR_MAX_LENGTH}`,
			{ length: value, maximum: PASSWORD_GENERATOR_MAX_LENGTH },
		)
	}
	return value
}
function validateSecurityLevel(level: unknown): PasswordGeneratorSecurityLevel {
	const rawValue = assertIsString(level, 'securityLevel')
	const value = sanitizeString(rawValue)
	const allowedLevels: readonly PasswordGeneratorSecurityLevel[] = [
		'low',
		'medium',
		'high',
		'critical',
	]
	if (!allowedLevels.includes(value as PasswordGeneratorSecurityLevel)) {
		throw new PasswordGeneratorValidationError(
			`securityLevel must be one of: ${allowedLevels.join(', ')}`,
			{ securityLevel: value, allowedLevels },
		)
	}
	return value as PasswordGeneratorSecurityLevel
}
function parseExcludeChars(excludeChars: unknown): string {
	if (excludeChars === undefined || excludeChars === null) {
		return ''
	}
	if (Array.isArray(excludeChars)) {
		for (const ch of excludeChars) {
			if (typeof ch !== 'string' || ch.length !== 1) {
				throw new PasswordGeneratorValidationError(
					'excludeChars array must contain single-character strings',
					{ invalid: ch },
				)
			}
		}
		return excludeChars.join('')
	}
	if (typeof excludeChars === 'string') {
		return excludeChars
	}
	throw new PasswordGeneratorValidationError(
		'excludeChars must be a string or array of strings',
		{ excludeChars },
	)
}
function passwordValidateOptions(
	options: PasswordGeneratorGenerateOptions,
): Required<Omit<PasswordGeneratorGenerateOptions, 'excludeChars'>> & { excludeChars: string } {
	const count = validateCount(options.count ?? PASSWORD_GENERATOR_DEFAULT_COUNT)
	const length = validateLength(options.length ?? PASSWORD_GENERATOR_DEFAULT_LENGTH)
	const useUppercase = assertIsBoolean(options.useUppercase ?? true, 'useUppercase')
	const useLowercase = assertIsBoolean(options.useLowercase ?? true, 'useLowercase')
	const useNumbers = assertIsBoolean(options.useNumbers ?? true, 'useNumbers')
	const useSymbols = assertIsBoolean(options.useSymbols ?? true, 'useSymbols')
	const excludeSimilar = assertIsBoolean(options.excludeSimilar ?? false, 'excludeSimilar')
	const requireAllTypes = assertIsBoolean(options.requireAllTypes ?? false, 'requireAllTypes')
	const excludeWhitespace = assertIsBoolean(
		options.excludeWhitespace ?? true,
		'excludeWhitespace',
	)
	const excludeSequential = assertIsBoolean(
		options.excludeSequential ?? false,
		'excludeSequential',
	)
	const excludeRepeating = assertIsInteger(
		assertIsNumber(options.excludeRepeating ?? 0, 'excludeRepeating'),
		'excludeRepeating',
	)
	const minUppercase = assertIsInteger(
		assertIsNumber(options.minUppercase ?? 0, 'minUppercase'),
		'minUppercase',
	)
	const minLowercase = assertIsInteger(
		assertIsNumber(options.minLowercase ?? 0, 'minLowercase'),
		'minLowercase',
	)
	const minNumbers = assertIsInteger(
		assertIsNumber(options.minNumbers ?? 0, 'minNumbers'),
		'minNumbers',
	)
	const minSymbols = assertIsInteger(
		assertIsNumber(options.minSymbols ?? 0, 'minSymbols'),
		'minSymbols',
	)
	const excludeCommonPasswords = assertIsBoolean(
		options.excludeCommonPasswords ?? false,
		'excludeCommonPasswords',
	)
	const includeTimestamp = assertIsBoolean(options.includeTimestamp ?? false, 'includeTimestamp')
	const includeEntropy = assertIsBoolean(options.includeEntropy ?? false, 'includeEntropy')
	const securityLevel = validateSecurityLevel(options.securityLevel ?? 'medium')
	const excludeChars = parseExcludeChars(options.excludeChars)
	const minRequired = minUppercase + minLowercase + minNumbers + minSymbols
	if (minRequired > length) {
		throw new PasswordGeneratorValidationError(
			`Sum of minimum character requirements (${minRequired}) exceeds password length (${length})`,
			{ minRequired, length },
		)
	}
	if (!useUppercase && !useLowercase && !useNumbers && !useSymbols) {
		throw new PasswordGeneratorValidationError('At least one character set must be selected', {
			useUppercase,
			useLowercase,
			useNumbers,
			useSymbols,
		})
	}
	if (securityLevel === 'critical' && length < PASSWORD_GENERATOR_SECURE_LENGTH) {
		throw new PasswordGeneratorSecurityError(
			`Critical security level requires minimum ${PASSWORD_GENERATOR_SECURE_LENGTH} characters`,
			{ securityLevel, length, required: PASSWORD_GENERATOR_SECURE_LENGTH },
		)
	}
	if (securityLevel === 'high' && length < 16) {
		throw new PasswordGeneratorSecurityError(
			'High security level requires minimum 16 characters',
			{ securityLevel, length, required: 16 },
		)
	}
	if (excludeRepeating < 0) {
		throw new PasswordGeneratorValidationError(
			'excludeRepeating must be a non-negative integer',
			{ excludeRepeating },
		)
	}
	return {
		count,
		length,
		useUppercase,
		useLowercase,
		useNumbers,
		useSymbols,
		excludeSimilar,
		excludeChars,
		requireAllTypes,
		excludeWhitespace,
		excludeSequential,
		excludeRepeating,
		minUppercase,
		minLowercase,
		minNumbers,
		minSymbols,
		excludeCommonPasswords,
		includeTimestamp,
		includeEntropy,
		securityLevel,
	}
}
function passwordBuildCharacterPool(
	options: Required<Omit<PasswordGeneratorGenerateOptions, 'excludeChars'>> & {
		excludeChars: string
	},
): string {
	let pool = ''
	if (options.useUppercase) pool += PASSWORD_GENERATOR_UPPERCASE_CHARS
	if (options.useLowercase) pool += PASSWORD_GENERATOR_LOWERCASE_CHARS
	if (options.useNumbers) pool += PASSWORD_GENERATOR_NUMBER_CHARS
	if (options.useSymbols) pool += PASSWORD_GENERATOR_SYMBOL_CHARS
	const excludeSet = new Set<string>(options.excludeChars.split(''))
	if (options.excludeWhitespace) {
		for (const ch of PASSWORD_GENERATOR_WHITESPACE_CHARS) {
			excludeSet.add(ch)
		}
	}
	if (options.excludeSimilar) {
		for (const ch of PASSWORD_GENERATOR_AMBIGUOUS_CHARS) {
			excludeSet.add(ch)
		}
	}
	if (excludeSet.size > 0) {
		pool = pool
			.split('')
			.filter((ch) => !excludeSet.has(ch))
			.join('')
	}
	if (pool.length === 0) {
		throw new PasswordGeneratorValidationError('Character pool is empty after exclusions', {
			excludeSimilar: options.excludeSimilar,
			excludeChars: options.excludeChars,
			excludeWhitespace: options.excludeWhitespace,
		})
	}
	return pool
}
export function passwordCalculateEntropy(poolSize: number, length: number): number {
	if (poolSize <= 0 || length <= 0) return 0
	const entropy = length * Math.log2(poolSize)
	return Math.round(entropy * 10) / 10
}
export function passwordGetStrength(entropyBits: number): PasswordGeneratorStrength {
	if (!Number.isFinite(entropyBits)) {
		return 'weak'
	}
	const threshold = PASSWORD_GENERATOR_ENTROPY_THRESHOLDS.find(
		(t) => entropyBits >= t.min && entropyBits <= t.max,
	)
	return threshold?.label ?? 'weak'
}
export function passwordGetSecurityLevel(entropyBits: number): PasswordGeneratorSecurityLevel {
	if (entropyBits >= PASSWORD_GENERATOR_MIN_ENTROPY_FOR_SENSITIVE) {
		return 'critical'
	}
	if (entropyBits >= PASSWORD_GENERATOR_MIN_ENTROPY_FOR_PRODUCTION) {
		return 'high'
	}
	if (entropyBits >= 60) {
		return 'medium'
	}
	return 'low'
}
export function passwordGetPoolSize(options: {
	useUppercase: boolean
	useLowercase: boolean
	useNumbers: boolean
	useSymbols: boolean
	excludeSimilar: boolean
	excludeChars: string
	excludeWhitespace: boolean
}): number {
	let poolSize = 0
	if (options.useUppercase) poolSize += PASSWORD_GENERATOR_UPPERCASE_CHARS.length
	if (options.useLowercase) poolSize += PASSWORD_GENERATOR_LOWERCASE_CHARS.length
	if (options.useNumbers) poolSize += PASSWORD_GENERATOR_NUMBER_CHARS.length
	if (options.useSymbols) poolSize += PASSWORD_GENERATOR_SYMBOL_CHARS.length
	const excludeSet = new Set<string>(options.excludeChars.split(''))
	if (options.excludeWhitespace) {
		for (const ch of PASSWORD_GENERATOR_WHITESPACE_CHARS) {
			excludeSet.add(ch)
		}
	}
	if (options.excludeSimilar) {
		for (const ch of PASSWORD_GENERATOR_AMBIGUOUS_CHARS) {
			excludeSet.add(ch)
		}
	}
	return poolSize - excludeSet.size
}
export function passwordCalculateSecurityScore(
	validation: PasswordGeneratorValidationResult,
): number {
	let score = 0
	score += Math.min(40, (validation.entropyBits / 160) * 40)
	if (!validation.isCommonPassword) {
		score += 20
	}
	if (validation.errors.length === 0) {
		score += 25
	}
	if (validation.warnings.length === 0) {
		score += 15
	}
	return Math.round(score)
}
export function passwordHasUppercase(password: string): boolean {
	return PASSWORD_GENERATOR_VALIDATION_PATTERNS.hasUppercase.test(password)
}
export function passwordHasLowercase(password: string): boolean {
	return PASSWORD_GENERATOR_VALIDATION_PATTERNS.hasLowercase.test(password)
}
export function passwordHasNumber(password: string): boolean {
	return PASSWORD_GENERATOR_VALIDATION_PATTERNS.hasNumber.test(password)
}
export function passwordHasSymbol(password: string): boolean {
	return PASSWORD_GENERATOR_VALIDATION_PATTERNS.hasSymbol.test(password)
}
export function passwordHasWhitespace(password: string): boolean {
	return PASSWORD_GENERATOR_VALIDATION_PATTERNS.hasWhitespace.test(password)
}
export function passwordHasRepeatingChars(password: string, maxRepeat: number = 3): boolean {
	if (maxRepeat <= 0) return false
	let count = 1
	for (let i = 1; i < password.length; i++) {
		if (password[i] === password[i - 1]) {
			count++
			if (count > maxRepeat) return true
		} else {
			count = 1
		}
	}
	return false
}
export function passwordHasSequentialChars(password: string): boolean {
	const lower = password.toLowerCase()
	for (let i = 0; i < lower.length - 2; i++) {
		const c1 = lower.charCodeAt(i)
		const c2 = lower.charCodeAt(i + 1)
		const c3 = lower.charCodeAt(i + 2)
		if (c2 === c1 + 1 && c3 === c2 + 1) return true
		if (c2 === c1 - 1 && c3 === c2 - 1) return true
	}
	return false
}
export function passwordIsCommonPassword(password: string): boolean {
	const lower = password.toLowerCase()
	return PASSWORD_GENERATOR_COMMON_PASSWORDS.includes(lower as any)
}
export function passwordCountCharTypes(password: string): {
	uppercase: number
	lowercase: number
	numbers: number
	symbols: number
} {
	let uppercase = 0
	let lowercase = 0
	let numbers = 0
	let symbols = 0
	for (const ch of password) {
		if (/[A-Z]/.test(ch)) uppercase++
		else if (/[a-z]/.test(ch)) lowercase++
		else if (/[0-9]/.test(ch)) numbers++
		else if (PASSWORD_GENERATOR_VALIDATION_PATTERNS.hasSymbol.test(ch)) symbols++
	}
	return { uppercase, lowercase, numbers, symbols }
}
function passwordSatisfiesRequirements(
	password: string,
	options: Required<Omit<PasswordGeneratorGenerateOptions, 'excludeChars'>> & {
		excludeChars: string
	},
): boolean {
	const charTypes = passwordCountCharTypes(password)
	if (charTypes.uppercase < options.minUppercase) return false
	if (charTypes.lowercase < options.minLowercase) return false
	if (charTypes.numbers < options.minNumbers) return false
	if (charTypes.symbols < options.minSymbols) return false
	if (options.excludeSequential && passwordHasSequentialChars(password)) return false
	if (
		options.excludeRepeating > 0 &&
		passwordHasRepeatingChars(password, options.excludeRepeating)
	)
		return false
	if (options.excludeCommonPasswords && passwordIsCommonPassword(password)) return false
	return true
}
function* passwordGenerateItems(
	count: number,
	pool: string,
	length: number,
	options: Required<Omit<PasswordGeneratorGenerateOptions, 'excludeChars'>> & {
		excludeChars: string
	},
): Generator<PasswordGeneratorItem, void, unknown> {
	const poolArray = pool.split('')
	const poolSize = poolArray.length
	const maxAttempts = PASSWORD_GENERATOR_MAX_GENERATION_ATTEMPTS
	for (let i = 0; i < count; i++) {
		let attempts = 0
		let password = ''
		let satisfied = false
		while (!satisfied && attempts < maxAttempts) {
			let pwd = ''
			for (let j = 0; j < length; j++) {
				const idx = randomInt(0, poolSize)
				pwd += poolArray[idx]!
			}
			if (passwordSatisfiesRequirements(pwd, options)) {
				password = pwd
				satisfied = true
			}
			attempts++
		}
		if (!satisfied) {
			throw new PasswordGeneratorValidationError(
				`Failed to generate password after ${maxAttempts} attempts. Constraints may be too strict.`,
				{
					useUppercase: options.useUppercase,
					useLowercase: options.useLowercase,
					useNumbers: options.useNumbers,
					useSymbols: options.useSymbols,
					requireAllTypes: options.requireAllTypes,
					length,
					minUppercase: options.minUppercase,
					minLowercase: options.minLowercase,
					minNumbers: options.minNumbers,
					minSymbols: options.minSymbols,
				},
			)
		}
		const timestamp = options.includeTimestamp ? Math.floor(Date.now() / 1000) : undefined
		let entropyBits: number | undefined
		let strength: PasswordGeneratorStrength | undefined
		if (options.includeEntropy) {
			entropyBits = passwordCalculateEntropy(poolSize, length)
			strength = passwordGetStrength(entropyBits)
		}
		const item: PasswordGeneratorItem = {
			password,
			timestamp,
			entropyBits,
			strength,
		}
		yield item
	}
}
function passwordBuildMetadata(
	validated: Required<Omit<PasswordGeneratorGenerateOptions, 'excludeChars'>> & {
		excludeChars: string
	},
	poolSize: number,
	entropyBits: number,
	strength: PasswordGeneratorStrength,
): PasswordGeneratorGenerateMetadata {
	const securityLevel = passwordGetSecurityLevel(entropyBits)
	const base: Omit<PasswordGeneratorGenerateMetadata, 'excludeChars'> = {
		count: validated.count,
		length: validated.length,
		useUppercase: validated.useUppercase,
		useLowercase: validated.useLowercase,
		useNumbers: validated.useNumbers,
		useSymbols: validated.useSymbols,
		excludeSimilar: validated.excludeSimilar,
		poolSize,
		entropyBits,
		strength,
		requireAllTypes: validated.requireAllTypes,
		minUppercase: validated.minUppercase,
		minLowercase: validated.minLowercase,
		minNumbers: validated.minNumbers,
		minSymbols: validated.minSymbols,
		excludeSequential: validated.excludeSequential,
		excludeRepeating: validated.excludeRepeating,
		excludeCommonPasswords: validated.excludeCommonPasswords,
		generatedAt: Math.floor(Date.now() / 1000),
		securityLevel,
	}
	if (validated.excludeChars && validated.excludeChars.length > 0) {
		return { ...base, excludeChars: validated.excludeChars }
	}
	return base as PasswordGeneratorGenerateMetadata
}
export function passwordGenerateTokens(
	options: PasswordGeneratorGenerateOptions = {},
): PasswordGeneratorGenerateResult {
	const validated = passwordValidateOptions(options)
	const pool = passwordBuildCharacterPool(validated)
	const generator = passwordGenerateItems(validated.count, pool, validated.length, validated)
	const passwords: PasswordGeneratorItem[] = []
	for (const item of generator) {
		passwords.push(item)
	}
	const entropyBits = passwordCalculateEntropy(pool.length, validated.length)
	const strength = passwordGetStrength(entropyBits)
	const metadata = passwordBuildMetadata(validated, pool.length, entropyBits, strength)
	return {
		passwords: Object.freeze(passwords) as readonly PasswordGeneratorItem[],
		meta: Object.freeze(metadata),
	}
}
export function passwordGenerateToken(
	options: PasswordGeneratorGenerateOptions = {},
): PasswordGeneratorItem {
	const result = passwordGenerateTokens({ ...options, count: 1 })
	const password = result.passwords[0]
	if (!password) {
		throw new PasswordGeneratorSecurityError(
			'Failed to generate password - passwords array is empty',
		)
	}
	return password
}
export function passwordGenerateString(options: PasswordGeneratorGenerateOptions = {}): string {
	const password = passwordGenerateToken({ ...options, count: 1 })
	return password.password
}
export function passwordGenerateSample(): PasswordGeneratorItem {
	return passwordGenerateTokens({
		count: 1,
		length: PASSWORD_GENERATOR_DEFAULT_LENGTH,
	}).passwords[0]!
}
export function passwordGenerateBasic(count: number = 1): PasswordGeneratorGenerateResult {
	return passwordGenerateTokens({
		count,
		length: 10,
		useUppercase: true,
		useLowercase: true,
		useNumbers: true,
		useSymbols: false,
		requireAllTypes: false,
		securityLevel: 'low',
	})
}
export function passwordGenerateStandard(count: number = 1): PasswordGeneratorGenerateResult {
	return passwordGenerateTokens({
		count,
		length: 14,
		useUppercase: true,
		useLowercase: true,
		useNumbers: true,
		useSymbols: true,
		requireAllTypes: true,
		excludeSimilar: true,
		securityLevel: 'medium',
	})
}
export function passwordGenerateSecure(count: number = 1): PasswordGeneratorGenerateResult {
	return passwordGenerateTokens({
		count,
		length: 18,
		useUppercase: true,
		useLowercase: true,
		useNumbers: true,
		useSymbols: true,
		requireAllTypes: true,
		excludeSimilar: true,
		excludeSequential: true,
		excludeRepeating: 3,
		minUppercase: 2,
		minLowercase: 2,
		minNumbers: 2,
		minSymbols: 2,
		excludeCommonPasswords: true,
		securityLevel: 'high',
	})
}
export function passwordGenerateMaximum(count: number = 1): PasswordGeneratorGenerateResult {
	return passwordGenerateTokens({
		count,
		length: 24,
		useUppercase: true,
		useLowercase: true,
		useNumbers: true,
		useSymbols: true,
		requireAllTypes: true,
		excludeSimilar: true,
		excludeSequential: true,
		excludeRepeating: 2,
		minUppercase: 3,
		minLowercase: 3,
		minNumbers: 3,
		minSymbols: 3,
		excludeCommonPasswords: true,
		securityLevel: 'critical',
	})
}
export function passwordGeneratePin(count: number = 1): PasswordGeneratorGenerateResult {
	return passwordGenerateTokens({
		count,
		length: 6,
		useUppercase: false,
		useLowercase: false,
		useNumbers: true,
		useSymbols: false,
		requireAllTypes: false,
		securityLevel: 'low',
	})
}
export function passwordGenerateApiKey(count: number = 1): PasswordGeneratorGenerateResult {
	return passwordGenerateTokens({
		count,
		length: 32,
		useUppercase: true,
		useLowercase: true,
		useNumbers: true,
		useSymbols: false,
		requireAllTypes: true,
		excludeSimilar: true,
		securityLevel: 'high',
	})
}
export function passwordValidate(
	password: string,
	validationOptions?: PasswordGeneratorValidationOptions,
): PasswordGeneratorValidationResult {
	const errors: string[] = []
	const warnings: string[] = []
	if (!password || typeof password !== 'string') {
		return {
			isValid: false,
			strength: 'weak',
			entropyBits: 0,
			length: 0,
			hasUppercase: false,
			hasLowercase: false,
			hasNumber: false,
			hasSymbol: false,
			hasWhitespace: false,
			hasRepeatingChars: false,
			hasSequentialChars: false,
			isCommonPassword: false,
			errors: Object.freeze(['Password is empty or invalid']) as readonly string[],
			warnings: Object.freeze([]) as readonly string[],
			securityScore: 0,
			isProductionReady: false,
		}
	}
	const length = password.length
	const minLength = validationOptions?.minLength ?? PASSWORD_GENERATOR_MIN_LENGTH
	if (length < minLength) {
		errors.push(`Password must be at least ${minLength} characters`)
	}
	if (validationOptions?.allowedLengths && !validationOptions.allowedLengths.includes(length)) {
		errors.push(
			`Password length must be one of: ${validationOptions.allowedLengths.join(', ')}`,
		)
	}
	if (length < 8) {
		warnings.push('Password is shorter than recommended (8 characters)')
	}
	const hasUppercase = passwordHasUppercase(password)
	const hasLowercase = passwordHasLowercase(password)
	const hasNumber = passwordHasNumber(password)
	const hasSymbol = passwordHasSymbol(password)
	const hasWhitespace = passwordHasWhitespace(password)
	const hasRepeatingChars = passwordHasRepeatingChars(password)
	const hasSequentialChars = passwordHasSequentialChars(password)
	const isCommonPassword = passwordIsCommonPassword(password)
	if (validationOptions?.requireUppercase && !hasUppercase) {
		errors.push('Password must contain at least one uppercase letter')
	}
	if (validationOptions?.requireLowercase && !hasLowercase) {
		errors.push('Password must contain at least one lowercase letter')
	}
	if (validationOptions?.requireNumber && !hasNumber) {
		errors.push('Password must contain at least one number')
	}
	if (validationOptions?.requireSymbol && !hasSymbol) {
		errors.push('Password must contain at least one symbol')
	}
	if (validationOptions?.excludeCommonPasswords && isCommonPassword) {
		errors.push('Password is a commonly used password')
	}
	if (hasWhitespace) {
		warnings.push('Password contains whitespace characters')
	}
	if (hasRepeatingChars) {
		warnings.push('Password contains repeating characters (3+ consecutive)')
	}
	if (hasSequentialChars) {
		warnings.push('Password contains sequential characters')
	}
	if (isCommonPassword) {
		warnings.push('Password is a commonly used password')
	}
	let poolSize = 0
	if (hasUppercase) poolSize += PASSWORD_GENERATOR_UPPERCASE_CHARS.length
	if (hasLowercase) poolSize += PASSWORD_GENERATOR_LOWERCASE_CHARS.length
	if (hasNumber) poolSize += PASSWORD_GENERATOR_NUMBER_CHARS.length
	if (hasSymbol) poolSize += PASSWORD_GENERATOR_SYMBOL_CHARS.length
	if (poolSize === 0) poolSize = 95
	const entropyBits = passwordCalculateEntropy(poolSize, length)
	const strength = passwordGetStrength(entropyBits)
	if (validationOptions?.minEntropy && entropyBits < validationOptions.minEntropy) {
		errors.push(
			`Password entropy (${entropyBits}) is below minimum required (${validationOptions.minEntropy})`,
		)
	}
	if (strength === 'weak') {
		errors.push('Password strength is too weak')
	} else if (strength === 'medium') {
		warnings.push('Password strength could be improved')
	}
	const isProductionReady =
		errors.length === 0 &&
		entropyBits >= PASSWORD_GENERATOR_MIN_ENTROPY_FOR_PRODUCTION &&
		!isCommonPassword
	if (validationOptions?.checkProductionReady && !isProductionReady) {
		errors.push('Password is not production-ready')
	}
	const baseResult = {
		isValid: errors.length === 0,
		strength,
		entropyBits,
		length,
		hasUppercase,
		hasLowercase,
		hasNumber,
		hasSymbol,
		hasWhitespace,
		hasRepeatingChars,
		hasSequentialChars,
		isCommonPassword,
		errors: Object.freeze(errors) as readonly string[],
		warnings: Object.freeze(warnings) as readonly string[],
	}
	const securityScore = passwordCalculateSecurityScore(
		baseResult as PasswordGeneratorValidationResult,
	)
	return {
		...baseResult,
		securityScore,
		isProductionReady,
	}
}
export function passwordIsStrong(
	password: string,
	minEntropy: number = PASSWORD_GENERATOR_MIN_ENTROPY_FOR_PRODUCTION,
): boolean {
	const validation = passwordValidate(password)
	return validation.isValid && validation.entropyBits >= minEntropy
}
export function passwordIsProductionReady(password: string): boolean {
	const validation = passwordValidate(password, { checkProductionReady: true })
	return validation.isProductionReady
}
export function passwordCalculateEntropyFromString(password: string): number {
	return passwordValidate(password).entropyBits
}
export function passwordExportTokens(
	result: PasswordGeneratorGenerateResult,
	format: PasswordGeneratorExportFormat = 'json',
): string {
	const { passwords, meta } = result
	if (!passwords || passwords.length === 0) {
		throw new PasswordGeneratorValidationError('No passwords to export', { passwordCount: 0 })
	}
	switch (format) {
		case 'json':
			return JSON.stringify({ meta, passwords }, null, 2)
		case 'txt':
			return passwords.map((p) => p.password).join('\n')
		case 'csv': {
			const escapeCsv = (str: string): string => {
				if (str.includes('"') || str.includes(',') || str.includes('\n')) {
					return `"${str.replace(/"/g, '""')}"`
				}
				return str
			}
			const firstItem = passwords[0]
			const hasTimestamp = firstItem?.timestamp !== undefined
			const hasEntropy = firstItem?.entropyBits !== undefined
			const headers = ['password']
			if (hasTimestamp) headers.push('timestamp')
			if (hasEntropy) headers.push('entropyBits')
			if (hasEntropy) headers.push('strength')
			const rows = passwords.map((p) => {
				const cols = [escapeCsv(p.password)]
				if (hasTimestamp && p.timestamp !== undefined) {
					cols.push(p.timestamp.toString())
				}
				if (hasEntropy && p.entropyBits !== undefined) {
					cols.push(p.entropyBits.toString())
				}
				if (hasEntropy && p.strength !== undefined) {
					cols.push(p.strength)
				}
				return cols.join(',')
			})
			return [headers.join(','), ...rows].join('\n')
		}
		case 'env': {
			const envPrefix = 'PASSWORD'
			return passwords.map((p, i) => `${envPrefix}_${i + 1}="${p.password}"`).join('\n')
		}
		default:
			throw new PasswordGeneratorValidationError(`Unsupported export format: ${format}`, {
				format,
			})
	}
}
export function passwordExportToEnv(
	result: PasswordGeneratorGenerateResult,
	prefix: string = 'PASSWORD',
): string {
	const rawPrefix = assertIsString(prefix, 'prefix')
	const validatedPrefix = sanitizeString(rawPrefix)
	if (!validatedPrefix || validatedPrefix.length === 0) {
		throw new PasswordGeneratorValidationError('Environment variable prefix cannot be empty')
	}
	if (!/^[A-Z][A-Z0-9_]*$/.test(validatedPrefix)) {
		throw new PasswordGeneratorValidationError(
			'Environment variable prefix must be uppercase alphanumeric with underscores',
		)
	}
	const { passwords } = result
	return passwords.map((p, i) => `${validatedPrefix}_${i + 1}="${p.password}"`).join('\n')
}
export const passwordPresets = Object.freeze({
	basic: {
		length: 10,
		useUppercase: true,
		useLowercase: true,
		useNumbers: true,
		useSymbols: false,
		requireAllTypes: false,
		excludeSimilar: false,
		excludeSequential: false,
		excludeRepeating: 0,
		minUppercase: 0,
		minLowercase: 0,
		minNumbers: 0,
		minSymbols: 0,
		excludeCommonPasswords: false,
		securityLevel: 'low' as PasswordGeneratorSecurityLevel,
	},
	standard: {
		length: 14,
		useUppercase: true,
		useLowercase: true,
		useNumbers: true,
		useSymbols: true,
		requireAllTypes: true,
		excludeSimilar: true,
		excludeSequential: false,
		excludeRepeating: 0,
		minUppercase: 1,
		minLowercase: 1,
		minNumbers: 1,
		minSymbols: 1,
		excludeCommonPasswords: false,
		securityLevel: 'medium' as PasswordGeneratorSecurityLevel,
	},
	strong: {
		length: 18,
		useUppercase: true,
		useLowercase: true,
		useNumbers: true,
		useSymbols: true,
		requireAllTypes: true,
		excludeSimilar: true,
		excludeSequential: true,
		excludeRepeating: 3,
		minUppercase: 2,
		minLowercase: 2,
		minNumbers: 2,
		minSymbols: 2,
		excludeCommonPasswords: true,
		securityLevel: 'high' as PasswordGeneratorSecurityLevel,
	},
	maximum: {
		length: 24,
		useUppercase: true,
		useLowercase: true,
		useNumbers: true,
		useSymbols: true,
		requireAllTypes: true,
		excludeSimilar: true,
		excludeSequential: true,
		excludeRepeating: 2,
		minUppercase: 3,
		minLowercase: 3,
		minNumbers: 3,
		minSymbols: 3,
		excludeCommonPasswords: true,
		securityLevel: 'critical' as PasswordGeneratorSecurityLevel,
	},
	pin: {
		length: 6,
		useUppercase: false,
		useLowercase: false,
		useNumbers: true,
		useSymbols: false,
		requireAllTypes: false,
		excludeSimilar: false,
		excludeSequential: false,
		excludeRepeating: 0,
		minUppercase: 0,
		minLowercase: 0,
		minNumbers: 0,
		minSymbols: 0,
		excludeCommonPasswords: false,
		securityLevel: 'low' as PasswordGeneratorSecurityLevel,
	},
	apiKey: {
		length: 32,
		useUppercase: true,
		useLowercase: true,
		useNumbers: true,
		useSymbols: false,
		requireAllTypes: true,
		excludeSimilar: true,
		excludeSequential: false,
		excludeRepeating: 0,
		minUppercase: 4,
		minLowercase: 4,
		minNumbers: 4,
		minSymbols: 0,
		excludeCommonPasswords: false,
		securityLevel: 'high' as PasswordGeneratorSecurityLevel,
	},
} as const satisfies Record<PasswordGeneratorPreset, PasswordGeneratorPresetConfig>)
export function passwordGenerateWithPreset(
	preset: PasswordGeneratorPreset,
	overrides: Partial<PasswordGeneratorGenerateOptions> = {},
): PasswordGeneratorGenerateResult {
	const baseOptions = passwordPresets[preset]
	if (!baseOptions) {
		throw new PasswordGeneratorValidationError(`Unknown preset: ${preset}`, {
			preset,
			availablePresets: Object.keys(passwordPresets),
		})
	}
	return passwordGenerateTokens({ ...baseOptions, ...overrides })
}
export function passwordGetLengthStrength(length: number): PasswordGeneratorStrength {
	const entropyBits = passwordCalculateEntropy(95, length)
	return passwordGetStrength(entropyBits)
}
export function passwordCompareLengths(len1: number, len2: number): number {
	const strength1 = passwordGetLengthStrength(len1)
	const strength2 = passwordGetLengthStrength(len2)
	const strengthOrder: Record<PasswordGeneratorStrength, number> = {
		weak: 0,
		medium: 1,
		strong: 2,
		very_strong: 3,
	}
	return strengthOrder[strength2] - strengthOrder[strength1]
}
export function passwordIsLengthSecure(
	length: number,
	minStrength: PasswordGeneratorStrength = 'strong',
): boolean {
	const strength = passwordGetLengthStrength(length)
	const strengthOrder: Record<PasswordGeneratorStrength, number> = {
		weak: 0,
		medium: 1,
		strong: 2,
		very_strong: 3,
	}
	return strengthOrder[strength] >= strengthOrder[minStrength]
}
export function passwordGetRecommendedLength(
	securityLevel: PasswordGeneratorSecurityLevel,
): number {
	switch (securityLevel) {
		case 'critical':
			return 24
		case 'high':
			return 18
		case 'medium':
			return 14
		case 'low':
			return 10
		default:
			return 14
	}
}
export function passwordGetSecurityReport(password: string): {
	readonly score: number
	readonly strength: PasswordGeneratorStrength
	readonly isProductionReady: boolean
	readonly recommendations: readonly string[]
} {
	const validation = passwordValidate(password)
	const recommendations: string[] = []
	if (validation.entropyBits < PASSWORD_GENERATOR_MIN_ENTROPY_FOR_PRODUCTION) {
		recommendations.push('Increase password length for production use (minimum 14 characters)')
	}
	if (validation.length < 12) {
		recommendations.push('Use minimum 12 characters for better security')
	}
	if (validation.isCommonPassword) {
		recommendations.push('Avoid commonly used passwords')
	}
	if (validation.hasSequentialChars) {
		recommendations.push('Avoid sequential characters (abc, 123, etc.)')
	}
	if (validation.hasRepeatingChars) {
		recommendations.push('Avoid consecutive repeating characters (aaa, 111, etc.)')
	}
	if (!validation.hasUppercase) {
		recommendations.push('Add uppercase letters for better security')
	}
	if (!validation.hasLowercase) {
		recommendations.push('Add lowercase letters for better security')
	}
	if (!validation.hasNumber) {
		recommendations.push('Add numbers for better security')
	}
	if (!validation.hasSymbol) {
		recommendations.push('Add symbols for better security')
	}
	if (validation.warnings.length > 0) {
		recommendations.push(`Address ${validation.warnings.length} warning(s)`)
	}
	return {
		score: validation.securityScore,
		strength: validation.strength,
		isProductionReady: validation.isProductionReady,
		recommendations: Object.freeze(recommendations) as readonly string[],
	}
}
export class PasswordGenerator {
	private readonly options: Required<Omit<PasswordGeneratorGenerateOptions, 'excludeChars'>> & {
		excludeChars: string
	}
	private readonly pool: string
	private readonly entropyBits: number
	private readonly strength: PasswordGeneratorStrength
	private readonly securityLevel: PasswordGeneratorSecurityLevel
	private static requestCount = 0
	private static lastRequestTime = 0
	constructor(options: PasswordGeneratorGenerateOptions = {}) {
		this.options = passwordValidateOptions(options)
		this.pool = passwordBuildCharacterPool(this.options)
		this.entropyBits = passwordCalculateEntropy(this.pool.length, this.options.length)
		this.strength = passwordGetStrength(this.entropyBits)
		this.securityLevel = this.options.securityLevel
	}
	private static checkRateLimit(): void {
		const now = Date.now()
		if (now - PasswordGenerator.lastRequestTime > PASSWORD_GENERATOR_RATE_LIMIT_WINDOW_MS) {
			PasswordGenerator.requestCount = 0
			PasswordGenerator.lastRequestTime = now
		}
		if (PasswordGenerator.requestCount >= PASSWORD_GENERATOR_RATE_LIMIT_MAX_REQUESTS) {
			throw new PasswordGeneratorRateLimitError(
				`Rate limit exceeded: ${PASSWORD_GENERATOR_RATE_LIMIT_MAX_REQUESTS} requests per minute`,
			)
		}
		PasswordGenerator.requestCount++
	}
	public generate(): PasswordGeneratorGenerateResult {
		PasswordGenerator.checkRateLimit()
		const generator = passwordGenerateItems(
			this.options.count,
			this.pool,
			this.options.length,
			this.options,
		)
		const passwords: PasswordGeneratorItem[] = []
		for (const item of generator) {
			passwords.push(item)
		}
		const metadata = passwordBuildMetadata(
			this.options,
			this.pool.length,
			this.entropyBits,
			this.strength,
		)
		return {
			passwords: Object.freeze(passwords) as readonly PasswordGeneratorItem[],
			meta: Object.freeze(metadata),
		}
	}
	public generateOne(): string {
		const result = this.generate()
		return result.passwords[0]?.password ?? ''
	}
	public generateBasic(count: number = 1): PasswordGeneratorGenerateResult {
		return passwordGenerateBasic(count)
	}
	public generateStandard(count: number = 1): PasswordGeneratorGenerateResult {
		return passwordGenerateStandard(count)
	}
	public generateSecure(count: number = 1): PasswordGeneratorGenerateResult {
		return passwordGenerateSecure(count)
	}
	public generateMaximum(count: number = 1): PasswordGeneratorGenerateResult {
		return passwordGenerateMaximum(count)
	}
	public generatePin(count: number = 1): PasswordGeneratorGenerateResult {
		return passwordGeneratePin(count)
	}
	public generateApiKey(count: number = 1): PasswordGeneratorGenerateResult {
		return passwordGenerateApiKey(count)
	}
	public export(
		result: PasswordGeneratorGenerateResult,
		format: PasswordGeneratorExportFormat = 'json',
	): string {
		return passwordExportTokens(result, format)
	}
	public exportToEnv(
		result: PasswordGeneratorGenerateResult,
		prefix: string = 'PASSWORD',
	): string {
		return passwordExportToEnv(result, prefix)
	}
	public validate(
		password: string,
		options?: PasswordGeneratorValidationOptions,
	): PasswordGeneratorValidationResult {
		return passwordValidate(password, options)
	}
	public isStrong(password: string, minEntropy?: number): boolean {
		return passwordIsStrong(password, minEntropy)
	}
	public isProductionReady(password: string): boolean {
		return passwordIsProductionReady(password)
	}
	public getPoolSize(): number {
		return this.pool.length
	}
	public getEntropyBits(): number {
		return this.entropyBits
	}
	public getStrength(): PasswordGeneratorStrength {
		return this.strength
	}
	public getSecurityLevel(): PasswordGeneratorSecurityLevel {
		return this.securityLevel
	}
	public getOptions(): Readonly<
		Required<Omit<PasswordGeneratorGenerateOptions, 'excludeChars'>> & {
			excludeChars: string
		}
	> {
		return Object.freeze({ ...this.options })
	}
	public static resetRateLimit(): void {
		PasswordGenerator.requestCount = 0
		PasswordGenerator.lastRequestTime = 0
	}
}
export function passwordGeneratorDebugInfo(): {
	readonly version: string
	readonly supportedExportFormats: readonly PasswordGeneratorExportFormat[]
	readonly constants: Record<string, unknown>
} {
	return {
		version: '1.0.0',
		supportedExportFormats: [...PASSWORD_GENERATOR_SUPPORTED_EXPORT_FORMATS],
		constants: {
			MIN_LENGTH: PASSWORD_GENERATOR_MIN_LENGTH,
			MAX_LENGTH: PASSWORD_GENERATOR_MAX_LENGTH,
			SECURE_LENGTH: PASSWORD_GENERATOR_SECURE_LENGTH,
			MIN_COUNT: PASSWORD_GENERATOR_MIN_COUNT,
			MAX_COUNT: PASSWORD_GENERATOR_MAX_COUNT,
			MAX_GENERATION_ATTEMPTS: PASSWORD_GENERATOR_MAX_GENERATION_ATTEMPTS,
			MIN_ENTROPY_PRODUCTION: PASSWORD_GENERATOR_MIN_ENTROPY_FOR_PRODUCTION,
			MIN_ENTROPY_SENSITIVE: PASSWORD_GENERATOR_MIN_ENTROPY_FOR_SENSITIVE,
			RATE_LIMIT_WINDOW_MS: PASSWORD_GENERATOR_RATE_LIMIT_WINDOW_MS,
			RATE_LIMIT_MAX_REQUESTS: PASSWORD_GENERATOR_RATE_LIMIT_MAX_REQUESTS,
			UPPERCASE_CHARS: PASSWORD_GENERATOR_UPPERCASE_CHARS.length,
			LOWERCASE_CHARS: PASSWORD_GENERATOR_LOWERCASE_CHARS.length,
			NUMBER_CHARS: PASSWORD_GENERATOR_NUMBER_CHARS.length,
			SYMBOL_CHARS: PASSWORD_GENERATOR_SYMBOL_CHARS.length,
			AMBIGUOUS_CHARS: PASSWORD_GENERATOR_AMBIGUOUS_CHARS,
			COMMON_PASSWORDS_COUNT: PASSWORD_GENERATOR_COMMON_PASSWORDS.length,
		},
	}
}
export function passwordGeneratorBenchmark(iterations: number = 100): {
	readonly avgTimeMs: number
	readonly totalTimeMs: number
	readonly iterations: number
	readonly passwordsPerSecond: number
} {
	const startTime = Date.now()
	for (let i = 0; i < iterations; i++) {
		passwordGenerateTokens({ count: 1, length: 16 })
	}
	const endTime = Date.now()
	const totalTimeMs = endTime - startTime
	const avgTimeMs = totalTimeMs / iterations
	const passwordsPerSecond = (iterations / totalTimeMs) * 1000
	return {
		avgTimeMs: Math.round(avgTimeMs * 100) / 100,
		totalTimeMs,
		iterations,
		passwordsPerSecond: Math.round(passwordsPerSecond * 100) / 100,
	}
}
export default {
	generate: passwordGenerateTokens,
	generateOne: passwordGenerateToken,
	generateString: passwordGenerateString,
	generateBasic: passwordGenerateBasic,
	generateStandard: passwordGenerateStandard,
	generateSecure: passwordGenerateSecure,
	generateMaximum: passwordGenerateMaximum,
	generatePin: passwordGeneratePin,
	generateApiKey: passwordGenerateApiKey,
	generateWithPreset: passwordGenerateWithPreset,
	validate: passwordValidate,
	isStrong: passwordIsStrong,
	isProductionReady: passwordIsProductionReady,
	export: passwordExportTokens,
	exportToEnv: passwordExportToEnv,
	getSecurityReport: passwordGetSecurityReport,
	Generator: PasswordGenerator,
	presets: passwordPresets,
	helpers: {
		hasUppercase: passwordHasUppercase,
		hasLowercase: passwordHasLowercase,
		hasNumber: passwordHasNumber,
		hasSymbol: passwordHasSymbol,
		hasWhitespace: passwordHasWhitespace,
		hasRepeatingChars: passwordHasRepeatingChars,
		hasSequentialChars: passwordHasSequentialChars,
		isCommonPassword: passwordIsCommonPassword,
		countCharTypes: passwordCountCharTypes,
		calculateEntropy: passwordCalculateEntropy,
		getStrength: passwordGetStrength,
		getSecurityLevel: passwordGetSecurityLevel,
		getLengthStrength: passwordGetLengthStrength,
		compareLengths: passwordCompareLengths,
		isLengthSecure: passwordIsLengthSecure,
		getRecommendedLength: passwordGetRecommendedLength,
	},
	debug: {
		info: passwordGeneratorDebugInfo,
		benchmark: passwordGeneratorBenchmark,
	},
	constants: {
		MIN_LENGTH: PASSWORD_GENERATOR_MIN_LENGTH,
		MAX_LENGTH: PASSWORD_GENERATOR_MAX_LENGTH,
		SECURE_LENGTH: PASSWORD_GENERATOR_SECURE_LENGTH,
		MIN_COUNT: PASSWORD_GENERATOR_MIN_COUNT,
		MAX_COUNT: PASSWORD_GENERATOR_MAX_COUNT,
		MAX_GENERATION_ATTEMPTS: PASSWORD_GENERATOR_MAX_GENERATION_ATTEMPTS,
		MIN_ENTROPY_PRODUCTION: PASSWORD_GENERATOR_MIN_ENTROPY_FOR_PRODUCTION,
		MIN_ENTROPY_SENSITIVE: PASSWORD_GENERATOR_MIN_ENTROPY_FOR_SENSITIVE,
		RATE_LIMIT_WINDOW_MS: PASSWORD_GENERATOR_RATE_LIMIT_WINDOW_MS,
		RATE_LIMIT_MAX_REQUESTS: PASSWORD_GENERATOR_RATE_LIMIT_MAX_REQUESTS,
		UPPERCASE_CHARS: PASSWORD_GENERATOR_UPPERCASE_CHARS,
		LOWERCASE_CHARS: PASSWORD_GENERATOR_LOWERCASE_CHARS,
		NUMBER_CHARS: PASSWORD_GENERATOR_NUMBER_CHARS,
		SYMBOL_CHARS: PASSWORD_GENERATOR_SYMBOL_CHARS,
		AMBIGUOUS_CHARS: PASSWORD_GENERATOR_AMBIGUOUS_CHARS,
		COMMON_PASSWORDS: PASSWORD_GENERATOR_COMMON_PASSWORDS,
		VALIDATION_PATTERNS: PASSWORD_GENERATOR_VALIDATION_PATTERNS,
	},
}
