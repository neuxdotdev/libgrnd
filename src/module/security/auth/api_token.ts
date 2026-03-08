import { randomBytes } from 'crypto'
import { ValidationError } from '../../../error.js'
export const API_TOKEN_SUPPORTED_BIT_LENGTHS = Object.freeze([
	64, 128, 256, 512, 1024, 2048,
] as const)
export const API_TOKEN_SUPPORTED_FORMATS = Object.freeze([
	'base64url',
	'base64',
	'hex',
	'alphanumeric',
] as const)
export const API_TOKEN_SUPPORTED_EXPORT_FORMATS = Object.freeze(['json', 'txt', 'csv'] as const)
export const API_TOKEN_PRESETS = Object.freeze([
	'basic',
	'standard',
	'strong',
	'maximum',
	'short',
	'long',
] as const) as readonly string[]
export const API_TOKEN_MIN_COUNT = 1 as const
export const API_TOKEN_MAX_COUNT = 25 as const
export const API_TOKEN_DEFAULT_COUNT = 1 as const
export const API_TOKEN_DEFAULT_BIT_LENGTH = 256 as const
export const API_TOKEN_MIN_BIT_LENGTH = 128 as const
export const API_TOKEN_RECOMMENDED_BIT_LENGTH = 256 as const
export const API_TOKEN_SECURE_BIT_LENGTH = 512 as const
export const API_TOKEN_MAX_PREFIX_LENGTH = 20 as const
export const API_TOKEN_MIN_PREFIX_LENGTH = 1 as const
export const API_TOKEN_MAX_TOKEN_LENGTH = 4096 as const
export const API_TOKEN_PREFIX_REGEX = /^[a-zA-Z][a-zA-Z0-9_]{0,19}$/
export const API_TOKEN_PREFIX_REGEX_STRICT = /^[a-zA-Z][a-zA-Z0-9_]{2,19}$/
export const API_TOKEN_BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
export const API_TOKEN_ENTROPY_THRESHOLDS = Object.freeze([
	{ min: 0, max: 64, label: 'weak' as const, recommendation: 'Not recommended for production' },
	{ min: 65, max: 128, label: 'medium' as const, recommendation: 'Minimum for internal use' },
	{ min: 129, max: 192, label: 'strong' as const, recommendation: 'Recommended for most APIs' },
	{
		min: 193,
		max: 256,
		label: 'very_strong' as const,
		recommendation: 'Recommended for sensitive data',
	},
	{ min: 257, max: Infinity, label: 'very_strong' as const, recommendation: 'Maximum security' },
] as const)
export const API_TOKEN_MIN_ENTROPY_FOR_PRODUCTION = 193 as const
export const API_TOKEN_MIN_ENTROPY_FOR_SENSITIVE = 256 as const
export const API_TOKEN_RATE_LIMIT_WINDOW_MS = 60000 as const
export const API_TOKEN_RATE_LIMIT_MAX_REQUESTS = 100 as const
export type ApiTokenBitLength = (typeof API_TOKEN_SUPPORTED_BIT_LENGTHS)[number]
export type ApiTokenFormat = (typeof API_TOKEN_SUPPORTED_FORMATS)[number]
export type ApiTokenExportFormat = (typeof API_TOKEN_SUPPORTED_EXPORT_FORMATS)[number]
export type ApiTokenPreset = 'basic' | 'standard' | 'strong' | 'maximum' | 'short' | 'long'
export type ApiTokenStrength = 'weak' | 'medium' | 'strong' | 'very_strong'
export type ApiTokenSecurityLevel = 'low' | 'medium' | 'high' | 'critical'
export interface ApiTokenGenerateOptions {
	readonly count?: number
	readonly bitLength?: ApiTokenBitLength
	readonly format?: ApiTokenFormat
	readonly prefix?: string | undefined
	readonly includeTimestamp?: boolean
	readonly includeEntropy?: boolean
	readonly securityLevel?: ApiTokenSecurityLevel
}
export interface ApiTokenItem {
	readonly token: string
	readonly timestamp?: number | undefined
	readonly entropyBits?: number | undefined
	readonly strength?: ApiTokenStrength | undefined
}
export interface ApiTokenGenerateMetadata {
	readonly count: number
	readonly bitLength: ApiTokenBitLength
	readonly format: ApiTokenFormat
	readonly prefix?: string | undefined
	readonly includeTimestamp: boolean
	readonly includeEntropy: boolean
	readonly byteLength: number
	readonly avgEntropyBits: number
	readonly strength: ApiTokenStrength
	readonly generatedAt: number
	readonly securityLevel: ApiTokenSecurityLevel
}
export interface ApiTokenGenerateResult {
	readonly tokens: readonly ApiTokenItem[]
	readonly meta: ApiTokenGenerateMetadata
}
export interface ApiTokenValidationResult {
	readonly isValid: boolean
	readonly strength: ApiTokenStrength
	readonly entropyBits: number
	readonly bitLength: number
	readonly format: ApiTokenFormat | 'unknown'
	readonly hasPrefix: boolean
	readonly prefix?: string | undefined
	readonly errors: readonly string[]
	readonly warnings: readonly string[]
	readonly securityScore: number
	readonly isProductionReady: boolean
}
export interface ApiTokenPresetConfig {
	readonly bitLength: ApiTokenBitLength
	readonly format: ApiTokenFormat
	readonly includeTimestamp: boolean
	readonly includeEntropy: boolean
	readonly securityLevel: ApiTokenSecurityLevel
}
export interface ApiTokenValidationOptions {
	readonly minEntropy?: number
	readonly requirePrefix?: boolean
	readonly allowedFormats?: readonly ApiTokenFormat[]
	readonly checkProductionReady?: boolean
}
export class ApiTokenValidationError extends ValidationError {
	constructor(message: string, context?: Record<string, unknown>) {
		super(message, { ...context, errorType: 'ApiTokenValidationError' })
	}
}
export class SecurityError extends Error {
	constructor(message: string, context?: Record<string, unknown>) {
		super(message)
		this.name = 'SecurityError'
		if (context) {
			;(this as any).context = context
		}
	}
}
export class ApiTokenSecurityError extends SecurityError {
	constructor(message: string, context?: Record<string, unknown>) {
		super(message, context)
		this.name = 'ApiTokenSecurityError'
	}
}
export class ApiTokenRateLimitError extends Error {
	constructor(message: string, context?: Record<string, unknown>) {
		super(message)
		this.name = 'ApiTokenRateLimitError'
		if (context) {
			;(this as any).context = context
		}
	}
}
function assertIsNumber(value: unknown, fieldName: string): number {
	if (typeof value !== 'number' || !Number.isFinite(value)) {
		throw new ApiTokenValidationError(`${fieldName} must be a finite number`, {
			fieldName,
			value,
		})
	}
	return value
}
function assertIsInteger(value: number, fieldName: string): number {
	if (!Number.isInteger(value)) {
		throw new ApiTokenValidationError(`${fieldName} must be an integer`, { fieldName, value })
	}
	return value
}
function assertIsBoolean(value: unknown, fieldName: string): boolean {
	if (typeof value !== 'boolean') {
		throw new ApiTokenValidationError(`${fieldName} must be a boolean`, { fieldName, value })
	}
	return value
}
function assertIsString(value: unknown, fieldName: string): string {
	if (typeof value !== 'string') {
		throw new ApiTokenValidationError(`${fieldName} must be a string`, { fieldName, value })
	}
	return value
}
function assertInArray<T>(value: T, allowedValues: readonly T[], fieldName: string): T {
	if (!allowedValues.includes(value)) {
		throw new ApiTokenValidationError(
			`${fieldName} must be one of: ${allowedValues.join(', ')}`,
			{ fieldName, value, allowedValues },
		)
	}
	return value
}
function sanitizeString(value: string): string {
	return value.trim().normalize('NFC')
}
function validateBitLength(bitLength: unknown): ApiTokenBitLength {
	const value = assertIsInteger(assertIsNumber(bitLength, 'bitLength'), 'bitLength')
	if (!API_TOKEN_SUPPORTED_BIT_LENGTHS.includes(value as ApiTokenBitLength)) {
		throw new ApiTokenValidationError(
			`bitLength must be one of: ${API_TOKEN_SUPPORTED_BIT_LENGTHS.join(', ')}`,
			{ bitLength: value, supportedValues: API_TOKEN_SUPPORTED_BIT_LENGTHS },
		)
	}
	if (value < API_TOKEN_MIN_BIT_LENGTH) {
		throw new ApiTokenSecurityError(
			`bitLength ${value} is below minimum security requirement (${API_TOKEN_MIN_BIT_LENGTH} bits)`,
			{ bitLength: value, minimum: API_TOKEN_MIN_BIT_LENGTH },
		)
	}
	return value as ApiTokenBitLength
}
function validateFormat(format: unknown): ApiTokenFormat {
	const value = assertInArray(
		assertIsString(format, 'format'),
		API_TOKEN_SUPPORTED_FORMATS,
		'format',
	)
	return value as ApiTokenFormat
}
function validateCount(count: unknown): number {
	const value = assertIsInteger(assertIsNumber(count, 'count'), 'count')
	if (value < API_TOKEN_MIN_COUNT) {
		throw new ApiTokenValidationError(`count must be at least ${API_TOKEN_MIN_COUNT}`, {
			count: value,
			minimum: API_TOKEN_MIN_COUNT,
		})
	}
	if (value > API_TOKEN_MAX_COUNT) {
		throw new ApiTokenValidationError(
			`count must not exceed ${API_TOKEN_MAX_COUNT} (rate limit protection)`,
			{ count: value, maximum: API_TOKEN_MAX_COUNT },
		)
	}
	return value
}
function validatePrefix(prefix: unknown): string | undefined {
	if (prefix === undefined || prefix === null) {
		return undefined
	}
	const value = sanitizeString(assertIsString(prefix, 'prefix'))
	if (value.length === 0) {
		return undefined
	}
	if (value.length < API_TOKEN_MIN_PREFIX_LENGTH) {
		throw new ApiTokenValidationError(
			`prefix must be at least ${API_TOKEN_MIN_PREFIX_LENGTH} character`,
			{ prefixLength: value.length, minimum: API_TOKEN_MIN_PREFIX_LENGTH },
		)
	}
	if (value.length > API_TOKEN_MAX_PREFIX_LENGTH) {
		throw new ApiTokenValidationError(
			`prefix must not exceed ${API_TOKEN_MAX_PREFIX_LENGTH} characters`,
			{ prefixLength: value.length, maximum: API_TOKEN_MAX_PREFIX_LENGTH },
		)
	}
	if (!API_TOKEN_PREFIX_REGEX.test(value)) {
		throw new ApiTokenValidationError(
			'prefix must start with a letter and contain only alphanumeric characters and underscores',
			{ prefix: value, pattern: API_TOKEN_PREFIX_REGEX.source },
		)
	}
	const forbiddenPrefixes = ['api', 'token', 'key', 'secret', 'auth', 'access']
	if (forbiddenPrefixes.some((fp) => value.toLowerCase().startsWith(fp))) {
		throw new ApiTokenSecurityError(
			`prefix cannot start with reserved words: ${forbiddenPrefixes.join(', ')}`,
			{ prefix: value, forbiddenPrefixes },
		)
	}
	return value
}
function validateSecurityLevel(level: unknown): ApiTokenSecurityLevel {
	const allowedLevels: readonly ApiTokenSecurityLevel[] = ['low', 'medium', 'high', 'critical']
	const value = assertInArray(
		assertIsString(level, 'securityLevel'),
		allowedLevels,
		'securityLevel',
	)
	return value as ApiTokenSecurityLevel
}
function validateOptions(
	options: ApiTokenGenerateOptions,
): Required<Omit<ApiTokenGenerateOptions, 'prefix'>> & { prefix?: string } {
	const count = validateCount(options.count ?? API_TOKEN_DEFAULT_COUNT)
	const bitLength = validateBitLength(options.bitLength ?? API_TOKEN_DEFAULT_BIT_LENGTH)
	const format = validateFormat(options.format ?? 'base64url')
	const prefix = validatePrefix(options.prefix)
	const includeTimestamp = assertIsBoolean(options.includeTimestamp ?? false, 'includeTimestamp')
	const includeEntropy = assertIsBoolean(options.includeEntropy ?? false, 'includeEntropy')
	const securityLevel = validateSecurityLevel(options.securityLevel ?? 'medium')
	if (securityLevel === 'critical' && bitLength < API_TOKEN_SECURE_BIT_LENGTH) {
		throw new ApiTokenSecurityError(
			`Critical security level requires minimum ${API_TOKEN_SECURE_BIT_LENGTH} bits`,
			{ securityLevel, bitLength, required: API_TOKEN_SECURE_BIT_LENGTH },
		)
	}
	if (securityLevel === 'high' && bitLength < API_TOKEN_RECOMMENDED_BIT_LENGTH) {
		throw new ApiTokenSecurityError(
			`High security level requires minimum ${API_TOKEN_RECOMMENDED_BIT_LENGTH} bits`,
			{ securityLevel, bitLength, required: API_TOKEN_RECOMMENDED_BIT_LENGTH },
		)
	}
	return {
		count,
		bitLength,
		format,
		includeTimestamp,
		includeEntropy,
		securityLevel,
		...(prefix !== undefined ? { prefix } : {}),
	}
}
function apiTokenBase32Encode(buffer: Buffer): string {
	if (!Buffer.isBuffer(buffer)) {
		throw new ApiTokenValidationError('Input must be a Buffer', { type: typeof buffer })
	}
	if (buffer.length === 0) {
		throw new ApiTokenValidationError('Buffer cannot be empty', { length: buffer.length })
	}
	let bits = 0
	let value = 0
	let output = ''
	for (const byte of buffer) {
		value = (value << 8) | byte
		bits += 8
		while (bits >= 5) {
			const index = (value >>> (bits - 5)) & 31
			output += API_TOKEN_BASE32_ALPHABET[index]
			bits -= 5
		}
	}
	if (bits > 0) {
		const index = (value << (5 - bits)) & 31
		output += API_TOKEN_BASE32_ALPHABET[index]
	}
	return output
}
const apiTokenFormatToEncoderFunctionMap: Record<ApiTokenFormat, (buf: Buffer) => string> = {
	base64url: (buf) => {
		if (!Buffer.isBuffer(buf)) throw new ApiTokenValidationError('Invalid buffer')
		return buf.toString('base64url')
	},
	base64: (buf) => {
		if (!Buffer.isBuffer(buf)) throw new ApiTokenValidationError('Invalid buffer')
		return buf.toString('base64').replace(/=+$/, '')
	},
	hex: (buf) => {
		if (!Buffer.isBuffer(buf)) throw new ApiTokenValidationError('Invalid buffer')
		return buf.toString('hex')
	},
	alphanumeric: apiTokenBase32Encode,
}
function apiTokenCalculateEntropy(bitLength: number): number {
	if (!Number.isFinite(bitLength)) {
		throw new ApiTokenValidationError('bitLength must be a finite number', { bitLength })
	}
	if (bitLength <= 0) {
		return 0
	}
	return Math.round(bitLength * 10) / 10
}
function apiTokenGetStrength(entropyBits: number): ApiTokenStrength {
	if (!Number.isFinite(entropyBits)) {
		return 'weak'
	}
	const threshold = API_TOKEN_ENTROPY_THRESHOLDS.find(
		(t) => entropyBits >= t.min && entropyBits <= t.max,
	)
	return threshold?.label ?? 'weak'
}
function apiTokenGetSecurityLevel(entropyBits: number): ApiTokenSecurityLevel {
	if (entropyBits >= API_TOKEN_MIN_ENTROPY_FOR_SENSITIVE) {
		return 'critical'
	}
	if (entropyBits >= API_TOKEN_MIN_ENTROPY_FOR_PRODUCTION) {
		return 'high'
	}
	if (entropyBits >= 128) {
		return 'medium'
	}
	return 'low'
}
function apiTokenGetPoolSize(format: ApiTokenFormat): number {
	switch (format) {
		case 'base64url':
		case 'base64':
			return 64
		case 'hex':
			return 16
		case 'alphanumeric':
			return 32
		default:
			return 64
	}
}
function apiTokenCalculateSecurityScore(validation: ApiTokenValidationResult): number {
	let score = 0
	score += Math.min(40, (validation.entropyBits / 256) * 40)
	if (validation.format !== 'unknown') {
		score += 20
	}
	if (validation.errors.length === 0) {
		score += 30
	}
	if (validation.warnings.length === 0) {
		score += 10
	}
	return Math.round(score)
}
function apiTokenGenerateSingleItem(
	validated: Required<Omit<ApiTokenGenerateOptions, 'prefix'>> & { prefix?: string },
): ApiTokenItem {
	const byteLength = validated.bitLength / 8
	if (!Number.isInteger(byteLength) || byteLength <= 0) {
		throw new ApiTokenSecurityError('Invalid byte length calculated', {
			bitLength: validated.bitLength,
		})
	}
	const bytes = randomBytes(byteLength)
	if (bytes.length !== byteLength) {
		throw new ApiTokenSecurityError('Failed to generate secure random bytes', {
			expected: byteLength,
			actual: bytes.length,
		})
	}
	const encoder = apiTokenFormatToEncoderFunctionMap[validated.format]
	if (!encoder) {
		throw new ApiTokenValidationError('Unsupported format encoder', {
			format: validated.format,
		})
	}
	const tokenRaw = encoder(bytes)
	if (!tokenRaw || tokenRaw.length === 0) {
		throw new ApiTokenSecurityError('Generated token is empty', { format: validated.format })
	}
	if (tokenRaw.length > API_TOKEN_MAX_TOKEN_LENGTH) {
		throw new ApiTokenSecurityError('Generated token exceeds maximum length', {
			length: tokenRaw.length,
			maximum: API_TOKEN_MAX_TOKEN_LENGTH,
		})
	}
	const token = validated.prefix ? `${validated.prefix}_${tokenRaw}` : tokenRaw
	const item: {
		token: string
		timestamp?: number
		entropyBits?: number
		strength?: ApiTokenStrength
	} = { token }
	if (validated.includeTimestamp) {
		item.timestamp = Math.floor(Date.now() / 1000)
	}
	if (validated.includeEntropy) {
		item.entropyBits = apiTokenCalculateEntropy(validated.bitLength)
		item.strength = apiTokenGetStrength(item.entropyBits)
	}
	return item as ApiTokenItem
}
function apiTokenBuildMetadata(
	validated: Required<Omit<ApiTokenGenerateOptions, 'prefix'>> & { prefix?: string },
	avgEntropyBits: number,
): ApiTokenGenerateMetadata {
	const byteLength = validated.bitLength / 8
	const strength = apiTokenGetStrength(avgEntropyBits)
	const securityLevel = apiTokenGetSecurityLevel(avgEntropyBits)
	const base = {
		count: validated.count,
		bitLength: validated.bitLength,
		format: validated.format,
		includeTimestamp: validated.includeTimestamp,
		includeEntropy: validated.includeEntropy,
		byteLength,
		avgEntropyBits,
		strength,
		generatedAt: Math.floor(Date.now() / 1000),
		securityLevel,
	}
	return validated.prefix !== undefined ? { ...base, prefix: validated.prefix } : base
}
function apiTokenDetectFormat(token: string): ApiTokenFormat | 'unknown' {
	if (!token || typeof token !== 'string') {
		return 'unknown'
	}
	const tokenWithoutPrefix = token.includes('_') ? token.split('_').slice(1).join('_') : token
	if (!tokenWithoutPrefix || tokenWithoutPrefix.length === 0) {
		return 'unknown'
	}
	if (/^[0-9a-fA-F]+$/.test(tokenWithoutPrefix)) return 'hex'
	if (/^[A-Z2-7]+$/.test(tokenWithoutPrefix)) return 'alphanumeric'
	if (/^[A-Za-z0-9_-]+$/.test(tokenWithoutPrefix)) return 'base64url'
	if (/^[A-Za-z0-9+/]+$/.test(tokenWithoutPrefix)) return 'base64'
	return 'unknown'
}
function apiTokenExtractPrefix(token: string): string | undefined {
	if (!token || typeof token !== 'string') {
		return undefined
	}
	if (!token.includes('_')) {
		return undefined
	}
	const parts = token.split('_')
	if (parts.length === 0 || !parts[0]) {
		return undefined
	}
	const potentialPrefix = parts[0]
	return potentialPrefix && API_TOKEN_PREFIX_REGEX.test(potentialPrefix)
		? potentialPrefix
		: undefined
}
export function apiTokenGenerateTokens(
	options: ApiTokenGenerateOptions = {},
): ApiTokenGenerateResult {
	const validated = validateOptions(options)
	const tokens: ApiTokenItem[] = []
	let totalEntropy = 0
	for (let i = 0; i < validated.count; i++) {
		const token = apiTokenGenerateSingleItem(validated)
		tokens.push(token)
		if (validated.includeEntropy && token.entropyBits !== undefined) {
			totalEntropy += token.entropyBits
		}
	}
	const avgEntropyBits = validated.includeEntropy
		? Math.round((totalEntropy / validated.count) * 10) / 10
		: apiTokenCalculateEntropy(validated.bitLength)
	const metadata = apiTokenBuildMetadata(validated, avgEntropyBits)
	return {
		tokens: Object.freeze(tokens) as readonly ApiTokenItem[],
		meta: Object.freeze(metadata),
	}
}
export function apiTokenGenerateToken(options: ApiTokenGenerateOptions = {}): ApiTokenItem {
	const result = apiTokenGenerateTokens({ ...options, count: 1 })
	const token = result.tokens[0]
	if (!token) {
		throw new ApiTokenSecurityError('Failed to generate token - tokens array is empty')
	}
	return token
}
export function apiTokenGenerateTokenString(options: ApiTokenGenerateOptions = {}): string {
	const token = apiTokenGenerateToken({ ...options, count: 1 })
	return token.token
}
export function apiTokenGenerateSample(): ApiTokenItem {
	return apiTokenGenerateTokens({
		count: 1,
		bitLength: 256,
		format: 'base64url',
	}).tokens[0]!
}
export function apiTokenGenerateStrong(
	options: Partial<ApiTokenGenerateOptions> = {},
): ApiTokenItem {
	return apiTokenGenerateTokens({
		count: 1,
		bitLength: options.bitLength ?? 512,
		format: options.format ?? 'base64url',
		includeTimestamp: true,
		includeEntropy: true,
		securityLevel: 'high',
		...options,
	}).tokens[0]!
}
export function apiTokenGenerateBasic(count: number = 1): ApiTokenGenerateResult {
	return apiTokenGenerateTokens({ count, bitLength: 128, format: 'base64url' })
}
export function apiTokenGenerateStandard(count: number = 1): ApiTokenGenerateResult {
	return apiTokenGenerateTokens({ count, bitLength: 256, format: 'base64url' })
}
export function apiTokenGenerateMaximum(count: number = 1): ApiTokenGenerateResult {
	return apiTokenGenerateTokens({
		count,
		bitLength: 2048,
		format: 'hex',
		includeTimestamp: true,
		includeEntropy: true,
		securityLevel: 'critical',
	})
}
export function apiTokenValidate(
	token: string,
	validationOptions?: ApiTokenValidationOptions,
): ApiTokenValidationResult {
	const errors: string[] = []
	const warnings: string[] = []
	if (!token || typeof token !== 'string') {
		return {
			isValid: false,
			strength: 'weak',
			entropyBits: 0,
			bitLength: 0,
			format: 'unknown',
			hasPrefix: false,
			errors: Object.freeze(['Token is empty or invalid']) as readonly string[],
			warnings: Object.freeze([]) as readonly string[],
			securityScore: 0,
			isProductionReady: false,
		}
	}
	if (token.length > API_TOKEN_MAX_TOKEN_LENGTH) {
		errors.push(`Token exceeds maximum length (${API_TOKEN_MAX_TOKEN_LENGTH} characters)`)
	}
	if (token.length < 20) {
		warnings.push('Token is unusually short')
	}
	const format = apiTokenDetectFormat(token)
	const prefix = apiTokenExtractPrefix(token)
	const hasPrefix = prefix !== undefined
	const tokenWithoutPrefix = hasPrefix ? token.split('_').slice(1).join('_') : token
	const tokenLength = tokenWithoutPrefix.length
	if (
		validationOptions?.allowedFormats &&
		!validationOptions.allowedFormats.includes(format as ApiTokenFormat)
	) {
		errors.push(`Token format '${format}' is not in allowed formats`)
	}
	if (validationOptions?.requirePrefix && !hasPrefix) {
		errors.push('Token is required to have a prefix')
	}
	let bitLength = 0
	if (format === 'hex') {
		bitLength = tokenLength * 4
	} else if (format === 'alphanumeric') {
		bitLength = Math.floor(tokenLength * 5)
	} else if (format === 'base64url' || format === 'base64') {
		bitLength = Math.floor(tokenLength * 6)
	}
	if (bitLength < API_TOKEN_MIN_BIT_LENGTH) {
		errors.push(`Token bit length is too short (minimum ${API_TOKEN_MIN_BIT_LENGTH} bits)`)
	}
	if (bitLength < API_TOKEN_RECOMMENDED_BIT_LENGTH) {
		warnings.push(
			`Token bit length is below recommended (${API_TOKEN_RECOMMENDED_BIT_LENGTH} bits)`,
		)
	}
	const entropyBits = apiTokenCalculateEntropy(bitLength)
	const strength = apiTokenGetStrength(entropyBits)
	if (validationOptions?.minEntropy && entropyBits < validationOptions.minEntropy) {
		errors.push(
			`Token entropy (${entropyBits}) is below minimum required (${validationOptions.minEntropy})`,
		)
	}
	if (strength === 'weak') {
		errors.push('Token strength is too weak')
	} else if (strength === 'medium') {
		warnings.push('Token strength could be improved')
	}
	const isProductionReady =
		errors.length === 0 && entropyBits >= API_TOKEN_MIN_ENTROPY_FOR_PRODUCTION
	if (validationOptions?.checkProductionReady && !isProductionReady) {
		errors.push('Token is not production-ready')
	}
	const baseResult = {
		isValid: errors.length === 0,
		strength,
		entropyBits,
		bitLength,
		format,
		hasPrefix,
		errors: Object.freeze(errors) as readonly string[],
		warnings: Object.freeze(warnings) as readonly string[],
	}
	const securityScore = apiTokenCalculateSecurityScore(baseResult as ApiTokenValidationResult)
	return {
		...baseResult,
		securityScore,
		isProductionReady,
		...(prefix !== undefined ? { prefix } : {}),
	}
}
export function apiTokenIsStrong(
	token: string,
	minEntropy: number = API_TOKEN_MIN_ENTROPY_FOR_PRODUCTION,
): boolean {
	const validation = apiTokenValidate(token)
	return validation.isValid && validation.entropyBits >= minEntropy
}
export function apiTokenIsProductionReady(token: string): boolean {
	const validation = apiTokenValidate(token, { checkProductionReady: true })
	return validation.isProductionReady
}
export function apiTokenCalculateEntropyFromToken(token: string): number {
	return apiTokenValidate(token).entropyBits
}
export function apiTokenExportTokens(
	result: ApiTokenGenerateResult,
	format: ApiTokenExportFormat = 'json',
): string {
	const { tokens, meta } = result
	if (!tokens || tokens.length === 0) {
		throw new ApiTokenValidationError('No tokens to export', { tokenCount: 0 })
	}
	switch (format) {
		case 'json':
			return JSON.stringify({ meta, tokens }, null, 2)
		case 'txt':
			return tokens.map((t) => t.token).join('\n')
		case 'csv': {
			const escapeCsv = (str: string): string => {
				if (str.includes('"') || str.includes(',') || str.includes('\n')) {
					return `"${str.replace(/"/g, '""')}"`
				}
				return str
			}
			const headers = ['token']
			if (meta.includeTimestamp) headers.push('timestamp')
			if (meta.includeEntropy) headers.push('entropyBits')
			if (meta.includeEntropy) headers.push('strength')
			const rows = tokens.map((t) => {
				const cols = [escapeCsv(t.token)]
				if (meta.includeTimestamp && t.timestamp !== undefined) {
					cols.push(t.timestamp.toString())
				}
				if (meta.includeEntropy && t.entropyBits !== undefined) {
					cols.push(t.entropyBits.toString())
				}
				if (meta.includeEntropy && t.strength !== undefined) {
					cols.push(t.strength)
				}
				return cols.join(',')
			})
			return [headers.join(','), ...rows].join('\n')
		}
		default:
			throw new ApiTokenValidationError(`Unsupported export format: ${format}`, { format })
	}
}
export function apiTokenExportToEnv(
	result: ApiTokenGenerateResult,
	prefix: string = 'API_TOKEN',
): string {
	if (!prefix || prefix.trim().length === 0) {
		throw new ApiTokenValidationError('Environment variable prefix cannot be empty')
	}
	if (!/^[A-Z][A-Z0-9_]*$/.test(prefix)) {
		throw new ApiTokenValidationError(
			'Environment variable prefix must be uppercase alphanumeric with underscores',
		)
	}
	return result.tokens.map((t, i) => `${prefix}_${i + 1}="${t.token}"`).join('\n')
}
export const apiTokenPresets = Object.freeze({
	basic: {
		bitLength: 128 as ApiTokenBitLength,
		format: 'base64url' as ApiTokenFormat,
		includeTimestamp: false,
		includeEntropy: false,
		securityLevel: 'low' as ApiTokenSecurityLevel,
	},
	standard: {
		bitLength: 256 as ApiTokenBitLength,
		format: 'base64url' as ApiTokenFormat,
		includeTimestamp: true,
		includeEntropy: true,
		securityLevel: 'medium' as ApiTokenSecurityLevel,
	},
	strong: {
		bitLength: 512 as ApiTokenBitLength,
		format: 'base64url' as ApiTokenFormat,
		includeTimestamp: true,
		includeEntropy: true,
		securityLevel: 'high' as ApiTokenSecurityLevel,
	},
	maximum: {
		bitLength: 2048 as ApiTokenBitLength,
		format: 'hex' as ApiTokenFormat,
		includeTimestamp: true,
		includeEntropy: true,
		securityLevel: 'critical' as ApiTokenSecurityLevel,
	},
	short: {
		bitLength: 128 as ApiTokenBitLength,
		format: 'hex' as ApiTokenFormat,
		includeTimestamp: true,
		includeEntropy: false,
		securityLevel: 'low' as ApiTokenSecurityLevel,
	},
	long: {
		bitLength: 1024 as ApiTokenBitLength,
		format: 'base64url' as ApiTokenFormat,
		includeTimestamp: true,
		includeEntropy: true,
		securityLevel: 'high' as ApiTokenSecurityLevel,
	},
} as const satisfies Record<ApiTokenPreset, ApiTokenPresetConfig>)
export function apiTokenGenerateWithPreset(
	preset: ApiTokenPreset,
	overrides: Partial<ApiTokenGenerateOptions> = {},
): ApiTokenGenerateResult {
	const baseOptions = apiTokenPresets[preset]
	if (!baseOptions) {
		throw new ApiTokenValidationError(`Unknown preset: ${preset}`, {
			preset,
			availablePresets: Object.keys(apiTokenPresets),
		})
	}
	return apiTokenGenerateTokens({ ...baseOptions, ...overrides })
}
export function apiTokenGetBitLengthStrength(bitLength: ApiTokenBitLength): ApiTokenStrength {
	return apiTokenGetStrength(apiTokenCalculateEntropy(bitLength))
}
export function apiTokenCompareBitLengths(
	len1: ApiTokenBitLength,
	len2: ApiTokenBitLength,
): number {
	const strengthOrder: Record<ApiTokenStrength, number> = {
		weak: 0,
		medium: 1,
		strong: 2,
		very_strong: 3,
	}
	return (
		strengthOrder[apiTokenGetBitLengthStrength(len2)] -
		strengthOrder[apiTokenGetBitLengthStrength(len1)]
	)
}
export function apiTokenIsBitLengthSecure(
	bitLength: ApiTokenBitLength,
	minStrength: ApiTokenStrength = 'strong',
): boolean {
	const strengthOrder: Record<ApiTokenStrength, number> = {
		weak: 0,
		medium: 1,
		strong: 2,
		very_strong: 3,
	}
	return strengthOrder[apiTokenGetBitLengthStrength(bitLength)] >= strengthOrder[minStrength]
}
export function apiTokenGetFormatStrength(format: ApiTokenFormat): ApiTokenStrength {
	const poolSize = apiTokenGetPoolSize(format)
	const entropyBits = Math.log2(poolSize) * 32
	return apiTokenGetStrength(entropyBits)
}
export function apiTokenIsFormatSecure(
	format: ApiTokenFormat,
	minStrength: ApiTokenStrength = 'strong',
): boolean {
	const strengthOrder: Record<ApiTokenStrength, number> = {
		weak: 0,
		medium: 1,
		strong: 2,
		very_strong: 3,
	}
	return strengthOrder[apiTokenGetFormatStrength(format)] >= strengthOrder[minStrength]
}
export function apiTokenGetRecommendedBitLength(
	securityLevel: ApiTokenSecurityLevel,
): ApiTokenBitLength {
	switch (securityLevel) {
		case 'critical':
			return 2048
		case 'high':
			return 512
		case 'medium':
			return 256
		case 'low':
			return 128
		default:
			return 256
	}
}
export class ApiTokenGenerator {
	private readonly options: Required<Omit<ApiTokenGenerateOptions, 'prefix'>> & {
		prefix?: string
	}
	private readonly entropyBits: number
	private readonly strength: ApiTokenStrength
	private readonly securityLevel: ApiTokenSecurityLevel
	private static requestCount = 0
	private static lastRequestTime = 0
	constructor(options: ApiTokenGenerateOptions = {}) {
		this.options = validateOptions(options)
		this.entropyBits = apiTokenCalculateEntropy(this.options.bitLength)
		this.strength = apiTokenGetStrength(this.entropyBits)
		this.securityLevel = this.options.securityLevel ?? 'medium'
	}
	private static checkRateLimit(): void {
		const now = Date.now()
		if (now - ApiTokenGenerator.lastRequestTime > API_TOKEN_RATE_LIMIT_WINDOW_MS) {
			ApiTokenGenerator.requestCount = 0
			ApiTokenGenerator.lastRequestTime = now
		}
		if (ApiTokenGenerator.requestCount >= API_TOKEN_RATE_LIMIT_MAX_REQUESTS) {
			throw new ApiTokenRateLimitError(
				`Rate limit exceeded: ${API_TOKEN_RATE_LIMIT_MAX_REQUESTS} requests per minute`,
			)
		}
		ApiTokenGenerator.requestCount++
	}
	public generate(): ApiTokenGenerateResult {
		ApiTokenGenerator.checkRateLimit()
		const tokens: ApiTokenItem[] = []
		let totalEntropy = 0
		for (let i = 0; i < this.options.count; i++) {
			const token = apiTokenGenerateSingleItem(this.options)
			tokens.push(token)
			if (this.options.includeEntropy && token.entropyBits !== undefined) {
				totalEntropy += token.entropyBits
			}
		}
		const avgEntropyBits = this.options.includeEntropy
			? Math.round((totalEntropy / this.options.count) * 10) / 10
			: this.entropyBits
		const metadata = apiTokenBuildMetadata(this.options, avgEntropyBits)
		return {
			tokens: Object.freeze(tokens) as readonly ApiTokenItem[],
			meta: Object.freeze(metadata),
		}
	}
	public generateOne(): string {
		return this.generate().tokens[0]!.token
	}
	public generateStrong(): ApiTokenItem {
		return apiTokenGenerateStrong({
			bitLength: Math.max(this.options.bitLength, 512) as ApiTokenBitLength,
			format: this.options.format,
			securityLevel: 'high',
		})
	}
	public generateBasic(count: number = 1): ApiTokenGenerateResult {
		return apiTokenGenerateBasic(count)
	}
	public generateStandard(count: number = 1): ApiTokenGenerateResult {
		return apiTokenGenerateStandard(count)
	}
	public generateMaximum(count: number = 1): ApiTokenGenerateResult {
		return apiTokenGenerateMaximum(count)
	}
	public export(result: ApiTokenGenerateResult, format: ApiTokenExportFormat = 'json'): string {
		return apiTokenExportTokens(result, format)
	}
	public exportToEnv(result: ApiTokenGenerateResult, prefix: string = 'API_TOKEN'): string {
		return apiTokenExportToEnv(result, prefix)
	}
	public validate(token: string, options?: ApiTokenValidationOptions): ApiTokenValidationResult {
		return apiTokenValidate(token, options)
	}
	public isStrong(token: string, minEntropy?: number): boolean {
		return apiTokenIsStrong(token, minEntropy)
	}
	public isProductionReady(token: string): boolean {
		return apiTokenIsProductionReady(token)
	}
	public getEntropyBits(): number {
		return this.entropyBits
	}
	public getStrength(): ApiTokenStrength {
		return this.strength
	}
	public getSecurityLevel(): ApiTokenSecurityLevel {
		return this.securityLevel
	}
	public getOptions(): Readonly<
		Required<Omit<ApiTokenGenerateOptions, 'prefix'>> & { prefix?: string }
	> {
		return Object.freeze({ ...this.options })
	}
	public static resetRateLimit(): void {
		ApiTokenGenerator.requestCount = 0
		ApiTokenGenerator.lastRequestTime = 0
	}
}
export function apiTokenSecureCompare(a: string, b: string): boolean {
	if (typeof a !== 'string' || typeof b !== 'string') {
		return false
	}
	if (a.length !== b.length) {
		return false
	}
	let result = 0
	for (let i = 0; i < a.length; i++) {
		result |= a.charCodeAt(i) ^ b.charCodeAt(i)
	}
	return result === 0
}
export function apiTokenGetSecurityReport(token: string): {
	readonly score: number
	readonly strength: ApiTokenStrength
	readonly isProductionReady: boolean
	readonly recommendations: readonly string[]
} {
	const validation = apiTokenValidate(token)
	const recommendations: string[] = []
	if (validation.entropyBits < API_TOKEN_MIN_ENTROPY_FOR_PRODUCTION) {
		recommendations.push('Increase token entropy to at least 193 bits for production use')
	}
	if (validation.bitLength < API_TOKEN_RECOMMENDED_BIT_LENGTH) {
		recommendations.push('Use minimum 256 bits for better security')
	}
	if (validation.format === 'unknown') {
		recommendations.push('Use a standard encoding format (base64url, hex, etc.)')
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
export default {
	generate: apiTokenGenerateTokens,
	generateOne: apiTokenGenerateToken,
	generateString: apiTokenGenerateTokenString,
	generateStrong: apiTokenGenerateStrong,
	generateBasic: apiTokenGenerateBasic,
	generateStandard: apiTokenGenerateStandard,
	generateMaximum: apiTokenGenerateMaximum,
	generateWithPreset: apiTokenGenerateWithPreset,
	validate: apiTokenValidate,
	isStrong: apiTokenIsStrong,
	isProductionReady: apiTokenIsProductionReady,
	export: apiTokenExportTokens,
	exportToEnv: apiTokenExportToEnv,
	getSecurityReport: apiTokenGetSecurityReport,
	Generator: ApiTokenGenerator,
	presets: apiTokenPresets,
	constants: {
		MIN_BIT_LENGTH: API_TOKEN_MIN_BIT_LENGTH,
		RECOMMENDED_BIT_LENGTH: API_TOKEN_RECOMMENDED_BIT_LENGTH,
		SECURE_BIT_LENGTH: API_TOKEN_SECURE_BIT_LENGTH,
		MIN_ENTROPY_PRODUCTION: API_TOKEN_MIN_ENTROPY_FOR_PRODUCTION,
		MIN_ENTROPY_SENSITIVE: API_TOKEN_MIN_ENTROPY_FOR_SENSITIVE,
		MAX_COUNT: API_TOKEN_MAX_COUNT,
		MAX_PREFIX_LENGTH: API_TOKEN_MAX_PREFIX_LENGTH,
	},
}
