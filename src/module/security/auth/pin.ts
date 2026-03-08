import { randomInt } from 'crypto'
import { ValidationError } from '../../../error.js'
export const PIN_VALID_LENGTHS = Object.freeze([4, 6, 8] as const)
export const PIN_MIN_COUNT = 1 as const
export const PIN_MAX_COUNT = 100 as const
export const PIN_DEFAULT_COUNT = 1 as const
export const PIN_MAX_GENERATION_ATTEMPTS = 1000 as const
export const PIN_RATE_LIMIT_WINDOW_MS = 60000 as const
export const PIN_RATE_LIMIT_MAX_REQUESTS = 100 as const
export const PIN_SUPPORTED_EXPORT_FORMATS = Object.freeze(['json', 'txt', 'csv'] as const)
export const PIN_ENTROPY_THRESHOLDS = Object.freeze([
	{ min: 0, max: 13, label: 'weak' as const, recommendation: 'Not recommended for production' },
	{ min: 14, max: 19, label: 'medium' as const, recommendation: 'Minimum for internal use' },
	{
		min: 20,
		max: 26,
		label: 'strong' as const,
		recommendation: 'Recommended for most use cases',
	},
	{ min: 27, max: Infinity, label: 'very_strong' as const, recommendation: 'Maximum security' },
] as const)
export const PIN_SEQUENTIAL_PATTERNS = Object.freeze([
	'012',
	'123',
	'234',
	'345',
	'456',
	'567',
	'678',
	'789',
	'987',
	'876',
	'765',
	'654',
	'543',
	'432',
	'321',
	'210',
] as const)
export const PIN_COMMON_PINS = Object.freeze([
	'0000',
	'1111',
	'2222',
	'3333',
	'4444',
	'5555',
	'6666',
	'7777',
	'8888',
	'9999',
	'1234',
	'4321',
	'1212',
	'1112',
	'1222',
	'1235',
	'1236',
	'1237',
	'1238',
	'1239',
	'1004',
	'2000',
	'2001',
	'2002',
	'2003',
	'2004',
	'2005',
	'2006',
	'2007',
	'2008',
	'2009',
	'2010',
	'2011',
	'2012',
	'2013',
	'2014',
	'2015',
	'2016',
	'2017',
	'2018',
	'2019',
	'2020',
	'2021',
	'2022',
	'2023',
	'2024',
	'2025',
	'1313',
	'1331',
	'1414',
	'1441',
	'1515',
	'1551',
	'7777',
	'8888',
	'9999',
	'0000',
	'1000',
	'2000',
	'3000',
	'4000',
	'5000',
	'6000',
	'7000',
	'8000',
	'9000',
	'1111',
	'2222',
	'3333',
	'4444',
	'5555',
	'6666',
	'7777',
	'8888',
	'9999',
	'0000',
] as const)
export const PIN_MIN_ENTROPY_FOR_PRODUCTION = 20 as const
export const PIN_MIN_ENTROPY_FOR_SENSITIVE = 26 as const
export type PinLength = (typeof PIN_VALID_LENGTHS)[number]
export type PinExportFormat = (typeof PIN_SUPPORTED_EXPORT_FORMATS)[number]
export type PinStrength = 'weak' | 'medium' | 'strong' | 'very_strong'
export type PinPreset = 'atm' | 'auth' | 'secure' | 'maximum'
export type PinSecurityLevel = 'low' | 'medium' | 'high' | 'critical'
export interface PinGenerateOptions {
	readonly count?: number
	readonly length?: PinLength
	readonly uniqueDigits?: boolean
	readonly excludeRepeating?: boolean
	readonly excludeSequential?: boolean
	readonly excludeZero?: boolean
	readonly excludeCommonPins?: boolean
	readonly includeTimestamp?: boolean
	readonly includeEntropy?: boolean
	readonly securityLevel?: PinSecurityLevel
}
export interface PinItem {
	readonly pin: string
	readonly timestamp?: number | undefined
	readonly entropyBits?: number | undefined
	readonly strength?: PinStrength | undefined
}
export interface PinGenerateMetadata {
	readonly count: number
	readonly length: PinLength
	readonly uniqueDigits: boolean
	readonly excludeRepeating: boolean
	readonly excludeSequential: boolean
	readonly excludeZero: boolean
	readonly excludeCommonPins: boolean
	readonly includeTimestamp: boolean
	readonly includeEntropy: boolean
	readonly poolSize: number
	readonly avgEntropyBits: number
	readonly strength: PinStrength
	readonly generatedAt: number
	readonly securityLevel: PinSecurityLevel
}
export interface PinGenerateResult {
	readonly pins: readonly PinItem[]
	readonly meta: PinGenerateMetadata
}
export interface PinValidationResult {
	readonly isValid: boolean
	readonly strength: PinStrength
	readonly entropyBits: number
	readonly length: number
	readonly hasRepeatingDigits: boolean
	readonly hasSequentialDigits: boolean
	readonly hasZero: boolean
	readonly hasAllUniqueDigits: boolean
	readonly isCommonPin: boolean
	readonly errors: readonly string[]
	readonly warnings: readonly string[]
	readonly securityScore: number
	readonly isProductionReady: boolean
}
export interface PinValidationOptions {
	readonly minEntropy?: number
	readonly requireUniqueDigits?: boolean
	readonly excludeSequential?: boolean
	readonly excludeCommonPins?: boolean
	readonly checkProductionReady?: boolean
	readonly allowedLengths?: readonly PinLength[]
}
export interface PinPresetConfig {
	readonly length: PinLength
	readonly uniqueDigits: boolean
	readonly excludeRepeating: boolean
	readonly excludeSequential: boolean
	readonly excludeZero: boolean
	readonly excludeCommonPins: boolean
	readonly includeTimestamp: boolean
	readonly includeEntropy: boolean
	readonly securityLevel: PinSecurityLevel
}
export class PinValidationError extends ValidationError {
	constructor(message: string, context?: Record<string, unknown>) {
		super(message, { ...context, errorType: 'PinValidationError' })
	}
}
export class PinSecurityError extends Error {
	constructor(message: string, context?: Record<string, unknown>) {
		super(message)
		this.name = 'PinSecurityError'
		if (context) {
			;(this as any).context = context
		}
	}
}
export class PinRateLimitError extends Error {
	constructor(message: string, context?: Record<string, unknown>) {
		super(message)
		this.name = 'PinRateLimitError'
		if (context) {
			;(this as any).context = context
		}
	}
}
function assertIsNumber(value: unknown, fieldName: string): number {
	if (typeof value !== 'number' || !Number.isFinite(value)) {
		throw new PinValidationError(`${fieldName} must be a finite number`, { fieldName, value })
	}
	return value
}
function assertIsInteger(value: number, fieldName: string): number {
	if (!Number.isInteger(value)) {
		throw new PinValidationError(`${fieldName} must be an integer`, { fieldName, value })
	}
	return value
}
function assertIsBoolean(value: unknown, fieldName: string): boolean {
	if (typeof value !== 'boolean') {
		throw new PinValidationError(`${fieldName} must be a boolean`, { fieldName, value })
	}
	return value
}
function assertInArray<T>(value: T, allowedValues: readonly T[], fieldName: string): T {
	if (!allowedValues.includes(value)) {
		throw new PinValidationError(`${fieldName} must be one of: ${allowedValues.join(', ')}`, {
			fieldName,
			value,
			allowedValues,
		})
	}
	return value
}
export function pinHasSequentialDigits(pin: string): boolean {
	for (const pattern of PIN_SEQUENTIAL_PATTERNS) {
		if (pin.includes(pattern)) return true
	}
	return false
}
export function pinHasConsecutiveRepeatingDigits(pin: string): boolean {
	for (let i = 0; i < pin.length - 1; i++) {
		if (pin[i] === pin[i + 1]) return true
	}
	return false
}
export function pinHasAllUniqueDigits(pin: string): boolean {
	const digitSet = new Set(pin)
	return digitSet.size === pin.length
}
export function pinContainsZero(pin: string): boolean {
	return pin.includes('0')
}
export function pinIsCommonPin(pin: string): boolean {
	return PIN_COMMON_PINS.includes(pin as any)
}
export function pinHasOnlyDigits(pin: string): boolean {
	return /^\d+$/.test(pin)
}
function validateCount(count: unknown): number {
	const value = assertIsInteger(assertIsNumber(count, 'count'), 'count')
	if (value < PIN_MIN_COUNT) {
		throw new PinValidationError(`count must be at least ${PIN_MIN_COUNT}`, {
			count: value,
			minimum: PIN_MIN_COUNT,
		})
	}
	if (value > PIN_MAX_COUNT) {
		throw new PinValidationError(
			`count must not exceed ${PIN_MAX_COUNT} (rate limit protection)`,
			{ count: value, maximum: PIN_MAX_COUNT },
		)
	}
	return value
}
function validateLength(length: unknown): PinLength {
	const value = assertIsInteger(assertIsNumber(length, 'length'), 'length')
	if (!PIN_VALID_LENGTHS.includes(value as PinLength)) {
		throw new PinValidationError(`length must be one of: ${PIN_VALID_LENGTHS.join(', ')}`, {
			length: value,
			validLengths: PIN_VALID_LENGTHS,
		})
	}
	return value as PinLength
}
function validateSecurityLevel(level: unknown): PinSecurityLevel {
	const allowedLevels: readonly PinSecurityLevel[] = ['low', 'medium', 'high', 'critical']
	const value = assertInArray(String(level), allowedLevels, 'securityLevel')
	return value as PinSecurityLevel
}
function pinValidateOptions(options: PinGenerateOptions): Required<
	Omit<PinGenerateOptions, 'includeTimestamp' | 'includeEntropy' | 'securityLevel'>
> & {
	includeTimestamp: boolean
	includeEntropy: boolean
	securityLevel: PinSecurityLevel
} {
	const count = validateCount(options.count ?? PIN_DEFAULT_COUNT)
	const length = validateLength(options.length ?? 4)
	const uniqueDigits = assertIsBoolean(options.uniqueDigits ?? false, 'uniqueDigits')
	const excludeRepeating = assertIsBoolean(options.excludeRepeating ?? false, 'excludeRepeating')
	const excludeSequential = assertIsBoolean(
		options.excludeSequential ?? false,
		'excludeSequential',
	)
	const excludeZero = assertIsBoolean(options.excludeZero ?? false, 'excludeZero')
	const excludeCommonPins = assertIsBoolean(
		options.excludeCommonPins ?? false,
		'excludeCommonPins',
	)
	const includeTimestamp = assertIsBoolean(options.includeTimestamp ?? false, 'includeTimestamp')
	const includeEntropy = assertIsBoolean(options.includeEntropy ?? false, 'includeEntropy')
	const securityLevel = validateSecurityLevel(options.securityLevel ?? 'medium')
	if (securityLevel === 'critical' && length < 8) {
		throw new PinSecurityError('Critical security level requires minimum 8-digit PIN', {
			securityLevel,
			length,
			required: 8,
		})
	}
	if (securityLevel === 'high' && length < 6) {
		throw new PinSecurityError('High security level requires minimum 6-digit PIN', {
			securityLevel,
			length,
			required: 6,
		})
	}
	if (uniqueDigits && length > 10) {
		throw new PinValidationError('uniqueDigits cannot be true for PIN length greater than 10', {
			uniqueDigits,
			length,
		})
	}
	return {
		count,
		length,
		uniqueDigits,
		excludeRepeating,
		excludeSequential,
		excludeZero,
		excludeCommonPins,
		includeTimestamp,
		includeEntropy,
		securityLevel,
	}
}
export function pinCalculateEntropyBits(length: number, uniqueDigits: boolean): number {
	if (length <= 0) return 0
	const poolSize = uniqueDigits ? 10 : 10
	const combinations = uniqueDigits
		? Array.from({ length }, (_, i) => 10 - i).reduce((a, b) => a * b, 1)
		: Math.pow(poolSize, length)
	const entropy = Math.log2(combinations)
	return Math.round(entropy * 10) / 10
}
export function pinGetStrength(entropyBits: number): PinStrength {
	if (!Number.isFinite(entropyBits)) {
		return 'weak'
	}
	const threshold = PIN_ENTROPY_THRESHOLDS.find(
		(t) => entropyBits >= t.min && entropyBits <= t.max,
	)
	return threshold?.label ?? 'weak'
}
export function pinGetSecurityLevel(entropyBits: number): PinSecurityLevel {
	if (entropyBits >= PIN_MIN_ENTROPY_FOR_SENSITIVE) {
		return 'critical'
	}
	if (entropyBits >= PIN_MIN_ENTROPY_FOR_PRODUCTION) {
		return 'high'
	}
	if (entropyBits >= 14) {
		return 'medium'
	}
	return 'low'
}
export function pinGetPoolSize(uniqueDigits: boolean): number {
	return uniqueDigits ? 10 : 10
}
export function pinCalculateSecurityScore(validation: PinValidationResult): number {
	let score = 0
	score += Math.min(40, (validation.entropyBits / 26) * 40)
	if (!validation.isCommonPin) {
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
function pinGenerateSingleItem(
	validated: Required<
		Omit<PinGenerateOptions, 'includeTimestamp' | 'includeEntropy' | 'securityLevel'>
	> & {
		includeTimestamp: boolean
		includeEntropy: boolean
		securityLevel: PinSecurityLevel
	},
): PinItem {
	let attempts = 0
	let pin = ''
	while (attempts < PIN_MAX_GENERATION_ATTEMPTS) {
		attempts++
		pin = ''
		const availableDigits = validated.excludeZero
			? ['1', '2', '3', '4', '5', '6', '7', '8', '9']
			: ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
		if (validated.uniqueDigits) {
			const shuffled = [...availableDigits].sort(() => Math.random() - 0.5)
			pin = shuffled.slice(0, validated.length).join('')
		} else {
			for (let i = 0; i < validated.length; i++) {
				const digitIndex = validated.excludeZero ? randomInt(1, 10) : randomInt(0, 10)
				pin += digitIndex.toString()
			}
		}
		if (validated.uniqueDigits && !pinHasAllUniqueDigits(pin)) continue
		if (validated.excludeRepeating && pinHasConsecutiveRepeatingDigits(pin)) continue
		if (validated.excludeSequential && pinHasSequentialDigits(pin)) continue
		if (validated.excludeZero && pinContainsZero(pin)) continue
		if (validated.excludeCommonPins && pinIsCommonPin(pin)) continue
		break
	}
	if (attempts >= PIN_MAX_GENERATION_ATTEMPTS) {
		throw new PinValidationError(
			`PIN generation failed after ${PIN_MAX_GENERATION_ATTEMPTS} attempts. Constraints may be too strict.`,
			{
				length: validated.length,
				uniqueDigits: validated.uniqueDigits,
				excludeRepeating: validated.excludeRepeating,
				excludeSequential: validated.excludeSequential,
				excludeZero: validated.excludeZero,
				excludeCommonPins: validated.excludeCommonPins,
			},
		)
	}
	const item: {
		pin: string
		timestamp?: number
		entropyBits?: number
		strength?: PinStrength
	} = { pin }
	if (validated.includeTimestamp) {
		item.timestamp = Math.floor(Date.now() / 1000)
	}
	if (validated.includeEntropy) {
		item.entropyBits = pinCalculateEntropyBits(validated.length, validated.uniqueDigits)
		item.strength = pinGetStrength(item.entropyBits)
	}
	return item as PinItem
}
function pinBuildMetadata(
	validated: Required<
		Omit<PinGenerateOptions, 'includeTimestamp' | 'includeEntropy' | 'securityLevel'>
	> & {
		includeTimestamp: boolean
		includeEntropy: boolean
		securityLevel: PinSecurityLevel
	},
	avgEntropyBits: number,
): PinGenerateMetadata {
	const poolSize = pinGetPoolSize(validated.uniqueDigits)
	const strength = pinGetStrength(avgEntropyBits)
	const securityLevel = pinGetSecurityLevel(avgEntropyBits)
	return {
		count: validated.count,
		length: validated.length,
		uniqueDigits: validated.uniqueDigits,
		excludeRepeating: validated.excludeRepeating,
		excludeSequential: validated.excludeSequential,
		excludeZero: validated.excludeZero,
		excludeCommonPins: validated.excludeCommonPins,
		includeTimestamp: validated.includeTimestamp,
		includeEntropy: validated.includeEntropy,
		poolSize,
		avgEntropyBits,
		strength,
		generatedAt: Math.floor(Date.now() / 1000),
		securityLevel,
	}
}
export function pinGenerateTokens(options: PinGenerateOptions = {}): PinGenerateResult {
	const validated = pinValidateOptions(options)
	const pins: PinItem[] = []
	let totalEntropy = 0
	for (let i = 0; i < validated.count; i++) {
		const pin = pinGenerateSingleItem(validated)
		pins.push(pin)
		if (validated.includeEntropy && pin.entropyBits !== undefined) {
			totalEntropy += pin.entropyBits
		}
	}
	const avgEntropyBits = validated.includeEntropy
		? Math.round((totalEntropy / validated.count) * 10) / 10
		: pinCalculateEntropyBits(validated.length, validated.uniqueDigits)
	const metadata = pinBuildMetadata(validated, avgEntropyBits)
	return {
		pins: Object.freeze(pins) as readonly PinItem[],
		meta: Object.freeze(metadata),
	}
}
export function pinGenerateToken(options: PinGenerateOptions = {}): PinItem {
	const result = pinGenerateTokens({ ...options, count: 1 })
	const pin = result.pins[0]
	if (!pin) {
		throw new PinSecurityError('Failed to generate PIN - pins array is empty')
	}
	return pin
}
export function pinGenerateTokenString(options: PinGenerateOptions = {}): string {
	const pin = pinGenerateToken({ ...options, count: 1 })
	return pin.pin
}
export function pinGenerateSample(): PinItem {
	return pinGenerateTokens({ count: 1, length: 4 }).pins[0]!
}
export function pinGenerateAtmPin(count: number = 1): PinGenerateResult {
	return pinGenerateTokens({
		count,
		length: 4,
		excludeZero: false,
		excludeCommonPins: true,
		securityLevel: 'low',
	})
}
export function pinGenerateAuthPin(count: number = 1): PinGenerateResult {
	return pinGenerateTokens({
		count,
		length: 6,
		excludeZero: false,
		excludeCommonPins: true,
		securityLevel: 'medium',
	})
}
export function pinGenerateSecurePin(count: number = 1): PinGenerateResult {
	return pinGenerateTokens({
		count,
		length: 8,
		excludeZero: false,
		excludeRepeating: true,
		excludeCommonPins: true,
		securityLevel: 'high',
	})
}
export function pinGenerateMaximumPin(count: number = 1): PinGenerateResult {
	return pinGenerateTokens({
		count,
		length: 8,
		excludeZero: false,
		excludeRepeating: true,
		excludeSequential: true,
		uniqueDigits: true,
		excludeCommonPins: true,
		securityLevel: 'critical',
	})
}
export function pinValidate(
	pin: string,
	validationOptions?: PinValidationOptions,
): PinValidationResult {
	const errors: string[] = []
	const warnings: string[] = []
	if (!pin || typeof pin !== 'string') {
		return {
			isValid: false,
			strength: 'weak',
			entropyBits: 0,
			length: 0,
			hasRepeatingDigits: false,
			hasSequentialDigits: false,
			hasZero: false,
			hasAllUniqueDigits: false,
			isCommonPin: false,
			errors: Object.freeze(['PIN is empty or invalid']) as readonly string[],
			warnings: Object.freeze([]) as readonly string[],
			securityScore: 0,
			isProductionReady: false,
		}
	}
	if (!pinHasOnlyDigits(pin)) {
		return {
			isValid: false,
			strength: 'weak',
			entropyBits: 0,
			length: pin.length,
			hasRepeatingDigits: false,
			hasSequentialDigits: false,
			hasZero: false,
			hasAllUniqueDigits: false,
			isCommonPin: false,
			errors: Object.freeze(['PIN must contain only digits']) as readonly string[],
			warnings: Object.freeze([]) as readonly string[],
			securityScore: 0,
			isProductionReady: false,
		}
	}
	const length = pin.length
	if (
		validationOptions?.allowedLengths &&
		!validationOptions.allowedLengths.includes(length as PinLength)
	) {
		errors.push(`PIN length must be one of: ${validationOptions.allowedLengths.join(', ')}`)
	} else if (!PIN_VALID_LENGTHS.includes(length as PinLength)) {
		errors.push(`PIN length must be one of: ${PIN_VALID_LENGTHS.join(', ')}`)
	}
	const hasRepeatingDigits = pinHasConsecutiveRepeatingDigits(pin)
	const hasSequentialDigits = pinHasSequentialDigits(pin)
	const hasZero = pinContainsZero(pin)
	const hasAllUniqueDigits = pinHasAllUniqueDigits(pin)
	const isCommonPin = pinIsCommonPin(pin)
	if (isCommonPin) {
		errors.push('PIN is a commonly used PIN (security risk)')
	}
	if (validationOptions?.requireUniqueDigits && !hasAllUniqueDigits) {
		errors.push('PIN must have all unique digits')
	}
	if (validationOptions?.excludeSequential && hasSequentialDigits) {
		errors.push('PIN contains sequential digits')
	}
	if (validationOptions?.excludeCommonPins && isCommonPin) {
		errors.push('PIN is a commonly used PIN')
	}
	if (hasRepeatingDigits) {
		warnings.push('PIN contains consecutive repeating digits')
	}
	if (hasSequentialDigits) {
		warnings.push('PIN contains sequential digits')
	}
	if (length === 4) {
		warnings.push('4-digit PIN is less secure than 6 or 8-digit PIN')
	}
	const entropyBits = pinCalculateEntropyBits(length, hasAllUniqueDigits)
	const strength = pinGetStrength(entropyBits)
	if (validationOptions?.minEntropy && entropyBits < validationOptions.minEntropy) {
		errors.push(
			`PIN entropy (${entropyBits}) is below minimum required (${validationOptions.minEntropy})`,
		)
	}
	if (strength === 'weak') {
		errors.push('PIN strength is too weak')
	} else if (strength === 'medium') {
		warnings.push('PIN strength could be improved')
	}
	const isProductionReady =
		errors.length === 0 && entropyBits >= PIN_MIN_ENTROPY_FOR_PRODUCTION && !isCommonPin
	if (validationOptions?.checkProductionReady && !isProductionReady) {
		errors.push('PIN is not production-ready')
	}
	const baseResult = {
		isValid: errors.length === 0,
		strength,
		entropyBits,
		length,
		hasRepeatingDigits,
		hasSequentialDigits,
		hasZero,
		hasAllUniqueDigits,
		isCommonPin,
		errors: Object.freeze(errors) as readonly string[],
		warnings: Object.freeze(warnings) as readonly string[],
	}
	const securityScore = pinCalculateSecurityScore(baseResult as PinValidationResult)
	return {
		...baseResult,
		securityScore,
		isProductionReady,
	}
}
export function pinIsStrong(
	pin: string,
	minEntropy: number = PIN_MIN_ENTROPY_FOR_PRODUCTION,
): boolean {
	const validation = pinValidate(pin)
	return validation.isValid && validation.entropyBits >= minEntropy
}
export function pinIsProductionReady(pin: string): boolean {
	const validation = pinValidate(pin, { checkProductionReady: true })
	return validation.isProductionReady
}
export function pinCalculateEntropy(pin: string): number {
	if (!pin || typeof pin !== 'string') return 0
	const length = pin.length
	const hasAllUnique = pinHasAllUniqueDigits(pin)
	return pinCalculateEntropyBits(length, hasAllUnique)
}
export function pinExportTokens(
	result: PinGenerateResult,
	format: PinExportFormat = 'json',
): string {
	const { pins, meta } = result
	if (!pins || pins.length === 0) {
		throw new PinValidationError('No PINs to export', { pinCount: 0 })
	}
	switch (format) {
		case 'json':
			return JSON.stringify({ meta, pins }, null, 2)
		case 'txt':
			return pins.map((p) => p.pin).join('\n')
		case 'csv': {
			const escapeCsv = (str: string | number): string => {
				const string = String(str)
				if (string.includes('"') || string.includes(',') || string.includes('\n')) {
					return `"${string.replace(/"/g, '""')}"`
				}
				return string
			}
			const headers = ['pin']
			if (meta.includeTimestamp) headers.push('timestamp')
			if (meta.includeEntropy) headers.push('entropyBits')
			if (meta.includeEntropy) headers.push('strength')
			const rows = pins.map((p) => {
				const cols = [escapeCsv(p.pin)]
				if (meta.includeTimestamp && p.timestamp !== undefined) {
					cols.push(p.timestamp.toString())
				}
				if (meta.includeEntropy && p.entropyBits !== undefined) {
					cols.push(p.entropyBits.toString())
				}
				if (meta.includeEntropy && p.strength !== undefined) {
					cols.push(p.strength)
				}
				return cols.join(',')
			})
			return [headers.join(','), ...rows].join('\n')
		}
		default:
			throw new PinValidationError(`Unsupported export format: ${format}`, { format })
	}
}
export function pinExportToEnv(result: PinGenerateResult, prefix: string = 'PIN'): string {
	if (!prefix || prefix.trim().length === 0) {
		throw new PinValidationError('Environment variable prefix cannot be empty')
	}
	if (!/^[A-Z][A-Z0-9_]*$/.test(prefix)) {
		throw new PinValidationError(
			'Environment variable prefix must be uppercase alphanumeric with underscores',
		)
	}
	const { pins } = result
	return pins.map((p, i) => `${prefix}_${i + 1}="${p.pin}"`).join('\n')
}
export const pinPresets = Object.freeze({
	atm: {
		length: 4 as PinLength,
		uniqueDigits: false,
		excludeRepeating: false,
		excludeSequential: false,
		excludeZero: false,
		excludeCommonPins: true,
		includeTimestamp: false,
		includeEntropy: false,
		securityLevel: 'low' as PinSecurityLevel,
	},
	auth: {
		length: 6 as PinLength,
		uniqueDigits: false,
		excludeRepeating: false,
		excludeSequential: false,
		excludeZero: false,
		excludeCommonPins: true,
		includeTimestamp: true,
		includeEntropy: true,
		securityLevel: 'medium' as PinSecurityLevel,
	},
	secure: {
		length: 8 as PinLength,
		uniqueDigits: false,
		excludeRepeating: true,
		excludeSequential: false,
		excludeZero: false,
		excludeCommonPins: true,
		includeTimestamp: true,
		includeEntropy: true,
		securityLevel: 'high' as PinSecurityLevel,
	},
	maximum: {
		length: 8 as PinLength,
		uniqueDigits: true,
		excludeRepeating: true,
		excludeSequential: true,
		excludeZero: false,
		excludeCommonPins: true,
		includeTimestamp: true,
		includeEntropy: true,
		securityLevel: 'critical' as PinSecurityLevel,
	},
} as const satisfies Record<PinPreset, PinPresetConfig>)
export function pinGenerateWithPreset(
	preset: PinPreset,
	overrides: Partial<PinGenerateOptions> = {},
): PinGenerateResult {
	const baseOptions = pinPresets[preset]
	if (!baseOptions) {
		throw new PinValidationError(`Unknown preset: ${preset}`, {
			preset,
			availablePresets: Object.keys(pinPresets),
		})
	}
	return pinGenerateTokens({ ...baseOptions, ...overrides })
}
export function pinGetLengthStrength(length: PinLength): PinStrength {
	const entropyBits = pinCalculateEntropyBits(length, false)
	return pinGetStrength(entropyBits)
}
export function pinCompareLengths(len1: PinLength, len2: PinLength): number {
	const strength1 = pinGetLengthStrength(len1)
	const strength2 = pinGetLengthStrength(len2)
	const strengthOrder: Record<PinStrength, number> = {
		weak: 0,
		medium: 1,
		strong: 2,
		very_strong: 3,
	}
	return strengthOrder[strength2] - strengthOrder[strength1]
}
export function pinIsLengthSecure(length: PinLength, minStrength: PinStrength = 'medium'): boolean {
	const strength = pinGetLengthStrength(length)
	const strengthOrder: Record<PinStrength, number> = {
		weak: 0,
		medium: 1,
		strong: 2,
		very_strong: 3,
	}
	return strengthOrder[strength] >= strengthOrder[minStrength]
}
export function pinGetRecommendedLength(securityLevel: PinSecurityLevel): PinLength {
	switch (securityLevel) {
		case 'critical':
			return 8
		case 'high':
			return 8
		case 'medium':
			return 6
		case 'low':
			return 4
		default:
			return 6
	}
}
export function pinGetSecurityReport(pin: string): {
	readonly score: number
	readonly strength: PinStrength
	readonly isProductionReady: boolean
	readonly recommendations: readonly string[]
} {
	const validation = pinValidate(pin)
	const recommendations: string[] = []
	if (validation.entropyBits < PIN_MIN_ENTROPY_FOR_PRODUCTION) {
		recommendations.push('Increase PIN length to at least 6 digits for production use')
	}
	if (validation.length < 6) {
		recommendations.push('Use minimum 6 digits for better security')
	}
	if (validation.isCommonPin) {
		recommendations.push('Avoid commonly used PINs (1234, 0000, etc.)')
	}
	if (validation.hasSequentialDigits) {
		recommendations.push('Avoid sequential digits (123, 456, etc.)')
	}
	if (validation.hasRepeatingDigits) {
		recommendations.push('Avoid consecutive repeating digits (11, 22, etc.)')
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
export class PinGenerator {
	private readonly options: Required<
		Omit<PinGenerateOptions, 'includeTimestamp' | 'includeEntropy' | 'securityLevel'>
	> & {
		includeTimestamp: boolean
		includeEntropy: boolean
		securityLevel: PinSecurityLevel
	}
	private readonly entropyBits: number
	private readonly strength: PinStrength
	private readonly securityLevel: PinSecurityLevel
	private static requestCount = 0
	private static lastRequestTime = 0
	constructor(options: PinGenerateOptions = {}) {
		this.options = pinValidateOptions(options)
		this.entropyBits = pinCalculateEntropyBits(this.options.length, this.options.uniqueDigits)
		this.strength = pinGetStrength(this.entropyBits)
		this.securityLevel = this.options.securityLevel
	}
	private static checkRateLimit(): void {
		const now = Date.now()
		if (now - PinGenerator.lastRequestTime > PIN_RATE_LIMIT_WINDOW_MS) {
			PinGenerator.requestCount = 0
			PinGenerator.lastRequestTime = now
		}
		if (PinGenerator.requestCount >= PIN_RATE_LIMIT_MAX_REQUESTS) {
			throw new PinRateLimitError(
				`Rate limit exceeded: ${PIN_RATE_LIMIT_MAX_REQUESTS} requests per minute`,
			)
		}
		PinGenerator.requestCount++
	}
	public generate(): PinGenerateResult {
		PinGenerator.checkRateLimit()
		const pins: PinItem[] = []
		let totalEntropy = 0
		for (let i = 0; i < this.options.count; i++) {
			const pin = pinGenerateSingleItem(this.options)
			pins.push(pin)
			if (this.options.includeEntropy && pin.entropyBits !== undefined) {
				totalEntropy += pin.entropyBits
			}
		}
		const avgEntropyBits = this.options.includeEntropy
			? Math.round((totalEntropy / this.options.count) * 10) / 10
			: this.entropyBits
		const metadata = pinBuildMetadata(this.options, avgEntropyBits)
		return {
			pins: Object.freeze(pins) as readonly PinItem[],
			meta: Object.freeze(metadata),
		}
	}
	public generateOne(): string {
		const result = this.generate()
		return result.pins[0]?.pin ?? ''
	}
	public generateAtm(count: number = 1): PinGenerateResult {
		return pinGenerateAtmPin(count)
	}
	public generateAuth(count: number = 1): PinGenerateResult {
		return pinGenerateAuthPin(count)
	}
	public generateSecure(count: number = 1): PinGenerateResult {
		return pinGenerateSecurePin(count)
	}
	public generateMaximum(count: number = 1): PinGenerateResult {
		return pinGenerateMaximumPin(count)
	}
	public export(result: PinGenerateResult, format: PinExportFormat = 'json'): string {
		return pinExportTokens(result, format)
	}
	public exportToEnv(result: PinGenerateResult, prefix: string = 'PIN'): string {
		return pinExportToEnv(result, prefix)
	}
	public validate(pin: string, options?: PinValidationOptions): PinValidationResult {
		return pinValidate(pin, options)
	}
	public isStrong(pin: string, minEntropy?: number): boolean {
		return pinIsStrong(pin, minEntropy)
	}
	public isProductionReady(pin: string): boolean {
		return pinIsProductionReady(pin)
	}
	public getEntropyBits(): number {
		return this.entropyBits
	}
	public getStrength(): PinStrength {
		return this.strength
	}
	public getSecurityLevel(): PinSecurityLevel {
		return this.securityLevel
	}
	public getOptions(): Readonly<
		Required<
			Omit<PinGenerateOptions, 'includeTimestamp' | 'includeEntropy' | 'securityLevel'>
		> & {
			includeTimestamp: boolean
			includeEntropy: boolean
			securityLevel: PinSecurityLevel
		}
	> {
		return Object.freeze({ ...this.options })
	}
	public static resetRateLimit(): void {
		PinGenerator.requestCount = 0
		PinGenerator.lastRequestTime = 0
	}
}
export default {
	generate: pinGenerateTokens,
	generateOne: pinGenerateToken,
	generateString: pinGenerateTokenString,
	generateAtm: pinGenerateAtmPin,
	generateAuth: pinGenerateAuthPin,
	generateSecure: pinGenerateSecurePin,
	generateMaximum: pinGenerateMaximumPin,
	generateWithPreset: pinGenerateWithPreset,
	validate: pinValidate,
	isStrong: pinIsStrong,
	isProductionReady: pinIsProductionReady,
	export: pinExportTokens,
	exportToEnv: pinExportToEnv,
	getSecurityReport: pinGetSecurityReport,
	Generator: PinGenerator,
	presets: pinPresets,
	helpers: {
		hasSequentialDigits: pinHasSequentialDigits,
		hasConsecutiveRepeatingDigits: pinHasConsecutiveRepeatingDigits,
		hasAllUniqueDigits: pinHasAllUniqueDigits,
		containsZero: pinContainsZero,
		isCommonPin: pinIsCommonPin,
		hasOnlyDigits: pinHasOnlyDigits,
		calculateEntropy: pinCalculateEntropy,
		calculateEntropyBits: pinCalculateEntropyBits,
		getStrength: pinGetStrength,
		getLengthStrength: pinGetLengthStrength,
		compareLengths: pinCompareLengths,
		isLengthSecure: pinIsLengthSecure,
		getRecommendedLength: pinGetRecommendedLength,
	},
	constants: {
		VALID_LENGTHS: PIN_VALID_LENGTHS,
		MIN_COUNT: PIN_MIN_COUNT,
		MAX_COUNT: PIN_MAX_COUNT,
		MAX_GENERATION_ATTEMPTS: PIN_MAX_GENERATION_ATTEMPTS,
		MIN_ENTROPY_PRODUCTION: PIN_MIN_ENTROPY_FOR_PRODUCTION,
		MIN_ENTROPY_SENSITIVE: PIN_MIN_ENTROPY_FOR_SENSITIVE,
		COMMON_PINS: PIN_COMMON_PINS,
		SEQUENTIAL_PATTERNS: PIN_SEQUENTIAL_PATTERNS,
	},
}
