import jwtGenerator, { SignOptions, VerifyOptions, Algorithm } from 'jsonwebtoken'
import { randomInt, randomUUID } from 'crypto'
import { ValidationError, CryptoError } from './../../../error.js'
import type { StringValue } from 'ms'
export const JWT_GENERATOR_SUPPORTED_ALGORITHMS = Object.freeze([
	'HS256',
	'HS384',
	'HS512',
	'RS256',
	'RS384',
	'RS512',
] as const)
export const JWT_GENERATOR_SUPPORTED_EXPORT_FORMATS = Object.freeze(['json', 'txt', 'csv'] as const)
export const JWT_GENERATOR_DEFAULT_CLOCK_TOLERANCE = 5
export const JWT_GENERATOR_GENERATION_MIN_COUNT = 1
export const JWT_GENERATOR_GENERATION_MAX_COUNT = 100
export const JWT_GENERATOR_DEFAULT_COUNT = 1
export const JWT_GENERATOR_DEFAULT_EXPIRES_IN = 3600
export const JWT_GENERATOR_MIN_EXPIRES_IN = 60
export const JWT_GENERATOR_MAX_EXPIRES_IN = 31536000
export const JWT_GENERATOR_DEFAULT_ISSUER = 'librgrn-jwtGenerator'
export const JWT_GENERATOR_MAX_ISSUER_LENGTH = 100
export const JWT_GENERATOR_MAX_AUDIENCE_LENGTH = 200
export const JWT_GENERATOR_ENTROPY_THRESHOLDS = Object.freeze([
	{ min: 0, max: 63, label: 'weak' as const },
	{ min: 64, max: 127, label: 'medium' as const },
	{ min: 128, max: 255, label: 'strong' as const },
	{ min: 256, max: Infinity, label: 'very_strong' as const },
] as const)
export const JWT_GENERATOR_ROLE_POOL = Object.freeze([
	'admin',
	'user',
	'editor',
	'viewer',
	'moderator',
] as const)
export const JWT_GENERATOR_SCOPE_POOL = Object.freeze([
	'read',
	'write',
	'delete',
	'update',
	'create',
] as const)
export type JwtGeneratorHmacAlgorithm = 'HS256' | 'HS384' | 'HS512'
export type JwtGeneratorRsaAlgorithm = 'RS256' | 'RS384' | 'RS512'
export type JwtGeneratorAlgorithm = (typeof JWT_GENERATOR_SUPPORTED_ALGORITHMS)[number]
export type JwtGeneratorExportFormat = (typeof JWT_GENERATOR_SUPPORTED_EXPORT_FORMATS)[number]
export type JwtGeneratorStrength = 'weak' | 'medium' | 'strong' | 'very_strong'
export type JwtGeneratorRole = (typeof JWT_GENERATOR_ROLE_POOL)[number]
export type JwtGeneratorScope = (typeof JWT_GENERATOR_SCOPE_POOL)[number]
export interface JwtGeneratorSignConfig {
	algorithm: JwtGeneratorAlgorithm
	key: string | Buffer
	keyid?: string
	issuer?: string
	audience?: string | string[]
	expiresIn?: number | StringValue
	notBefore?: number | StringValue
}
export interface JwtGeneratorVerifyConfig {
	algorithm: JwtGeneratorAlgorithm
	key: string | Buffer
	issuer?: string
	audience?: string
	clockTolerance?: number
	maxAge?: string | number
	requireIssuer?: boolean
	requireAudience?: boolean
	requireExpiration?: boolean
}
export interface JwtGeneratorPayloadOptions {
	includeRoles?: boolean
	includeScope?: boolean
	includeJti?: boolean
	includeSub?: boolean
	includeIat?: boolean
	includeExp?: boolean
	customClaims?: Record<string, unknown>
}
export interface JwtGeneratorGenerateOptions {
	count?: number
	algorithm?: JwtGeneratorAlgorithm
	expiresIn?: number
	includeRoles?: boolean
	includeScope?: boolean
	issuer?: string
	audience?: string
	key: string | Buffer
	includeTimestamp?: boolean
	includeEntropy?: boolean
	customClaims?: Record<string, unknown>
}
export interface JwtGeneratorPayloadBase {
	jti?: string
	sub?: string
	roles?: JwtGeneratorRole[]
	scope?: string
	iat?: number
	exp?: number
	iss?: string
	aud?: string | string[]
	[key: string]: unknown
}
export interface JwtGeneratorGeneratedToken {
	readonly token: string
	readonly payload: JwtGeneratorPayloadBase & Record<string, unknown>
	readonly header?: Record<string, unknown>
	readonly expiresAt?: number
	readonly entropyBits?: number
}
export interface JwtGeneratorGenerateMetadata {
	readonly count: number
	readonly algorithm: JwtGeneratorAlgorithm
	readonly expiresIn: number
	readonly issuer?: string
	readonly audience?: string
	readonly includeRoles: boolean
	readonly includeScope: boolean
	readonly includeTimestamp: boolean
	readonly includeEntropy: boolean
	readonly avgEntropyBits: number
	readonly strength: JwtGeneratorStrength
}
export interface JwtGeneratorGenerateResult {
	readonly tokens: readonly JwtGeneratorGeneratedToken[]
	readonly metadata: JwtGeneratorGenerateMetadata
}
export interface JwtGeneratorValidationResult {
	readonly isValid: boolean
	readonly isExpired: boolean
	readonly strength: JwtGeneratorStrength
	readonly entropyBits: number
	readonly algorithm: JwtGeneratorAlgorithm | 'unknown'
	readonly issuer?: string
	readonly audience?: string | string[]
	readonly expiresAt?: number
	readonly issuedAt?: number
	readonly errors: readonly string[]
	readonly warnings: readonly string[]
}
export interface JwtGeneratorDecodedToken {
	readonly header?: Record<string, unknown>
	readonly payload: JwtGeneratorPayloadBase & Record<string, unknown>
	readonly signature: string
}
function cleanUndefined<T extends Record<string, unknown>>(
	obj: T,
): {
	[K in keyof T]: T[K] extends undefined ? never : T[K]
} {
	return Object.fromEntries(Object.entries(obj).filter(([_, value]) => value !== undefined)) as {
		[K in keyof T]: T[K] extends undefined ? never : T[K]
	}
}
function jwtGeneratorAssertAlgorithm(alg: string): asserts alg is JwtGeneratorAlgorithm {
	if (!JWT_GENERATOR_SUPPORTED_ALGORITHMS.includes(alg as JwtGeneratorAlgorithm)) {
		throw new ValidationError(`Unsupported algorithm: ${alg}`, { alg })
	}
}
function jwtGeneratorValidateKeyForAlgorithm(
	algorithm: JwtGeneratorAlgorithm,
	key: unknown,
	operation: 'sign' | 'verify',
): asserts key is string | Buffer {
	if (!key) {
		throw new ValidationError('Key is required', { algorithm, operation })
	}
	if (algorithm.startsWith('RS')) {
		const keyStr = key.toString()
		if (operation === 'sign') {
			if (
				!keyStr.includes('BEGIN PRIVATE KEY') &&
				!keyStr.includes('BEGIN RSA PRIVATE KEY')
			) {
				throw new ValidationError('RSA signing requires a private key in PEM format', {
					algorithm,
				})
			}
		} else {
			if (!keyStr.includes('BEGIN PUBLIC KEY')) {
				throw new ValidationError('RSA verification requires a public key in PEM format', {
					algorithm,
				})
			}
		}
	}
}
function jwtGeneratorShuffle<T>(array: readonly T[]): T[] {
	const result = [...array]
	for (let i = result.length - 1; i > 0; i--) {
		const j = Math.floor(Math.random() * (i + 1))
		;[result[i]!, result[j]!] = [result[j]!, result[i]!]
	}
	return result
}
function jwtGeneratorGetUnixTimestamp(): number {
	return Math.floor(Date.now() / 1000)
}
function jwtGeneratorCalculateEntropy(algorithm: JwtGeneratorAlgorithm): number {
	const entropyMap: Record<JwtGeneratorAlgorithm, number> = {
		HS256: 256,
		HS384: 384,
		HS512: 512,
		RS256: 256,
		RS384: 384,
		RS512: 512,
	}
	return entropyMap[algorithm] ?? 256
}
function jwtGeneratorGetStrength(entropyBits: number): JwtGeneratorStrength {
	const threshold = JWT_GENERATOR_ENTROPY_THRESHOLDS.find(
		(t) => entropyBits >= t.min && entropyBits <= t.max,
	)
	return threshold?.label ?? 'weak'
}
type ValidatedGenerateOptions = Required<
	Omit<JwtGeneratorGenerateOptions, 'issuer' | 'audience' | 'customClaims'>
> & {
	issuer?: string
	audience?: string
	customClaims?: Record<string, unknown>
}
function jwtGeneratorValidateOptions(
	options: JwtGeneratorGenerateOptions,
): ValidatedGenerateOptions {
	if (!options?.key) {
		throw new ValidationError('Key is required for token generation')
	}
	const count = options.count ?? JWT_GENERATOR_DEFAULT_COUNT
	if (
		!Number.isInteger(count) ||
		count < JWT_GENERATOR_GENERATION_MIN_COUNT ||
		count > JWT_GENERATOR_GENERATION_MAX_COUNT
	) {
		throw new ValidationError(
			`count must be an integer between ${JWT_GENERATOR_GENERATION_MIN_COUNT} and ${JWT_GENERATOR_GENERATION_MAX_COUNT}`,
			{ count },
		)
	}
	const algorithm = options.algorithm ?? 'HS256'
	jwtGeneratorAssertAlgorithm(algorithm)
	const expiresIn = options.expiresIn ?? JWT_GENERATOR_DEFAULT_EXPIRES_IN
	if (
		!Number.isInteger(expiresIn) ||
		expiresIn < JWT_GENERATOR_MIN_EXPIRES_IN ||
		expiresIn > JWT_GENERATOR_MAX_EXPIRES_IN
	) {
		throw new ValidationError(
			`expiresIn must be an integer between ${JWT_GENERATOR_MIN_EXPIRES_IN} and ${JWT_GENERATOR_MAX_EXPIRES_IN}`,
			{ expiresIn },
		)
	}
	const includeRoles = options.includeRoles ?? false
	const includeScope = options.includeScope ?? false
	const includeTimestamp = options.includeTimestamp ?? false
	const includeEntropy = options.includeEntropy ?? false
	if (typeof includeRoles !== 'boolean')
		throw new ValidationError('includeRoles must be a boolean', { includeRoles })
	if (typeof includeScope !== 'boolean')
		throw new ValidationError('includeScope must be a boolean', { includeScope })
	if (typeof includeTimestamp !== 'boolean')
		throw new ValidationError('includeTimestamp must be a boolean', { includeTimestamp })
	if (typeof includeEntropy !== 'boolean')
		throw new ValidationError('includeEntropy must be a boolean', { includeEntropy })
	let issuer: string | undefined
	if (options.issuer !== undefined) {
		if (typeof options.issuer !== 'string') {
			throw new ValidationError('issuer must be a string', { issuer: options.issuer })
		}
		if (options.issuer.length > JWT_GENERATOR_MAX_ISSUER_LENGTH) {
			throw new ValidationError(
				`issuer length must not exceed ${JWT_GENERATOR_MAX_ISSUER_LENGTH} characters`,
				{
					issuerLength: options.issuer.length,
				},
			)
		}
		issuer = options.issuer
	}
	let audience: string | undefined
	if (options.audience !== undefined) {
		if (typeof options.audience !== 'string') {
			throw new ValidationError('audience must be a string', { audience: options.audience })
		}
		if (options.audience.length > JWT_GENERATOR_MAX_AUDIENCE_LENGTH) {
			throw new ValidationError(
				`audience length must not exceed ${JWT_GENERATOR_MAX_AUDIENCE_LENGTH} characters`,
				{
					audienceLength: options.audience.length,
				},
			)
		}
		audience = options.audience
	}
	let customClaims: Record<string, unknown> | undefined
	if (options.customClaims !== undefined) {
		if (typeof options.customClaims !== 'object' || options.customClaims === null) {
			throw new ValidationError('customClaims must be an object', {
				customClaims: options.customClaims,
			})
		}
		customClaims = options.customClaims
	}
	return {
		count,
		algorithm,
		expiresIn,
		includeRoles,
		includeScope,
		includeTimestamp,
		includeEntropy,
		key: options.key,
		...(issuer !== undefined && { issuer }),
		...(audience !== undefined && { audience }),
		...(customClaims !== undefined && { customClaims }),
	}
}
function jwtGeneratorBuildSignOptions(config: JwtGeneratorSignConfig): SignOptions {
	const options: SignOptions = { algorithm: config.algorithm as Algorithm }
	if (config.keyid !== undefined) options.keyid = config.keyid
	if (config.issuer !== undefined) options.issuer = config.issuer
	if (config.audience !== undefined) options.audience = config.audience
	if (config.expiresIn !== undefined) options.expiresIn = config.expiresIn
	if (config.notBefore !== undefined) options.notBefore = config.notBefore
	return options
}
function jwtGeneratorBuildVerifyOptions(config: JwtGeneratorVerifyConfig): VerifyOptions {
	const options: VerifyOptions = {
		algorithms: [config.algorithm as Algorithm],
		clockTolerance: config.clockTolerance ?? JWT_GENERATOR_DEFAULT_CLOCK_TOLERANCE,
	}
	if (config.issuer !== undefined) options.issuer = config.issuer
	if (config.audience !== undefined) options.audience = config.audience
	if (config.maxAge !== undefined) options.maxAge = config.maxAge
	return options
}
function jwtGeneratorEnforceStrictClaims(
	decoded: Record<string, unknown>,
	config: JwtGeneratorVerifyConfig,
): void {
	const requireIssuer = config.requireIssuer !== false
	const requireAudience = config.requireAudience !== false
	if (requireIssuer) {
		if (!decoded['iss'] || decoded['iss'] !== config.issuer) {
			throw new CryptoError('Missing or mismatched issuer', {
				expected: config.issuer,
				actual: decoded['iss'],
			})
		}
	}
	if (requireAudience) {
		const actualAud = decoded['aud']
		const expectedAud = config.audience
		if (
			!actualAud ||
			(Array.isArray(actualAud)
				? !actualAud.includes(expectedAud as string)
				: actualAud !== expectedAud)
		) {
			throw new CryptoError('Missing or mismatched audience', {
				expected: expectedAud,
				actual: actualAud,
			})
		}
	}
	if (config.requireExpiration && !decoded['exp']) {
		throw new CryptoError('Token expiration is required but missing', {
			algorithm: config.algorithm,
		})
	}
}
function jwtGeneratorGeneratePayload(
	options: JwtGeneratorPayloadOptions = {},
	issuer?: string,
	audience?: string,
	expiresIn?: number,
	now?: number,
): JwtGeneratorPayloadBase & Record<string, unknown> {
	const payload: JwtGeneratorPayloadBase & Record<string, unknown> = {}
	if (options.includeJti ?? true) payload.jti = randomUUID()
	if (options.includeSub ?? true) payload.sub = `user_${randomInt(1000, 9999)}`
	if (options.includeRoles ?? false) {
		const count = randomInt(1, 4)
		const shuffled = jwtGeneratorShuffle(JWT_GENERATOR_ROLE_POOL)
		payload.roles = shuffled.slice(0, count)
	}
	if (options.includeScope ?? false) {
		const count = randomInt(1, 4)
		const shuffled = jwtGeneratorShuffle(JWT_GENERATOR_SCOPE_POOL)
		payload.scope = shuffled.slice(0, count).join(' ')
	}
	if (options.includeIat ?? true) payload.iat = now ?? jwtGeneratorGetUnixTimestamp()
	if (expiresIn && (options.includeExp ?? true)) {
		payload.exp = (now ?? jwtGeneratorGetUnixTimestamp()) + expiresIn
	}
	if (issuer !== undefined) payload.iss = issuer
	if (audience !== undefined) payload.aud = audience
	if (options.customClaims !== undefined) Object.assign(payload, options.customClaims)
	return payload
}
function jwtGeneratorGenerateSingleToken(
	config: ValidatedGenerateOptions,
	now: number,
): JwtGeneratorGeneratedToken {
	const payload = jwtGeneratorGeneratePayload(
		{
			includeRoles: config.includeRoles,
			includeScope: config.includeScope,
			...(config.customClaims !== undefined && { customClaims: config.customClaims }),
		},
		config.issuer,
		config.audience,
		config.expiresIn,
		now,
	)
	const token = jwtGeneratorSign(payload, {
		algorithm: config.algorithm,
		key: config.key,
		...(config.issuer !== undefined && { issuer: config.issuer }),
		...(config.audience !== undefined && { audience: config.audience }),
		expiresIn: config.expiresIn,
	})
	const decoded = jwtGenerator.decode(token, { complete: true }) as {
		header?: Record<string, unknown>
		payload?: Record<string, unknown>
	} | null
	const expiresAt = config.includeTimestamp ? (payload.exp as number | undefined) : undefined
	const entropyBits = config.includeEntropy
		? jwtGeneratorCalculateEntropy(config.algorithm)
		: undefined
	return {
		token,
		payload: payload as JwtGeneratorPayloadBase & Record<string, unknown>,
		...(decoded?.header !== undefined && { header: decoded.header }),
		...(expiresAt !== undefined && { expiresAt }),
		...(entropyBits !== undefined && { entropyBits }),
	}
}
function jwtGeneratorBuildMetadata(
	validated: ValidatedGenerateOptions,
	avgEntropyBits: number,
): JwtGeneratorGenerateMetadata {
	const strength = jwtGeneratorGetStrength(avgEntropyBits)
	const base: Omit<JwtGeneratorGenerateMetadata, 'issuer' | 'audience'> = {
		count: validated.count,
		algorithm: validated.algorithm,
		expiresIn: validated.expiresIn,
		includeRoles: validated.includeRoles,
		includeScope: validated.includeScope,
		includeTimestamp: validated.includeTimestamp,
		includeEntropy: validated.includeEntropy,
		avgEntropyBits,
		strength,
	}
	const metadata = { ...base } as JwtGeneratorGenerateMetadata
	if (validated.issuer !== undefined)
		Object.defineProperty(metadata, 'issuer', { value: validated.issuer, enumerable: true })
	if (validated.audience !== undefined)
		Object.defineProperty(metadata, 'audience', { value: validated.audience, enumerable: true })
	return Object.freeze(metadata)
}
export function jwtGeneratorGenerateTokens(
	options: JwtGeneratorGenerateOptions,
): JwtGeneratorGenerateResult {
	const validated = jwtGeneratorValidateOptions(options)
	const now = jwtGeneratorGetUnixTimestamp()
	const tokens: JwtGeneratorGeneratedToken[] = []
	let totalEntropy = 0
	for (let i = 0; i < validated.count; i++) {
		const token = jwtGeneratorGenerateSingleToken(validated, now)
		tokens.push(token)
		if (validated.includeEntropy && token.entropyBits !== undefined) {
			totalEntropy += token.entropyBits
		}
	}
	const avgEntropyBits = validated.includeEntropy
		? Math.round((totalEntropy / validated.count) * 10) / 10
		: jwtGeneratorCalculateEntropy(validated.algorithm)
	const metadata = jwtGeneratorBuildMetadata(validated, avgEntropyBits)
	return {
		tokens: Object.freeze(tokens),
		metadata,
	}
}
export function jwtGeneratorGenerateToken(
	options: JwtGeneratorGenerateOptions,
): JwtGeneratorGeneratedToken {
	const result = jwtGeneratorGenerateTokens({ ...options, count: 1 })
	return result.tokens[0]!
}
export function jwtGeneratorGenerateTokenString(options: JwtGeneratorGenerateOptions): string {
	const result = jwtGeneratorGenerateTokens({ ...options, count: 1 })
	return result.tokens[0]?.token ?? ''
}
export function jwtGeneratorGenerateSample(): JwtGeneratorGeneratedToken {
	return jwtGeneratorGenerateTokens({
		count: 1,
		algorithm: 'HS256',
		expiresIn: JWT_GENERATOR_DEFAULT_EXPIRES_IN,
		key: 'sample-secret-key-for-development-only',
	}).tokens[0]!
}
export function jwtGeneratorGenerateStrong(
	options: Partial<JwtGeneratorGenerateOptions> = {},
): JwtGeneratorGeneratedToken {
	return jwtGeneratorGenerateTokens({
		count: 1,
		algorithm: options.algorithm ?? 'HS512',
		expiresIn: options.expiresIn ?? 7200,
		key: options.key ?? 'strong-secret-key-for-production',
		includeRoles: true,
		includeScope: true,
		includeTimestamp: true,
		includeEntropy: true,
		...cleanUndefined(options),
	}).tokens[0]!
}
export function jwtGeneratorSign<T extends object = any>(
	payload: T,
	config: JwtGeneratorSignConfig,
): string {
	jwtGeneratorAssertAlgorithm(config.algorithm)
	jwtGeneratorValidateKeyForAlgorithm(config.algorithm, config.key, 'sign')
	const options = jwtGeneratorBuildSignOptions(config)
	try {
		return jwtGenerator.sign(payload, config.key, options)
	} catch (err: any) {
		throw new CryptoError('JWT_GENERATOR signing failed', { algorithm: config.algorithm }, err)
	}
}
export function jwtGeneratorVerify<T extends object = any>(
	token: string,
	config: JwtGeneratorVerifyConfig,
	validate?: (payload: unknown) => T,
): T {
	jwtGeneratorAssertAlgorithm(config.algorithm)
	jwtGeneratorValidateKeyForAlgorithm(config.algorithm, config.key, 'verify')
	const options = jwtGeneratorBuildVerifyOptions(config)
	let decoded: unknown
	try {
		decoded = jwtGenerator.verify(token, config.key, options)
	} catch (err: any) {
		throw new CryptoError(
			'JWT_GENERATOR verification failed',
			{ algorithm: config.algorithm },
			err,
		)
	}
	if (typeof decoded !== 'object' || decoded === null) {
		throw new CryptoError('Invalid JWT_GENERATOR payload: not an object')
	}
	jwtGeneratorEnforceStrictClaims(decoded as Record<string, unknown>, config)
	return validate ? validate(decoded) : (decoded as T)
}
export function jwtGeneratorDecode<T = any>(token: string): T | null {
	return jwtGenerator.decode(token) as T | null
}
export function jwtGeneratorDecodeComplete(token: string): JwtGeneratorDecodedToken | null {
	const decoded = jwtGenerator.decode(token, { complete: true })
	if (!decoded || typeof decoded !== 'object') return null
	return {
		...(decoded.header !== undefined && {
			header: decoded.header as unknown as Record<string, unknown>,
		}),
		payload: (decoded as any).payload ?? {},
		signature: (decoded as any).signature ?? '',
	}
}
export function jwtGeneratorValidate(
	token: string,
	_config?: Partial<JwtGeneratorVerifyConfig>,
): JwtGeneratorValidationResult {
	const errors: string[] = []
	const warnings: string[] = []
	if (!token || typeof token !== 'string') {
		return {
			isValid: false,
			isExpired: false,
			strength: 'weak',
			entropyBits: 0,
			algorithm: 'unknown',
			errors: ['Token is empty or invalid'],
			warnings: [],
		}
	}
	const parts = token.split('.')
	if (parts.length !== 3) {
		return {
			isValid: false,
			isExpired: false,
			strength: 'weak',
			entropyBits: 0,
			algorithm: 'unknown',
			errors: ['Invalid JWT_GENERATOR format: must have 3 parts'],
			warnings: [],
		}
	}
	try {
		const decoded = jwtGeneratorDecodeComplete(token)
		if (!decoded) {
			errors.push('Failed to decode token')
		} else {
			const header = decoded.header as { alg?: string }
			const payload = decoded.payload as JwtGeneratorPayloadBase
			const algorithm = (header.alg as JwtGeneratorAlgorithm) ?? 'unknown'
			const entropyBits = jwtGeneratorCalculateEntropy(algorithm as JwtGeneratorAlgorithm)
			const strength = jwtGeneratorGetStrength(entropyBits)
			const now = jwtGeneratorGetUnixTimestamp()
			const isExpired = payload.exp !== undefined && payload.exp < now
			if (isExpired) errors.push('Token has expired')
			if (payload.exp === undefined) warnings.push('Token has no expiration time')
			if (payload.iat === undefined) warnings.push('Token has no issued-at time')
			if (strength === 'weak') warnings.push('Token algorithm strength is weak')
			return {
				isValid: errors.length === 0,
				isExpired,
				strength,
				entropyBits,
				algorithm: algorithm as JwtGeneratorAlgorithm | 'unknown',
				...(payload.iss !== undefined && { issuer: payload.iss }),
				...(payload.aud !== undefined && { audience: payload.aud }),
				...(payload.exp !== undefined && { expiresAt: payload.exp }),
				...(payload.iat !== undefined && { issuedAt: payload.iat }),
				errors: Object.freeze(errors),
				warnings: Object.freeze(warnings),
			}
		}
	} catch {
		errors.push('Token decoding failed')
	}
	return {
		isValid: false,
		isExpired: false,
		strength: 'weak',
		entropyBits: 0,
		algorithm: 'unknown',
		errors: Object.freeze(errors),
		warnings: Object.freeze(warnings),
	}
}
export function jwtGeneratorIsExpired(token: string): boolean {
	return jwtGeneratorValidate(token).isExpired
}
export function jwtGeneratorIsValid(token: string): boolean {
	return jwtGeneratorValidate(token).isValid
}
export function jwtGeneratorGetRemainingTime(token: string): number {
	const decoded = jwtGeneratorDecodeComplete(token)
	if (!decoded || decoded.payload?.exp === undefined) return 0
	const now = jwtGeneratorGetUnixTimestamp()
	return Math.max(0, decoded.payload.exp - now)
}
export function jwtGeneratorExportTokens(
	result: JwtGeneratorGenerateResult,
	format: JwtGeneratorExportFormat = 'json',
): string {
	const { tokens, metadata } = result
	switch (format) {
		case 'json':
			return JSON.stringify({ metadata, tokens }, null, 2)
		case 'txt':
			return tokens.map((t) => t.token).join('\n')
		case 'csv': {
			const escapeCsv = (str: string): string => {
				if (str.includes('"') || str.includes(',') || str.includes('\n')) {
					return `"${str.replace(/"/g, '""')}"`
				}
				return str
			}
			const header = 'token,payload,expiresAt'
			const rows = tokens.map((t) => {
				const payloadStr = escapeCsv(JSON.stringify(t.payload))
				const expiresAt = t.expiresAt?.toString() ?? ''
				return `"${escapeCsv(t.token)}","${payloadStr}","${expiresAt}"`
			})
			return header + '\n' + rows.join('\n')
		}
		default:
			throw new ValidationError(`Unsupported export format: ${format}`, { format })
	}
}
export function jwtGeneratorExportToEnv(
	result: JwtGeneratorGenerateResult,
	prefix: string = 'JWT_GENERATOR_TOKEN',
): string {
	const { tokens } = result
	return tokens.map((t, i) => `${prefix}_${i + 1}="${t.token}"`).join('\n')
}
export class JwtGeneratorGenerator {
	private readonly options: ValidatedGenerateOptions
	private readonly entropyBits: number
	private readonly strength: JwtGeneratorStrength
	constructor(options: JwtGeneratorGenerateOptions) {
		this.options = jwtGeneratorValidateOptions(options)
		this.entropyBits = jwtGeneratorCalculateEntropy(this.options.algorithm)
		this.strength = jwtGeneratorGetStrength(this.entropyBits)
	}
	public generate(): JwtGeneratorGenerateResult {
		const now = jwtGeneratorGetUnixTimestamp()
		const tokens: JwtGeneratorGeneratedToken[] = []
		let totalEntropy = 0
		for (let i = 0; i < this.options.count; i++) {
			const token = jwtGeneratorGenerateSingleToken(this.options, now)
			tokens.push(token)
			if (this.options.includeEntropy && token.entropyBits !== undefined) {
				totalEntropy += token.entropyBits
			}
		}
		const avgEntropyBits = this.options.includeEntropy
			? Math.round((totalEntropy / this.options.count) * 10) / 10
			: this.entropyBits
		const metadata = jwtGeneratorBuildMetadata(this.options, avgEntropyBits)
		return {
			tokens: Object.freeze(tokens),
			metadata,
		}
	}
	public generateOne(): string {
		return this.generate().tokens[0]?.token ?? ''
	}
	public generateStrong(): JwtGeneratorGeneratedToken {
		return jwtGeneratorGenerateStrong({
			algorithm: this.options.algorithm,
			key: this.options.key,
			expiresIn: Math.max(this.options.expiresIn, 7200),
		})
	}
	public sign<T extends object = any>(
		payload: T,
		config?: Partial<JwtGeneratorSignConfig>,
	): string {
		return jwtGeneratorSign(payload, {
			algorithm: this.options.algorithm,
			key: this.options.key,
			...(this.options.issuer !== undefined && { issuer: this.options.issuer }),
			...(this.options.audience !== undefined && { audience: this.options.audience }),
			...(this.options.expiresIn !== undefined && { expiresIn: this.options.expiresIn }),
			...cleanUndefined(config ?? {}),
		})
	}
	public verify<T extends object = any>(
		token: string,
		config?: Partial<JwtGeneratorVerifyConfig>,
		validate?: (payload: unknown) => T,
	): T {
		return jwtGeneratorVerify(
			token,
			{
				algorithm: this.options.algorithm,
				key: this.options.key,
				...(this.options.issuer !== undefined && { issuer: this.options.issuer }),
				...(this.options.audience !== undefined && { audience: this.options.audience }),
				...cleanUndefined(config ?? {}),
			},
			validate,
		)
	}
	public decode<T = any>(token: string): T | null {
		return jwtGeneratorDecode<T>(token)
	}
	public validate(token: string): JwtGeneratorValidationResult {
		return jwtGeneratorValidate(
			token,
			cleanUndefined({
				algorithm: this.options.algorithm,
				key: this.options.key,
				...(this.options.issuer !== undefined && { issuer: this.options.issuer }),
				...(this.options.audience !== undefined && { audience: this.options.audience }),
			}),
		)
	}
	public isExpired(token: string): boolean {
		return jwtGeneratorIsExpired(token)
	}
	public isValid(token: string): boolean {
		return jwtGeneratorIsValid(token)
	}
	public getRemainingTime(token: string): number {
		return jwtGeneratorGetRemainingTime(token)
	}
	public export(
		result: JwtGeneratorGenerateResult,
		format: JwtGeneratorExportFormat = 'json',
	): string {
		return jwtGeneratorExportTokens(result, format)
	}
	public exportToEnv(
		result: JwtGeneratorGenerateResult,
		prefix: string = 'JWT_GENERATOR_TOKEN',
	): string {
		return jwtGeneratorExportToEnv(result, prefix)
	}
	public getEntropyBits(): number {
		return this.entropyBits
	}
	public getStrength(): JwtGeneratorStrength {
		return this.strength
	}
	public getOptions(): Readonly<ValidatedGenerateOptions> {
		return Object.freeze({ ...this.options })
	}
}
export const jwtGeneratorPresets = Object.freeze({
	basic: {
		algorithm: 'HS256' as const,
		expiresIn: 3600,
		includeRoles: false,
		includeScope: false,
		includeTimestamp: true,
		includeEntropy: false,
	} as Partial<JwtGeneratorGenerateOptions>,
	standard: {
		algorithm: 'HS384' as const,
		expiresIn: 7200,
		includeRoles: true,
		includeScope: true,
		includeTimestamp: true,
		includeEntropy: true,
	} as Partial<JwtGeneratorGenerateOptions>,
	strong: {
		algorithm: 'HS512' as const,
		expiresIn: 14400,
		includeRoles: true,
		includeScope: true,
		includeTimestamp: true,
		includeEntropy: true,
	} as Partial<JwtGeneratorGenerateOptions>,
	maximum: {
		algorithm: 'RS512' as const,
		expiresIn: 3600,
		includeRoles: true,
		includeScope: true,
		includeTimestamp: true,
		includeEntropy: true,
	} as Partial<JwtGeneratorGenerateOptions>,
	shortLived: {
		algorithm: 'HS256' as const,
		expiresIn: 900,
		includeRoles: false,
		includeScope: true,
		includeTimestamp: true,
		includeEntropy: false,
	} as Partial<JwtGeneratorGenerateOptions>,
	refresh: {
		algorithm: 'HS384' as const,
		expiresIn: 604800,
		includeRoles: false,
		includeScope: false,
		includeTimestamp: true,
		includeEntropy: true,
	} as Partial<JwtGeneratorGenerateOptions>,
	service: {
		algorithm: 'RS256' as const,
		expiresIn: 86400,
		includeRoles: true,
		includeScope: true,
		includeTimestamp: true,
		includeEntropy: true,
	} as Partial<JwtGeneratorGenerateOptions>,
} as const)
export type JwtGeneratorPreset = keyof typeof jwtGeneratorPresets
export function jwtGeneratorGenerateWithPreset(
	preset: JwtGeneratorPreset,
	options: Omit<
		JwtGeneratorGenerateOptions,
		| 'algorithm'
		| 'expiresIn'
		| 'includeRoles'
		| 'includeScope'
		| 'includeTimestamp'
		| 'includeEntropy'
	>,
): JwtGeneratorGenerateResult {
	const baseOptions = jwtGeneratorPresets[preset]
	const merged = { ...baseOptions, ...cleanUndefined(options) }
	if (!merged.key) {
		throw new ValidationError('Key is required', { preset })
	}
	return jwtGeneratorGenerateTokens(merged as JwtGeneratorGenerateOptions)
}
export function jwtGeneratorGetAlgorithmStrength(
	algorithm: JwtGeneratorAlgorithm,
): JwtGeneratorStrength {
	const entropyBits = jwtGeneratorCalculateEntropy(algorithm)
	return jwtGeneratorGetStrength(entropyBits)
}
export function jwtGeneratorCompareAlgorithms(
	alg1: JwtGeneratorAlgorithm,
	alg2: JwtGeneratorAlgorithm,
): number {
	const strengthOrder: Record<JwtGeneratorStrength, number> = {
		weak: 0,
		medium: 1,
		strong: 2,
		very_strong: 3,
	}
	return (
		strengthOrder[jwtGeneratorGetAlgorithmStrength(alg2)] -
		strengthOrder[jwtGeneratorGetAlgorithmStrength(alg1)]
	)
}
export function jwtGeneratorIsAlgorithmSecure(
	algorithm: JwtGeneratorAlgorithm,
	minStrength: JwtGeneratorStrength = 'strong',
): boolean {
	const strengthOrder: Record<JwtGeneratorStrength, number> = {
		weak: 0,
		medium: 1,
		strong: 2,
		very_strong: 3,
	}
	return strengthOrder[jwtGeneratorGetAlgorithmStrength(algorithm)] >= strengthOrder[minStrength]
}
