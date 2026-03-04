import { randomBytes, createHmac } from 'crypto'
import { ValidationError } from '../../../error.js'
export const WEBHOOK_GENERATOR_SUPPORTED_HMAC_ALGORITHM_TYPES = Object.freeze([
	'sha256',
	'sha384',
	'sha512',
	'sha1',
] as const)
export const WEBHOOK_GENERATOR_AVAILABLE_SECRET_ENCODING_FORMATS = Object.freeze([
	'hex',
	'base64',
	'alphanumeric',
] as const)
export const WEBHOOK_GENERATOR_VALID_SECRET_BYTE_LENGTHS = Object.freeze([16, 32, 64] as const)
export const WEBHOOK_GENERATOR_SUPPORTED_EXPORT_FORMATS = Object.freeze([
	'json',
	'txt',
	'csv',
] as const)
export const WEBHOOK_GENERATOR_GENERATION_MINIMUM_COUNT = 1
export const WEBHOOK_GENERATOR_GENERATION_MAXIMUM_COUNT = 10
export const WEBHOOK_GENERATOR_GENERATION_DEFAULT_COUNT = 1
export const WEBHOOK_GENERATOR_GENERATION_DEFAULT_LENGTH = 32
export const WEBHOOK_GENERATOR_GENERATION_DEFAULT_ALGORITHM = 'sha256' as const
export const WEBHOOK_GENERATOR_GENERATION_DEFAULT_FORMAT = 'hex' as const
export const WEBHOOK_GENERATOR_SIGNATURE_DEFAULT_PAYLOAD_STRING = 'webhookGenerator-payload'
export const WEBHOOK_GENERATOR_BASE32_ENCODING_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
export const WEBHOOK_GENERATOR_ENTROPY_THRESHOLDS = Object.freeze([
	{ min: 0, max: 63, label: 'weak' as const },
	{ min: 64, max: 127, label: 'medium' as const },
	{ min: 128, max: 255, label: 'strong' as const },
	{ min: 256, max: Infinity, label: 'very_strong' as const },
] as const)
export const WEBHOOK_GENERATOR_MAX_CUSTOM_PAYLOAD_LENGTH = 1000
export type WebhookGeneratorHmacAlgorithm =
	(typeof WEBHOOK_GENERATOR_SUPPORTED_HMAC_ALGORITHM_TYPES)[number]
export type WebhookGeneratorSecretFormat =
	(typeof WEBHOOK_GENERATOR_AVAILABLE_SECRET_ENCODING_FORMATS)[number]
export type WebhookGeneratorSecretLength =
	(typeof WEBHOOK_GENERATOR_VALID_SECRET_BYTE_LENGTHS)[number]
export type WebhookGeneratorExportFormat =
	(typeof WEBHOOK_GENERATOR_SUPPORTED_EXPORT_FORMATS)[number]
export type WebhookGeneratorStrength = 'weak' | 'medium' | 'strong' | 'very_strong'
export interface WebhookGeneratorSecretsGenerationOptions {
	count?: number
	length?: WebhookGeneratorSecretLength
	algorithm?: WebhookGeneratorHmacAlgorithm
	format?: WebhookGeneratorSecretFormat
	includeSignature?: boolean
	includeTimestamp?: boolean
	signaturePayload?: string
	includeEntropy?: boolean
	customPayload?: string
}
export interface WebhookGeneratorGeneratedSecret {
	readonly secret: string
	readonly signature?: string
	readonly timestamp?: number
	readonly entropyBits?: number
	readonly payload?: string
}
export interface WebhookGeneratorGenerateMetadata {
	readonly count: number
	readonly length: WebhookGeneratorSecretLength
	readonly algorithm: WebhookGeneratorHmacAlgorithm
	readonly format: WebhookGeneratorSecretFormat
	readonly includeSignature: boolean
	readonly includeTimestamp: boolean
	readonly includeEntropy: boolean
	readonly signaturePayload?: string
	readonly poolSize: number
	readonly avgEntropyBits: number
	readonly strength: WebhookGeneratorStrength
}
export interface WebhookGeneratorSecretsGenerationResult {
	readonly secrets: readonly WebhookGeneratorGeneratedSecret[]
	readonly meta: WebhookGeneratorGenerateMetadata
}
export interface WebhookGeneratorValidationResult {
	readonly isValid: boolean
	readonly strength: WebhookGeneratorStrength
	readonly entropyBits: number
	readonly algorithm: WebhookGeneratorHmacAlgorithm | 'unknown'
	readonly format: WebhookGeneratorSecretFormat | 'unknown'
	readonly length: number
	readonly errors: readonly string[]
	readonly warnings: readonly string[]
}
export interface WebhookGeneratorSignatureVerificationResult {
	readonly isValid: boolean
	readonly algorithm: WebhookGeneratorHmacAlgorithm
	readonly expectedSignature: string
	readonly actualSignature: string
	readonly timestamp?: number
	readonly errors: readonly string[]
}
function webhookGeneratorEncodeBufferToBase32Alphabet(webhookGeneratorBuffer: Buffer): string {
	let bits = 0
	let value = 0
	let output = ''
	for (let i = 0; i < webhookGeneratorBuffer.length; i++) {
		const byte = webhookGeneratorBuffer[i]!
		value = (value << 8) | byte
		bits += 8
		while (bits >= 5) {
			const index = (value >>> (bits - 5)) & 31
			output += WEBHOOK_GENERATOR_BASE32_ENCODING_ALPHABET[index]!
			bits -= 5
		}
	}
	if (bits > 0) {
		const index = (value << (5 - bits)) & 31
		output += WEBHOOK_GENERATOR_BASE32_ENCODING_ALPHABET[index]!
	}
	return output
}
const webhookGeneratorFormatToEncoderFunctionMap: Record<
	WebhookGeneratorSecretFormat,
	(buf: Buffer) => string
> = {
	hex: (webhookGeneratorBuffer) => webhookGeneratorBuffer.toString('hex'),
	base64: (webhookGeneratorBuffer) =>
		webhookGeneratorBuffer.toString('base64').replace(/=+$/, ''),
	alphanumeric: webhookGeneratorEncodeBufferToBase32Alphabet,
}
function webhookGeneratorValidateOptions(
	webhookGeneratorOptions: WebhookGeneratorSecretsGenerationOptions,
): Required<
	Omit<WebhookGeneratorSecretsGenerationOptions, 'signaturePayload' | 'customPayload'>
> & {
	signaturePayload?: string
	customPayload?: string
} {
	const webhookGeneratorCount =
		webhookGeneratorOptions.count ?? WEBHOOK_GENERATOR_GENERATION_DEFAULT_COUNT
	if (
		!Number.isInteger(webhookGeneratorCount) ||
		webhookGeneratorCount < WEBHOOK_GENERATOR_GENERATION_MINIMUM_COUNT ||
		webhookGeneratorCount > WEBHOOK_GENERATOR_GENERATION_MAXIMUM_COUNT
	) {
		throw new ValidationError(
			`count must be an integer between ${WEBHOOK_GENERATOR_GENERATION_MINIMUM_COUNT} and ${WEBHOOK_GENERATOR_GENERATION_MAXIMUM_COUNT}`,
			{ count: webhookGeneratorCount },
		)
	}
	const webhookGeneratorLength =
		webhookGeneratorOptions.length ?? WEBHOOK_GENERATOR_GENERATION_DEFAULT_LENGTH
	if (
		!WEBHOOK_GENERATOR_VALID_SECRET_BYTE_LENGTHS.includes(
			webhookGeneratorLength as WebhookGeneratorSecretLength,
		)
	) {
		throw new ValidationError(
			`length must be one of: ${WEBHOOK_GENERATOR_VALID_SECRET_BYTE_LENGTHS.join(', ')}`,
			{ length: webhookGeneratorLength },
		)
	}
	const webhookGeneratorAlgorithm =
		webhookGeneratorOptions.algorithm ?? WEBHOOK_GENERATOR_GENERATION_DEFAULT_ALGORITHM
	if (
		!WEBHOOK_GENERATOR_SUPPORTED_HMAC_ALGORITHM_TYPES.includes(
			webhookGeneratorAlgorithm as WebhookGeneratorHmacAlgorithm,
		)
	) {
		throw new ValidationError(
			`algorithm must be one of: ${WEBHOOK_GENERATOR_SUPPORTED_HMAC_ALGORITHM_TYPES.join(', ')}`,
			{ algorithm: webhookGeneratorAlgorithm },
		)
	}
	const webhookGeneratorFormat =
		webhookGeneratorOptions.format ?? WEBHOOK_GENERATOR_GENERATION_DEFAULT_FORMAT
	if (
		!WEBHOOK_GENERATOR_AVAILABLE_SECRET_ENCODING_FORMATS.includes(
			webhookGeneratorFormat as WebhookGeneratorSecretFormat,
		)
	) {
		throw new ValidationError(
			`format must be one of: ${WEBHOOK_GENERATOR_AVAILABLE_SECRET_ENCODING_FORMATS.join(', ')}`,
			{ format: webhookGeneratorFormat },
		)
	}
	const includeSignature = webhookGeneratorOptions.includeSignature ?? false
	const includeTimestamp = webhookGeneratorOptions.includeTimestamp ?? false
	const includeEntropy = webhookGeneratorOptions.includeEntropy ?? false
	if (typeof includeSignature !== 'boolean') {
		throw new ValidationError('includeSignature must be a boolean', { includeSignature })
	}
	if (typeof includeTimestamp !== 'boolean') {
		throw new ValidationError('includeTimestamp must be a boolean', { includeTimestamp })
	}
	if (typeof includeEntropy !== 'boolean') {
		throw new ValidationError('includeEntropy must be a boolean', { includeEntropy })
	}
	let signaturePayload: string | undefined
	if (webhookGeneratorOptions.signaturePayload !== undefined) {
		if (typeof webhookGeneratorOptions.signaturePayload !== 'string') {
			throw new ValidationError('signaturePayload must be a string', {
				signaturePayload: webhookGeneratorOptions.signaturePayload,
			})
		}
		if (
			webhookGeneratorOptions.signaturePayload.length >
			WEBHOOK_GENERATOR_MAX_CUSTOM_PAYLOAD_LENGTH
		) {
			throw new ValidationError(
				`signaturePayload length must not exceed ${WEBHOOK_GENERATOR_MAX_CUSTOM_PAYLOAD_LENGTH} characters`,
				{ payloadLength: webhookGeneratorOptions.signaturePayload.length },
			)
		}
		signaturePayload = webhookGeneratorOptions.signaturePayload
	}
	let customPayload: string | undefined
	if (webhookGeneratorOptions.customPayload !== undefined) {
		if (typeof webhookGeneratorOptions.customPayload !== 'string') {
			throw new ValidationError('customPayload must be a string', {
				customPayload: webhookGeneratorOptions.customPayload,
			})
		}
		if (
			webhookGeneratorOptions.customPayload.length >
			WEBHOOK_GENERATOR_MAX_CUSTOM_PAYLOAD_LENGTH
		) {
			throw new ValidationError(
				`customPayload length must not exceed ${WEBHOOK_GENERATOR_MAX_CUSTOM_PAYLOAD_LENGTH} characters`,
				{ payloadLength: webhookGeneratorOptions.customPayload.length },
			)
		}
		customPayload = webhookGeneratorOptions.customPayload
	}
	return {
		count: webhookGeneratorCount,
		length: webhookGeneratorLength as WebhookGeneratorSecretLength,
		algorithm: webhookGeneratorAlgorithm as WebhookGeneratorHmacAlgorithm,
		format: webhookGeneratorFormat as WebhookGeneratorSecretFormat,
		includeSignature,
		includeTimestamp,
		includeEntropy,
		...(signaturePayload !== undefined && { signaturePayload }),
		...(customPayload !== undefined && { customPayload }),
	}
}
function webhookGeneratorComputeHmacSignature(
	payload: string,
	secretBuffer: Buffer,
	algorithm: WebhookGeneratorHmacAlgorithm,
	format: WebhookGeneratorSecretFormat,
): string {
	const hmac = createHmac(algorithm, secretBuffer)
	hmac.update(payload)
	const signatureBytes = hmac.digest()
	return webhookGeneratorFormatToEncoderFunctionMap[format](signatureBytes)
}
function webhookGeneratorCalculateEntropy(byteLength: number): number {
	if (byteLength <= 0) return 0
	const entropy = byteLength * 8
	return Math.round(entropy * 10) / 10
}
function webhookGeneratorGetStrength(entropyBits: number): WebhookGeneratorStrength {
	const threshold = WEBHOOK_GENERATOR_ENTROPY_THRESHOLDS.find(
		(t) => entropyBits >= t.min && entropyBits <= t.max,
	)
	return threshold?.label ?? 'weak'
}
function webhookGeneratorGetPoolSize(format: WebhookGeneratorSecretFormat): number {
	switch (format) {
		case 'hex':
			return 16
		case 'base64':
			return 64
		case 'alphanumeric':
			return 32
		default:
			return 16
	}
}
function webhookGeneratorGenerateSingleSecret(
	validated: Required<
		Omit<WebhookGeneratorSecretsGenerationOptions, 'signaturePayload' | 'customPayload'>
	> & {
		signaturePayload?: string
		customPayload?: string
	},
): WebhookGeneratorGeneratedSecret {
	const secretBytes = randomBytes(validated.length)
	const secret = webhookGeneratorFormatToEncoderFunctionMap[validated.format](secretBytes)
	const timestamp = Math.floor(Date.now() / 1000)
	const entropyBits = webhookGeneratorCalculateEntropy(validated.length)
	const signatureData = validated.includeSignature
		? {
				signature: webhookGeneratorComputeHmacSignature(
					validated.signaturePayload ??
						validated.customPayload ??
						WEBHOOK_GENERATOR_SIGNATURE_DEFAULT_PAYLOAD_STRING,
					secretBytes,
					validated.algorithm,
					validated.format,
				),
				payload:
					validated.signaturePayload ??
					validated.customPayload ??
					WEBHOOK_GENERATOR_SIGNATURE_DEFAULT_PAYLOAD_STRING,
			}
		: {}
	return {
		secret,
		...signatureData,
		...(validated.includeTimestamp && { timestamp }),
		...(validated.includeEntropy && { entropyBits }),
	}
}
function webhookGeneratorBuildMetadata(
	validated: Required<
		Omit<WebhookGeneratorSecretsGenerationOptions, 'signaturePayload' | 'customPayload'>
	> & {
		signaturePayload?: string
	},
	avgEntropyBits: number,
): WebhookGeneratorGenerateMetadata {
	const poolSize = webhookGeneratorGetPoolSize(validated.format)
	const strength = webhookGeneratorGetStrength(avgEntropyBits)
	const base: WebhookGeneratorGenerateMetadata = {
		count: validated.count,
		length: validated.length,
		algorithm: validated.algorithm,
		format: validated.format,
		includeSignature: validated.includeSignature,
		includeTimestamp: validated.includeTimestamp,
		includeEntropy: validated.includeEntropy,
		poolSize,
		avgEntropyBits,
		strength,
	}
	if (validated.signaturePayload) {
		return { ...base, signaturePayload: validated.signaturePayload }
	}
	return base
}
export function webhookGeneratorGenerateSecrets(
	webhookGeneratorOptions: WebhookGeneratorSecretsGenerationOptions = {},
): WebhookGeneratorSecretsGenerationResult {
	const validated = webhookGeneratorValidateOptions(webhookGeneratorOptions)
	const secrets: WebhookGeneratorGeneratedSecret[] = []
	let totalEntropy = 0
	for (let i = 0; i < validated.count; i++) {
		const secret = webhookGeneratorGenerateSingleSecret(validated)
		secrets.push(secret)
		if (validated.includeEntropy && secret.entropyBits !== undefined) {
			totalEntropy += secret.entropyBits
		}
	}
	const avgEntropyBits = validated.includeEntropy
		? Math.round((totalEntropy / validated.count) * 10) / 10
		: webhookGeneratorCalculateEntropy(validated.length)
	const metadata = webhookGeneratorBuildMetadata(validated, avgEntropyBits)
	return {
		secrets: Object.freeze(secrets) as readonly WebhookGeneratorGeneratedSecret[],
		meta: Object.freeze(metadata),
	}
}
export function webhookGeneratorGenerateSecret(
	webhookGeneratorOptions: WebhookGeneratorSecretsGenerationOptions = {},
): WebhookGeneratorGeneratedSecret {
	const result = webhookGeneratorGenerateSecrets({ ...webhookGeneratorOptions, count: 1 })
	return result.secrets[0]!
}
export function webhookGeneratorGenerateSecretString(
	webhookGeneratorOptions: WebhookGeneratorSecretsGenerationOptions = {},
): string {
	const result = webhookGeneratorGenerateSecrets({ ...webhookGeneratorOptions, count: 1 })
	return result.secrets[0]?.secret ?? ''
}
export function webhookGeneratorGenerateSample(): WebhookGeneratorGeneratedSecret {
	return webhookGeneratorGenerateSecrets({
		count: 1,
		length: 32,
		algorithm: 'sha256',
		format: 'hex',
		includeSignature: false,
		includeTimestamp: false,
	}).secrets[0]!
}
export function webhookGeneratorGenerateStrong(
	webhookGeneratorOptions: Partial<WebhookGeneratorSecretsGenerationOptions> = {},
): WebhookGeneratorGeneratedSecret {
	return webhookGeneratorGenerateSecrets({
		count: 1,
		length: webhookGeneratorOptions.length ?? 64,
		algorithm: webhookGeneratorOptions.algorithm ?? 'sha512',
		format: webhookGeneratorOptions.format ?? 'hex',
		includeSignature: true,
		includeTimestamp: true,
		includeEntropy: true,
		...webhookGeneratorOptions,
	}).secrets[0]!
}
export function webhookGeneratorValidateSecret(secret: string): WebhookGeneratorValidationResult {
	const errors: string[] = []
	const warnings: string[] = []
	if (!secret || typeof secret !== 'string') {
		return {
			isValid: false,
			strength: 'weak' as const,
			entropyBits: 0,
			algorithm: 'unknown' as const,
			format: 'unknown' as const,
			length: 0,
			errors: ['Secret is empty or invalid'],
			warnings: [],
		}
	}
	const length = secret.length
	if (length < 32) {
		errors.push('Secret is too short (minimum 32 characters for hex format)')
	}
	if (length < 64) {
		warnings.push('Secret length is below recommended (64 characters)')
	}
	let format: WebhookGeneratorSecretFormat | 'unknown' = 'unknown'
	if (/^[0-9a-fA-F]+$/.test(secret)) {
		format = 'hex'
	} else if (/^[A-Za-z0-9+/]+$/.test(secret)) {
		format = 'base64'
	} else if (/^[A-Z2-7]+$/.test(secret)) {
		format = 'alphanumeric'
	}
	let algorithm: WebhookGeneratorHmacAlgorithm | 'unknown' = 'unknown'
	const estimatedEntropy = length * (format === 'hex' ? 4 : format === 'base64' ? 6 : 5)
	const strength = webhookGeneratorGetStrength(estimatedEntropy)
	if (strength === 'weak') {
		errors.push('Secret strength is too weak')
	} else if (strength === 'medium') {
		warnings.push('Secret strength could be improved')
	}
	return {
		isValid: errors.length === 0,
		strength,
		entropyBits: estimatedEntropy,
		algorithm,
		format,
		length,
		errors: Object.freeze(errors),
		warnings: Object.freeze(warnings),
	}
}
export function webhookGeneratorIsStrong(secret: string, minEntropy: number = 128): boolean {
	const validation = webhookGeneratorValidateSecret(secret)
	return validation.isValid && validation.entropyBits >= minEntropy
}
export function webhookGeneratorVerifySignature(
	payload: string,
	secret: string,
	signature: string,
	algorithm: WebhookGeneratorHmacAlgorithm = 'sha256',
	format: WebhookGeneratorSecretFormat = 'hex',
): WebhookGeneratorSignatureVerificationResult {
	const errors: string[] = []
	if (!payload || typeof payload !== 'string') {
		return {
			isValid: false,
			algorithm,
			expectedSignature: '',
			actualSignature: signature,
			errors: ['Payload is empty or invalid'],
		}
	}
	if (!secret || typeof secret !== 'string') {
		return {
			isValid: false,
			algorithm,
			expectedSignature: '',
			actualSignature: signature,
			errors: ['Secret is empty or invalid'],
		}
	}
	if (!signature || typeof signature !== 'string') {
		return {
			isValid: false,
			algorithm,
			expectedSignature: '',
			actualSignature: signature,
			errors: ['Signature is empty or invalid'],
		}
	}
	try {
		const secretBuffer = Buffer.from(
			secret,
			format === 'hex' ? 'hex' : format === 'base64' ? 'base64' : undefined,
		)
		const expectedSignature = webhookGeneratorComputeHmacSignature(
			payload,
			secretBuffer,
			algorithm,
			format,
		)
		const isValid = expectedSignature === signature
		if (!isValid) {
			errors.push('Signature mismatch')
		}
		return {
			isValid,
			algorithm,
			expectedSignature,
			actualSignature: signature,
			timestamp: Math.floor(Date.now() / 1000),
			errors: Object.freeze(errors),
		}
	} catch (err) {
		return {
			isValid: false,
			algorithm,
			expectedSignature: '',
			actualSignature: signature,
			errors: ['Signature verification failed'],
		}
	}
}
export function webhookGeneratorCalculateSecretEntropy(secret: string): number {
	const length = secret.length
	let poolSize = 16
	if (/^[0-9a-fA-F]+$/.test(secret)) {
		poolSize = 16
	} else if (/^[A-Z2-7]+$/.test(secret)) {
		poolSize = 32
	} else if (/^[A-Za-z0-9+/_-]+$/.test(secret)) {
		poolSize = 64
	}
	return Math.round(length * Math.log2(poolSize) * 10) / 10
}
export function webhookGeneratorExportSecrets(
	webhookGeneratorResult: WebhookGeneratorSecretsGenerationResult,
	webhookGeneratorExportFormat: WebhookGeneratorExportFormat = 'json',
): string {
	const { secrets: webhookGeneratorSecrets, meta: webhookGeneratorMetadata } =
		webhookGeneratorResult
	switch (webhookGeneratorExportFormat) {
		case 'json':
			return JSON.stringify(
				{ metadata: webhookGeneratorMetadata, secrets: webhookGeneratorSecrets },
				null,
				2,
			)
		case 'txt':
			return webhookGeneratorSecrets
				.map((webhookGeneratorSingleSecret) => {
					const webhookGeneratorLines = [`secret: ${webhookGeneratorSingleSecret.secret}`]
					if (webhookGeneratorSingleSecret.signature)
						webhookGeneratorLines.push(
							`signature: ${webhookGeneratorSingleSecret.signature}`,
						)
					if (webhookGeneratorSingleSecret.payload)
						webhookGeneratorLines.push(
							`payload: ${webhookGeneratorSingleSecret.payload}`,
						)
					if (webhookGeneratorSingleSecret.timestamp)
						webhookGeneratorLines.push(
							`timestamp: ${webhookGeneratorSingleSecret.timestamp}`,
						)
					if (webhookGeneratorSingleSecret.entropyBits)
						webhookGeneratorLines.push(
							`entropyBits: ${webhookGeneratorSingleSecret.entropyBits}`,
						)
					return webhookGeneratorLines.join('\n')
				})
				.join('\n\n')
		case 'csv': {
			const webhookGeneratorHasSignature = webhookGeneratorSecrets.some(
				(webhookGeneratorSingleSecret) => webhookGeneratorSingleSecret.signature,
			)
			const webhookGeneratorHasTimestamp = webhookGeneratorSecrets.some(
				(webhookGeneratorSingleSecret) => webhookGeneratorSingleSecret.timestamp,
			)
			const webhookGeneratorHasPayload = webhookGeneratorSecrets.some(
				(webhookGeneratorSingleSecret) => webhookGeneratorSingleSecret.payload,
			)
			const webhookGeneratorHasEntropy = webhookGeneratorSecrets.some(
				(webhookGeneratorSingleSecret) => webhookGeneratorSingleSecret.entropyBits,
			)
			const webhookGeneratorHeaders = ['secret']
			if (webhookGeneratorHasSignature) webhookGeneratorHeaders.push('signature')
			if (webhookGeneratorHasPayload) webhookGeneratorHeaders.push('payload')
			if (webhookGeneratorHasTimestamp) webhookGeneratorHeaders.push('timestamp')
			if (webhookGeneratorHasEntropy) webhookGeneratorHeaders.push('entropyBits')
			const webhookGeneratorEscapeCsv = (webhookGeneratorValue: string | number): string => {
				const webhookGeneratorString = String(webhookGeneratorValue)
				if (
					webhookGeneratorString.includes('"') ||
					webhookGeneratorString.includes(',') ||
					webhookGeneratorString.includes('\n')
				) {
					return `"${webhookGeneratorString.replace(/"/g, '""')}"`
				}
				return webhookGeneratorString
			}
			const webhookGeneratorRows = webhookGeneratorSecrets.map(
				(webhookGeneratorSingleSecret) => {
					const webhookGeneratorCols = [
						webhookGeneratorEscapeCsv(webhookGeneratorSingleSecret.secret),
					]
					if (webhookGeneratorHasSignature && webhookGeneratorSingleSecret.signature)
						webhookGeneratorCols.push(
							webhookGeneratorEscapeCsv(webhookGeneratorSingleSecret.signature),
						)
					if (webhookGeneratorHasPayload && webhookGeneratorSingleSecret.payload)
						webhookGeneratorCols.push(
							webhookGeneratorEscapeCsv(webhookGeneratorSingleSecret.payload),
						)
					if (webhookGeneratorHasTimestamp && webhookGeneratorSingleSecret.timestamp)
						webhookGeneratorCols.push(webhookGeneratorSingleSecret.timestamp.toString())
					if (webhookGeneratorHasEntropy && webhookGeneratorSingleSecret.entropyBits)
						webhookGeneratorCols.push(
							webhookGeneratorSingleSecret.entropyBits.toString(),
						)
					return webhookGeneratorCols.join(',')
				},
			)
			return webhookGeneratorHeaders.join(',') + '\n' + webhookGeneratorRows.join('\n')
		}
		default:
			throw new ValidationError(
				`Unsupported export format: ${webhookGeneratorExportFormat}`,
				{
					format: webhookGeneratorExportFormat,
				},
			)
	}
}
export function webhookGeneratorExportToEnv(
	webhookGeneratorResult: WebhookGeneratorSecretsGenerationResult,
	prefix: string = 'WEBHOOK_GENERATOR',
): string {
	const { secrets, meta } = webhookGeneratorResult
	return secrets
		.map((s, i) => {
			const lines = [`${prefix}_${i + 1}_SECRET="${s.secret}"`]
			if (s.signature) lines.push(`${prefix}_${i + 1}_SIGNATURE="${s.signature}"`)
			if (s.payload) lines.push(`${prefix}_${i + 1}_PAYLOAD="${s.payload}"`)
			lines.push(`${prefix}_${i + 1}_ALGORITHM="${meta.algorithm}"`)
			return lines.join('\n')
		})
		.join('\n\n')
}
export class WebhookGeneratorGenerator {
	private readonly options: Required<
		Omit<WebhookGeneratorSecretsGenerationOptions, 'signaturePayload' | 'customPayload'>
	> & {
		signaturePayload?: string
		customPayload?: string
	}
	private readonly entropyBits: number
	private readonly strength: WebhookGeneratorStrength
	constructor(webhookGeneratorOptions: WebhookGeneratorSecretsGenerationOptions = {}) {
		this.options = webhookGeneratorValidateOptions(webhookGeneratorOptions)
		this.entropyBits = webhookGeneratorCalculateEntropy(this.options.length)
		this.strength = webhookGeneratorGetStrength(this.entropyBits)
	}
	public generate(): WebhookGeneratorSecretsGenerationResult {
		const secrets: WebhookGeneratorGeneratedSecret[] = []
		let totalEntropy = 0
		for (let i = 0; i < this.options.count; i++) {
			const secret = webhookGeneratorGenerateSingleSecret(this.options)
			secrets.push(secret)
			if (this.options.includeEntropy && secret.entropyBits !== undefined) {
				totalEntropy += secret.entropyBits
			}
		}
		const avgEntropyBits = this.options.includeEntropy
			? Math.round((totalEntropy / this.options.count) * 10) / 10
			: this.entropyBits
		const metadata = webhookGeneratorBuildMetadata(this.options, avgEntropyBits)
		return {
			secrets: Object.freeze(secrets) as readonly WebhookGeneratorGeneratedSecret[],
			meta: Object.freeze(metadata),
		}
	}
	public generateOne(): WebhookGeneratorGeneratedSecret {
		const result = this.generate()
		return result.secrets[0]!
	}
	public generateStrong(): WebhookGeneratorGeneratedSecret {
		return webhookGeneratorGenerateStrong({
			length: 64,
			algorithm: this.options.algorithm,
			format: this.options.format,
		})
	}
	public verify(
		payload: string,
		signature: string,
		secret?: string,
	): WebhookGeneratorSignatureVerificationResult {
		const secretToUse = secret || this.generateOne().secret
		return webhookGeneratorVerifySignature(
			payload,
			secretToUse,
			signature,
			this.options.algorithm,
			this.options.format,
		)
	}
	public export(
		result: WebhookGeneratorSecretsGenerationResult,
		format: WebhookGeneratorExportFormat = 'json',
	): string {
		return webhookGeneratorExportSecrets(result, format)
	}
	public exportToEnv(
		result: WebhookGeneratorSecretsGenerationResult,
		prefix: string = 'WEBHOOK_GENERATOR',
	): string {
		return webhookGeneratorExportToEnv(result, prefix)
	}
	public validate(secret: string): WebhookGeneratorValidationResult {
		return webhookGeneratorValidateSecret(secret)
	}
	public isStrong(secret: string, minEntropy: number = 128): boolean {
		return webhookGeneratorIsStrong(secret, minEntropy)
	}
	public getEntropyBits(): number {
		return this.entropyBits
	}
	public getStrength(): WebhookGeneratorStrength {
		return this.strength
	}
	public getOptions(): Readonly<
		Required<
			Omit<WebhookGeneratorSecretsGenerationOptions, 'signaturePayload' | 'customPayload'>
		> & {
			signaturePayload?: string
			customPayload?: string
		}
	> {
		return Object.freeze({ ...this.options })
	}
}
export const webhookGeneratorPresets = Object.freeze({
	basic: {
		length: 32 as WebhookGeneratorSecretLength,
		algorithm: 'sha256' as WebhookGeneratorHmacAlgorithm,
		format: 'hex' as WebhookGeneratorSecretFormat,
		includeSignature: false,
		includeTimestamp: false,
		includeEntropy: false,
	} as WebhookGeneratorSecretsGenerationOptions,
	standard: {
		length: 32 as WebhookGeneratorSecretLength,
		algorithm: 'sha256' as WebhookGeneratorHmacAlgorithm,
		format: 'hex' as WebhookGeneratorSecretFormat,
		includeSignature: true,
		includeTimestamp: true,
		includeEntropy: true,
	} as WebhookGeneratorSecretsGenerationOptions,
	strong: {
		length: 64 as WebhookGeneratorSecretLength,
		algorithm: 'sha512' as WebhookGeneratorHmacAlgorithm,
		format: 'hex' as WebhookGeneratorSecretFormat,
		includeSignature: true,
		includeTimestamp: true,
		includeEntropy: true,
	} as WebhookGeneratorSecretsGenerationOptions,
	maximum: {
		length: 64 as WebhookGeneratorSecretLength,
		algorithm: 'sha512' as WebhookGeneratorHmacAlgorithm,
		format: 'base64' as WebhookGeneratorSecretFormat,
		includeSignature: true,
		includeTimestamp: true,
		includeEntropy: true,
	} as WebhookGeneratorSecretsGenerationOptions,
	github: {
		length: 32 as WebhookGeneratorSecretLength,
		algorithm: 'sha256' as WebhookGeneratorHmacAlgorithm,
		format: 'hex' as WebhookGeneratorSecretFormat,
		includeSignature: true,
		includeTimestamp: false,
		includeEntropy: true,
		signaturePayload: 'github-webhookGenerator',
	} as WebhookGeneratorSecretsGenerationOptions,
	stripe: {
		length: 32 as WebhookGeneratorSecretLength,
		algorithm: 'sha256' as WebhookGeneratorHmacAlgorithm,
		format: 'hex' as WebhookGeneratorSecretFormat,
		includeSignature: true,
		includeTimestamp: true,
		includeEntropy: true,
		signaturePayload: 'stripe-webhookGenerator',
	} as WebhookGeneratorSecretsGenerationOptions,
} as const)
export type WebhookGeneratorPreset = keyof typeof webhookGeneratorPresets
export function webhookGeneratorGenerateWithPreset(
	preset: WebhookGeneratorPreset,
	overrides: Partial<WebhookGeneratorSecretsGenerationOptions> = {},
): WebhookGeneratorSecretsGenerationResult {
	const baseOptions = webhookGeneratorPresets[preset]
	return webhookGeneratorGenerateSecrets({ ...baseOptions, ...overrides })
}
export function webhookGeneratorGetAlgorithmStrength(
	algorithm: WebhookGeneratorHmacAlgorithm,
): WebhookGeneratorStrength {
	const entropyMap: Record<WebhookGeneratorHmacAlgorithm, number> = {
		sha1: 160,
		sha256: 256,
		sha384: 384,
		sha512: 512,
	}
	return webhookGeneratorGetStrength(entropyMap[algorithm] ?? 256)
}
export function webhookGeneratorCompareAlgorithms(
	alg1: WebhookGeneratorHmacAlgorithm,
	alg2: WebhookGeneratorHmacAlgorithm,
): number {
	const strength1 = webhookGeneratorGetAlgorithmStrength(alg1)
	const strength2 = webhookGeneratorGetAlgorithmStrength(alg2)
	const strengthOrder: Record<WebhookGeneratorStrength, number> = {
		weak: 0,
		medium: 1,
		strong: 2,
		very_strong: 3,
	}
	return strengthOrder[strength2] - strengthOrder[strength1]
}
export function webhookGeneratorIsAlgorithmSecure(
	algorithm: WebhookGeneratorHmacAlgorithm,
	minStrength: WebhookGeneratorStrength = 'strong',
): boolean {
	const strength = webhookGeneratorGetAlgorithmStrength(algorithm)
	const strengthOrder: Record<WebhookGeneratorStrength, number> = {
		weak: 0,
		medium: 1,
		strong: 2,
		very_strong: 3,
	}
	return strengthOrder[strength] >= strengthOrder[minStrength]
}
export function webhookGeneratorGetFormatStrength(
	format: WebhookGeneratorSecretFormat,
): WebhookGeneratorStrength {
	const poolSize = webhookGeneratorGetPoolSize(format)
	const entropyBits = Math.log2(poolSize) * 32
	return webhookGeneratorGetStrength(entropyBits)
}
export function webhookGeneratorIsFormatSecure(
	format: WebhookGeneratorSecretFormat,
	minStrength: WebhookGeneratorStrength = 'strong',
): boolean {
	const strength = webhookGeneratorGetFormatStrength(format)
	const strengthOrder: Record<WebhookGeneratorStrength, number> = {
		weak: 0,
		medium: 1,
		strong: 2,
		very_strong: 3,
	}
	return strengthOrder[strength] >= strengthOrder[minStrength]
}
