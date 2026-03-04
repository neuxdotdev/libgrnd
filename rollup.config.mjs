import { readFileSync } from 'node:fs'

import resolve from '@rollup/plugin-node-resolve'
import commonjs from '@rollup/plugin-commonjs'
import terser from '@rollup/plugin-terser'
import peerDepsExternal from 'rollup-plugin-peer-deps-external'

const isProduction = process.env.NODE_ENV === 'production'
const packageJson = JSON.parse(readFileSync('./package.json', 'utf8'))

const external = [
	...Object.keys(packageJson.dependencies || {}),
	...Object.keys(packageJson.peerDependencies || {}),
	/^node:.*/,
]

const getBaseOutput = (format) => ({
	format,
	sourcemap: true,
	sourcemapExcludeSources: false,
	exports: 'named',
	indent: false,
	strict: true,
	freeze: false,
	esModule: true,
	interop: 'auto',
	generatedCode: {
		constBindings: true,
		objectShorthand: true,
		arrowFunctions: true,
		reserveDefaultAs: false,
	},
})

const getJsPlugins = () => [
	peerDepsExternal(),

	resolve({
		preferBuiltins: true,
		browser: false,
		extensions: ['.js', '.ts', '.json'],
		moduleDirectories: ['node_modules'],
	}),

	commonjs({
		include: /node_modules/,
		requireReturnsDefault: 'auto',
		transformMixedEsModules: true,
		ignoreDynamicRequires: false,
	}),

	...(isProduction
		? [
				terser({
					compress: {
						drop_console: true,
						drop_debugger: true,
						pure_funcs: [
							'console.log',
							'console.info',
							'console.debug',
							'console.trace',
						],
						dead_code: true,
						unused: true,
						passes: 2,
					},
					format: {
						comments: false,
						ascii_only: true,
						wrap_iife: true,
					},
					sourceMap: true,
					module: true,
				}),
			]
		: []),
]

const treeShakeConfig = {
	preset: 'recommended',
	moduleSideEffects: false,
	propertyReadSideEffects: false,
	tryCatchDeoptimization: false,
	unknownGlobalSideEffects: false,
}

const onwarn = (warning, warn) => {
	const ignored = [
		'CIRCULAR_DEPENDENCY',
		'EVAL',
		'SOURCEMAP_ERROR',
		'THIS_IS_UNDEFINED',
		'MIXED_EXPORTS',
	]
	if (ignored.includes(warning.code)) return
	warn(warning)
}

export default [
	{
		input: 'dist/lib.js',
		external,
		plugins: getJsPlugins(),
		output: [
			{
				...getBaseOutput('cjs'),
				file: 'build/lib.cjs',
				entryFileNames: '[name].cjs',
				chunkFileNames: 'chunks/[name]-[hash].cjs',
				sourcemapPathTransform: isProduction
					? undefined
					: (relativeSourcePath) => relativeSourcePath.replace(/^\.\/\.\.\//, '../../'),
			},

			{
				...getBaseOutput('esm'),
				file: 'build/lib.js',
				entryFileNames: '[name].js',
				chunkFileNames: 'chunks/[name]-[hash].js',
				sourcemapPathTransform: isProduction
					? undefined
					: (relativeSourcePath) => relativeSourcePath.replace(/^\.\/\.\.\//, '../../'),
			},
		],
		treeshake: treeShakeConfig,
		onwarn,
		context: 'globalThis',
		preserveEntrySignatures: 'strict',
		makeAbsoluteExternalsRelative: false,
		shimMissingExports: false,
	},
]
