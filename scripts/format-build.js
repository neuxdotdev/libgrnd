#!/usr/bin/env node

import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'
import { execSync } from 'child_process'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const projectRoot = path.join(__dirname, '..')
const buildDir = path.join(projectRoot, 'build')
const tmpDir = path.join(projectRoot, 'tmp-build')

console.log('🚀 Starting build formatter...')

console.log('📦 Backing up build folder...')
if (fs.existsSync(buildDir)) {
	if (fs.existsSync(tmpDir)) {
		fs.rmSync(tmpDir, { recursive: true, force: true })
	}
	fs.renameSync(buildDir, tmpDir)
}

console.log('✨ Running npm format...')
try {
	execSync('npm run format', { stdio: 'inherit', cwd: projectRoot })
} catch (error) {
	console.warn('⚠️  npm format failed, but continuing...')
}

console.log('🔨 Force formatting all build files...')
try {
	execSync('npx prettier --write "tmp-build/**/*" --ignore-unknown', {
		stdio: 'inherit',
		cwd: projectRoot,
	})
} catch (error) {
	console.warn('⚠️  Prettier formatting had some issues, but continuing...')
}

console.log('🗺️  Ensuring source maps are formatted...')
function formatMapFiles(dir) {
	if (!fs.existsSync(dir)) return

	const files = fs.readdirSync(dir)

	files.forEach((file) => {
		const fullPath = path.join(dir, file)
		const stat = fs.statSync(fullPath)

		if (stat.isDirectory()) {
			formatMapFiles(fullPath)
		} else if (file.endsWith('.map')) {
			try {
				const content = fs.readFileSync(fullPath, 'utf8')

				const json = JSON.parse(content)

				fs.writeFileSync(fullPath, JSON.stringify(json, null, 2))
				console.log(`  ✅ Formatted: ${path.relative(projectRoot, fullPath)}`)
			} catch (err) {
				console.log(`  ❌ Failed: ${path.relative(projectRoot, fullPath)} - ${err.message}`)
			}
		}
	})
}

formatMapFiles(tmpDir)

console.log('📂 Restoring build folder...')
if (fs.existsSync(buildDir)) {
	fs.rmSync(buildDir, { recursive: true, force: true })
}
fs.renameSync(tmpDir, buildDir)

console.log('✅ Done! Build folder has been formatted.')
