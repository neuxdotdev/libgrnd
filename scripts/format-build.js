#!/usr/bin/env node

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { execSync } from 'node:child_process'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const projectRoot = path.join(__dirname, '..')
const buildDir = path.join(projectRoot, 'build')
const tmpDir = path.join(projectRoot, 'tmp-build')

console.log('🚀 Starting build formatter...')

// ✅ Helper: aman rename hanya jika source ada
const safeRename = (from, to) => {
	if (fs.existsSync(from)) {
		if (fs.existsSync(to)) {
			fs.rmSync(to, { recursive: true, force: true })
		}
		fs.renameSync(from, to)
		return true
	}
	return false
}

// ✅ Helper: format file .map
function formatMapFiles(dir) {
	if (!fs.existsSync(dir)) return

	for (const file of fs.readdirSync(dir)) {
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
				console.warn(
					`  ⚠️  Skip map: ${path.relative(projectRoot, fullPath)} - ${err.message}`,
				)
			}
		}
	}
}

// ✅ Step 1: Backup build → tmp-build (jika build ada)
console.log('📦 Backing up build folder...')
const buildWasMoved = safeRename(buildDir, tmpDir)

if (!buildWasMoved) {
	console.warn('⚠️  Build folder not found. Skipping format step.')
	console.log('✅ Done! (Nothing to format)')
	process.exit(0)
}

// ✅ Step 2: Run global format (prettier root)
console.log('✨ Running npm format...')
try {
	execSync('npm run format', { stdio: 'inherit', cwd: projectRoot })
} catch {
	console.warn('⚠️  npm format had issues, continuing...')
}

// ✅ Step 3: Format khusus file di tmp-build
console.log('🔨 Force formatting all build files...')
try {
	execSync(`npx prettier --write "${path.relative(projectRoot, tmpDir)}/**/*" --ignore-unknown`, {
		stdio: 'inherit',
		cwd: projectRoot,
	})
} catch {
	console.warn('⚠️  Prettier on build files had issues, continuing...')
}

// ✅ Step 4: Format sourcemaps
console.log('🗺️  Ensuring source maps are formatted...')
formatMapFiles(tmpDir)

// ✅ Step 5: Restore tmp-build → build
console.log('📂 Restoring build folder...')
if (fs.existsSync(buildDir)) {
	fs.rmSync(buildDir, { recursive: true, force: true })
}
safeRename(tmpDir, buildDir)

console.log('✅ Done! Build folder has been formatted.')
