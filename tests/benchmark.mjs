#!/usr/bin/env node
// Scores the scanner against fixtures/vulnerable-app/EXPECTED.json.
// Detection = planted bugs found (rule + file). False positive = any other finding of severity low or higher.

import fs from 'node:fs'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const APP = path.join(ROOT, 'fixtures', 'vulnerable-app')
const expected = JSON.parse(fs.readFileSync(path.join(APP, 'EXPECTED.json'), 'utf8')).planted

const r = spawnSync(process.execPath, [path.join(ROOT, 'skills/vibe-audit/scripts/scan.mjs'), APP, '--json', '--offline', '--no-external'], { encoding: 'utf8' })
if (r.status !== 0) { console.error(r.stderr); process.exit(1) }
const { findings } = JSON.parse(r.stdout)

const matched = new Set()
const results = expected.map((e) => {
  const hit = findings.find((f) => f.rule === e.rule && f.file === e.file)
  if (hit) matched.add(hit)
  return { ...e, found: !!hit, severity: hit?.severity }
})
const unexpected = findings.filter((f) => !matched.has(f) && !expected.some((e) => e.rule === f.rule && e.file === f.file))
const falsePositives = unexpected.filter((f) => !['low', 'info'].includes(f.severity))
const notes = unexpected.filter((f) => ['low', 'info'].includes(f.severity))

for (const x of results) console.log(`${x.found ? 'PASS' : 'MISS'}  ${x.rule.padEnd(24)} ${x.file}${x.found ? `  (${x.severity})` : ''}`)
for (const f of falsePositives) console.log(`FP    ${f.rule.padEnd(24)} ${f.file}:${f.line}  ${f.title}`)
for (const f of notes) console.log(`note  ${f.rule.padEnd(24)} ${f.file}:${f.line}  (${f.severity}) ${f.title}`)

const found = results.filter((x) => x.found).length
console.log(`\nDetected ${found}/${expected.length} planted vulnerabilities, ${falsePositives.length} false positive(s) at medium or above, ${notes.length} low/info note(s).`)
process.exit(found === expected.length && falsePositives.length === 0 ? 0 : 1)
