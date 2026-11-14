#!/usr/bin/env node
/**
 * LocalVault AI — Developer CLI (Option B Terminal & CI/CD Utility)
 */

import fs from 'node:fs';
import path from 'node:path';
import { scrubText } from '../src/pii-engine.js';
import { structureTranscriptInstant } from '../src/note-structurer.js';

const args = process.argv.slice(2);
const command = (args[0] || 'help').toLowerCase();
const target = args.slice(1).join(' ');

function readTargetInput(inputStr) {
  if (!inputStr) return '';
  const resolved = path.resolve(process.cwd(), inputStr);
  if (fs.existsSync(resolved) && fs.statSync(resolved).isFile()) {
    return fs.readFileSync(resolved, 'utf-8');
  }
  return inputStr;
}

if (command === 'scrub') {
  const raw = readTargetInput(target) || 'User: Dr. Jane Doe (jane@acme.io), DB: postgres://admin:s3cr3tPass99@db.internal:5432/prod';
  const result = scrubText(raw);
  console.log('=== LocalVault CLI: 4-Layer PII & Secret Scrubbing ===');
  console.log(`Risk Level: ${result.stats.risk.level} (${result.stats.risk.score}/100) | Redactions: ${result.stats.totalRedactions}`);
  console.log('\n--- Sanitized Output ---');
  console.log(result.scrubbedText);
  console.log('\n--- Detected Entities ---');
  for (const ent of result.entities) {
    console.log(`  ${ent.token} -> [${ent.category}] (entropy: ${ent.entropy} bits/char, hits: ${ent.count}x)`);
  }
} else if (command === 'structure') {
  const raw = readTargetInput(target) || 'Welcome to the sprint planning meeting. We must deploy the WebGPU PII firewall by Friday. Are there any blockers?';
  const notes = structureTranscriptInstant(raw, 'meeting');
  console.log(notes);
} else {
  console.log(`LocalVault AI CLI v2.0
Commands:
  npm run cli -- scrub <file-or-string>      Scrub PII, API keys, DB URIs & high-entropy secrets
  npm run cli -- structure <file-or-string>  Structure raw transcript into Markdown notes`);
}
