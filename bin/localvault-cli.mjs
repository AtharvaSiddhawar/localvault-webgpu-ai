#!/usr/bin/env node
/** LocalVault command-line companion. */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { PIIEngine, calculateShannonEntropy } from '../src/pii-engine.js';
import { structureTranscript, SUPPORTED_NOTE_MODES } from '../src/note-structurer.js';

const SCRIPT_PATH = fileURLToPath(import.meta.url);
function helpText() {
  return [
    'LocalVault AI v2.1 CLI', '',
    'Commands:',
    '  localvault scrub <file-path-or-literal-text>',
    '  localvault structure <file-path-or-literal-text> [--mode=meeting|lecture|incident|executive]',
    '  localvault entropy <text>',
    '  localvault --help', '',
    'Examples:',
    '  npm run cli -- scrub .env',
    '  npm run cli -- scrub "Contact alex@example.org"',
    '  npm run cli -- structure notes.txt --mode=incident',
    '  npm run cli -- entropy "sample-token-123"'
  ].join('\n');
}
function resolveInput(target) {
  if (typeof target !== 'string' || !target.length) throw new Error('Provide a file path or text input.');
  const candidate = path.resolve(process.cwd(), target);
  try { if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) return fs.readFileSync(candidate, 'utf8'); }
  catch (error) { throw new Error(`Could not read input file: ${error.message}`); }
  return target;
}
function write(output, isError = false) { (isError ? console.error : console.log)(output); }
function parseMode(flags) {
  const flag = flags.find((value) => value.startsWith('--mode='));
  const mode = flag ? flag.slice(7) : 'meeting';
  if (!SUPPORTED_NOTE_MODES.includes(mode)) throw new Error(`Unsupported mode "${mode}". Choose ${SUPPORTED_NOTE_MODES.join(', ')}.`);
  return mode;
}

export function runCli(argv = process.argv.slice(2)) {
  const [command, target, ...flags] = Array.isArray(argv) ? argv : [];
  if (!command || ['--help', '-h', 'help'].includes(command)) {
    const output = helpText(); write(output); return { exitCode: 0, output };
  }
  try {
    if (command === 'scrub') {
      const input = resolveInput(target);
      const result = new PIIEngine().scrub(input);
      const output = JSON.stringify({ scrubbedText: result.scrubbedText, stats: result.stats, detections: result.detections }, null, 2);
      write(output); return { exitCode: 0, output, result };
    }
    if (command === 'structure') {
      const input = resolveInput(target);
      const result = structureTranscript(input, { mode: parseMode(flags), autoScrub: true });
      write(result.markdown); return { exitCode: 0, output: result.markdown, result };
    }
    if (command === 'entropy') {
      if (typeof target !== 'string' || !target.length) throw new Error('Provide text for entropy calculation.');
      const entropy = calculateShannonEntropy(target);
      const output = `Shannon entropy: ${entropy} bits per character`;
      write(output); return { exitCode: 0, output, entropy };
    }
    throw new Error(`Unknown command: ${command}`);
  } catch (error) {
    const message = error?.message || String(error);
    const output = `LocalVault CLI error: ${message}`;
    write(output, true); return { exitCode: 1, output, error: message };
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(SCRIPT_PATH)) {
  const result = runCli(process.argv.slice(2));
  process.exitCode = result.exitCode;
}
