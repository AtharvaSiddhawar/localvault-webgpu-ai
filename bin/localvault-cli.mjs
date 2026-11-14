#!/usr/bin/env node
/**
 * LocalVault AI v2.0 — Node.js Terminal & CI/CD CLI (bin/localvault-cli.mjs)
 * Usage:
 *   npm run cli -- scrub <file-or-text>
 *   npm run cli -- structure <file-or-text> [--mode=meeting|lecture|incident|executive]
 *   npm run cli -- entropy <token>
 */

import fs from 'node:fs';
import path from 'node:path';
import { PIIEngine, calculateShannonEntropy } from '../src/pii-engine.js';
import { structureTranscript } from '../src/note-structurer.js';

function resolveInput(targetArg) {
  if (!targetArg) return '';
  const candidatePath = path.resolve(process.cwd(), targetArg);
  if (fs.existsSync(candidatePath) && fs.statSync(candidatePath).isFile()) {
    return fs.readFileSync(candidatePath, 'utf8');
  }
  return targetArg;
}

export function runCli(argv = process.argv.slice(2)) {
  const [command, target, ...flags] = argv;
  const engine = new PIIEngine();

  if (!command || command === '--help' || command === '-h') {
    const helpText = [
      'LocalVault AI v2.0 CLI (Zero-Cloud PII Firewall & Note Structurer)',
      '',
      'Commands:',
      '  localvault scrub <path-or-string>                 Run 4-layer PII & secret scrubber',
      '  localvault structure <path-or-string> [--mode=X]  Structure transcript (meeting|lecture|incident|executive)',
      '  localvault entropy <string>                       Compute Shannon entropy H(X) in bits/char'
    ].join('\n');
    console.log(helpText);
    return { exitCode: 0, output: helpText };
  }

  if (command === 'scrub') {
    const input = resolveInput(target);
    const result = engine.scrub(input);
    const output = JSON.stringify(
      {
        scrubbedText: result.scrubbedText,
        stats: result.stats,
        detections: result.detections
      },
      null,
      2
    );
    console.log(output);
    return { exitCode: 0, result };
  }

  if (command === 'structure') {
    const input = resolveInput(target);
    const modeFlag = flags.find((f) => f.startsWith('--mode='));
    const mode = modeFlag ? modeFlag.split('=')[1] : 'meeting';
    const result = structureTranscript(input, { mode, autoScrub: true, piiEngine: engine });
    console.log(result.markdown);
    return { exitCode: 0, result };
  }

  if (command === 'entropy') {
    const h = calculateShannonEntropy(target || '');
    console.log(`Shannon Entropy H(X): ${h} bits/char`);
    return { exitCode: 0, entropy: h };
  }

  console.error(`Unknown command: ${command}`);
  return { exitCode: 1 };
}

const isDirectExecution =
  process.argv[1] &&
  path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname);

if (isDirectExecution) {
  const { exitCode } = runCli(process.argv.slice(2));
  process.exit(exitCode);
}

