
#!/usr/bin/env node

/**
 * LocalVault AI v2.0 — Node.js CLI
 *
 * Usage:
 *   npm run cli -- scrub <file-or-text>
 *   npm run cli -- structure <file-or-text> --mode=meeting
 *   npm run cli -- entropy <string>
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  PIIEngine,
  calculateShannonEntropy
} from '../src/pii-engine.js';

import {
  structureTranscript,
  SUPPORTED_NOTE_MODES
} from '../src/note-structurer.js';

const SCRIPT_PATH = fileURLToPath(import.meta.url);

function printHelp() {
  return [
    'LocalVault AI v2.0 CLI',
    '',
    'Commands:',
    '  localvault scrub <path-or-text>',
    '      Detect and replace supported PII and secret patterns.',
    '',
    '  localvault structure <path-or-text> [--mode=MODE]',
    '      Structure text into Markdown.',
    '      Modes: meeting, lecture, incident, executive',
    '',
    '  localvault entropy <string>',
    '      Calculate Shannon entropy in bits per character.',
    '',
    '  localvault --help',
    '      Show this help message.',
    '',
    'Examples:',
    '  npm run cli -- scrub .env',
    '  npm run cli -- scrub "Email alice@example.com"',
    '  npm run cli -- structure notes.txt --mode=incident',
    '  npm run cli -- entropy "example-token-123"'
  ].join('\n');
}

/**
 * If the input names a regular file, read it as UTF-8.
 * Otherwise, treat the input as literal text.
 */
function resolveInput(targetArg) {
  if (typeof targetArg !== 'string' || !targetArg.length) {
    return '';
  }

  const candidatePath = path.resolve(
    process.cwd(),
    targetArg
  );

  try {
    if (
      fs.existsSync(candidatePath) &&
      fs.statSync(candidatePath).isFile()
    ) {
      return fs.readFileSync(candidatePath, 'utf8');
    }
  } catch (error) {
    throw new Error(
      `Could not read input file: ${error.message}`
    );
  }

  return targetArg;
}

function parseMode(flags) {
  const modeFlag = flags.find(
    flag => flag.startsWith('--mode=')
  );

  const mode = modeFlag
    ? modeFlag.slice('--mode='.length).trim()
    : 'meeting';

  if (!SUPPORTED_NOTE_MODES.includes(mode)) {
    throw new Error(
      `Unsupported note mode "${mode}". Use: ${SUPPORTED_NOTE_MODES.join(', ')}.`
    );
  }

  return mode;
}

function writeOutput(output, error = false) {
  if (error) {
    console.error(output);
  } else {
    console.log(output);
  }
}

/**
 * Run the CLI.
 *
 * Exported for automated tests.
 *
 * @param {string[]} argv
 * @returns {object}
 */
export function runCli(argv = process.argv.slice(2)) {
  const [command, target, ...flags] = argv || [];

  if (
    !command ||
    command === '--help' ||
    command === '-h' ||
    command === 'help'
  ) {
    const output = printHelp();
    writeOutput(output);

    return {
      exitCode: 0,
      output
    };
  }

  const engine = new PIIEngine();

  try {
    if (command === 'scrub') {
      if (!target) {
        throw new Error(
          'Provide a file path or text to scrub.'
        );
      }

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

      writeOutput(output);

      return {
        exitCode: 0,
        result
      };
    }

    if (command === 'structure') {
      if (!target) {
        throw new Error(
          'Provide a file path or text to structure.'
        );
      }

      const input = resolveInput(target);
      const mode = parseMode(flags);

      const result = structureTranscript(input, {
        mode,
        autoScrub: true,
        piiEngine: engine
      });

      writeOutput(result.markdown);

      return {
        exitCode: 0,
        result
      };
    }

    if (command === 'entropy') {
      if (!target) {
        throw new Error(
          'Provide a string to calculate entropy.'
        );
      }

      const entropy = calculateShannonEntropy(target);
      const output =
        `Shannon Entropy H(X): ${entropy} bits/char`;

      writeOutput(output);

      return {
        exitCode: 0,
        entropy
      };
    }

    throw new Error(`Unknown command: ${command}`);
  } catch (error) {
    const message = error?.message || String(error);
    writeOutput(`LocalVault CLI error: ${message}`, true);

    return {
      exitCode: 1,
      error: message
    };
  }
}

const isDirectExecution =
  process.argv[1] &&
  path.resolve(process.argv[1]) === path.resolve(SCRIPT_PATH);

if (isDirectExecution) {
  const result = runCli(process.argv.slice(2));
  process.exitCode = result.exitCode;
}
