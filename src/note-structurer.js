
/**
 * LocalVault AI v2.0 — Offline Engineering Note Structurer
 *
 * Supported modes:
 * - meeting
 * - lecture
 * - incident
 * - executive
 *
 * Features:
 * - Optional local PII and secret scrubbing
 * - Deterministic sentence classification
 * - Markdown output
 * - Explicit empty-section messages
 *
 * Note:
 * This is a deterministic rule-based structurer, not an AI summarizer.
 */

import { PIIEngine } from './pii-engine.js';

export const SUPPORTED_NOTE_MODES = Object.freeze([
  'meeting',
  'lecture',
  'incident',
  'executive'
]);

const EMPTY_MESSAGE = 'No explicit items identified in the supplied text.';

/**
 * Normalize and split transcript text into sentences.
 */
function splitSentences(text) {
  return String(text || '')
    .replace(/\r\n?/g, '\n')
    .split(/(?<=[.!?])\s+|\n+/)
    .map(sentence => sentence.trim())
    .filter(Boolean);
}

/**
 * Identify sentences that appear to contain action items.
 */
function extractActionItems(sentences) {
  const pattern =
    /\b(?:todo|action item|need to|must|will|should|assign(?:ed)? to|follow up|deploy|fix|patch|rotate|audit|investigate|schedule|implement|review|update|create|complete)\b/i;

  return sentences.filter(sentence => pattern.test(sentence));
}

/**
 * Identify decisions and important technical points.
 */
function extractDecisionsOrKeyPoints(sentences) {
  const pattern =
    /\b(?:decided|agreed|approved|architecture|selected|migrated|confirmed|concluded|key takeaway|important|root cause|resolved|designed|chosen|implemented)\b/i;

  return sentences.filter(sentence => pattern.test(sentence));
}

/**
 * Identify operational risks, failures and incident signals.
 */
function extractRisksOrTimeline(sentences) {
  const pattern =
    /\b(?:error|outage|latency|leak|vulnerability|timeout|failed|crash|alert|sev[0-9]|incident|risk|blocker|warning|degraded|downtime|regression|breach|unavailable)\b/i;

  return sentences.filter(sentence => pattern.test(sentence));
}

/**
 * Create a safe list of Markdown bullet items.
 */
function makeBulletList(items, emptyMessage = EMPTY_MESSAGE) {
  if (!items.length) {
    return [`- ${emptyMessage}`];
  }

  return items.map(item => `- ${item}`);
}

/**
 * Return an empty and consistent PII result.
 */
function createEmptyScrubResult(text) {
  return {
    scrubbedText: text,
    vaultMap: {},
    detections: [],
    stats: {
      totalRedacted: 0,
      byLayer: {
        1: 0,
        2: 0,
        3: 0,
        4: 0
      },
      byType: {}
    }
  };
}

/**
 * Structure a transcript or engineering notes into Markdown.
 *
 * @param {string} rawText
 * @param {object} [options]
 * @param {'meeting'|'lecture'|'incident'|'executive'} [options.mode='meeting']
 * @param {boolean} [options.autoScrub=true]
 * @param {PIIEngine} [options.piiEngine]
 *
 * @returns {{
 *   mode: string,
 *   markdown: string,
 *   scrubbedText: string,
 *   vaultMap: object,
 *   piiStats: object,
 *   sections: object
 * }}
 */
export function structureTranscript(rawText, options = {}) {
  const mode = SUPPORTED_NOTE_MODES.includes(options.mode)
    ? options.mode
    : 'meeting';

  const autoScrub = options.autoScrub !== false;

  const originalText =
    typeof rawText === 'string'
      ? rawText
      : '';

  const engine =
    options.piiEngine &&
    typeof options.piiEngine.scrub === 'function'
      ? options.piiEngine
      : new PIIEngine(options.piiOptions || {});

  // Privacy processing happens before sentence classification.
  const scrubResult = autoScrub
    ? engine.scrub(originalText)
    : createEmptyScrubResult(originalText);

  const cleanText = String(
    scrubResult.scrubbedText || ''
  ).trim();

  const sentences = splitSentences(cleanText);

  // These are extracted source sentences, not generated summaries.
  const summarySentences = sentences
    .slice(0, 2)
    .join(' ') || 'No transcript content provided.';

  const keyPoints =
    extractDecisionsOrKeyPoints(sentences);

  const actionItems =
    extractActionItems(sentences);

  const risksOrEvents =
    extractRisksOrTimeline(sentences);

  const sections = {
    summary: summarySentences,
    keyPoints,
    actionItems,
    risksOrEvents
  };

  const privacyStatus =
    `**Privacy Status:** ${scrubResult.stats.totalRedacted} sensitive token(s) scrubbed locally`;

  let markdown;

  if (mode === 'meeting') {
    markdown = [
      '# Engineering Meeting & Architecture Sync',
      '',
      privacyStatus,
      '',
      '## 1. Executive Summary',
      summarySentences,
      '',
      '## 2. Key Technical Decisions',
      ...makeBulletList(keyPoints),
      '',
      '## 3. Action Items & Owners',
      ...makeBulletList(actionItems).map(
        item => item.replace(/^- /, '- [ ] ')
      ),
      '',
      '## 4. Risks & Blockers',
      ...makeBulletList(risksOrEvents)
    ].join('\n');
  } else if (mode === 'lecture') {
    markdown = [
      '# Technical Lecture & Systems Study Notes',
      '',
      privacyStatus,
      '',
      '## 1. Core Thesis & Overview',
      summarySentences,
      '',
      '## 2. Key Concepts & Mechanisms',
      ...makeBulletList(keyPoints),
      '',
      '## 3. Practical Takeaways & Lab Exercises',
      ...makeBulletList(actionItems),
      '',
      '## 4. Edge Cases & Exam Pitfalls',
      ...makeBulletList(risksOrEvents)
    ].join('\n');
  } else if (mode === 'incident') {
    markdown = [
      '# SRE Incident Post-Mortem (RCA)',
      '',
      privacyStatus,
      '',
      '## 1. Incident Summary & Impact',
      summarySentences,
      '',
      '## 2. Root Cause & Trigger Analysis',
      ...makeBulletList(keyPoints),
      '',
      '## 3. Timeline & Detection Signals',
      ...makeBulletList(risksOrEvents),
      '',
      '## 4. Remediation & Prevention Action Items',
      ...makeBulletList(actionItems).map(
        item => item.replace(/^- /, '- [ ] ')
      )
    ].join('\n');
  } else {
    markdown = [
      '# Executive Engineering Brief',
      '',
      privacyStatus,
      '',
      '## 1. Bottom-Line Up Front (BLUF)',
      summarySentences,
      '',
      '## 2. Strategic Outcomes & Decisions',
      ...makeBulletList(keyPoints),
      '',
      '## 3. Operational Risks & Resource Exposure',
      ...makeBulletList(risksOrEvents),
      '',
      '## 4. Next Milestones',
      ...makeBulletList(actionItems)
    ].join('\n');
  }

  return {
    mode,
    markdown,
    scrubbedText: cleanText,
    vaultMap: scrubResult.vaultMap || {},
    piiStats: scrubResult.stats,
    sections
  };
}
