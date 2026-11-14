/**
 * LocalVault AI v2.0 — Offline Audio Transcript & Engineering Note Structurer (src/note-structurer.js)
 * Supports 4 engineering modes:
 * - 'meeting'   : Engineering Standup / Architecture Meeting Notes
 * - 'lecture'   : Technical Lecture / Deep-Dive Study Guide
 * - 'incident'  : SRE Incident Post-Mortem & Root Cause Analysis (RCA)
 * - 'executive' : Executive Engineering Brief & Decision Matrix
 * Integrates automatic 4-layer PII & secret scrubbing prior to structuring.
 */

import { PIIEngine } from './pii-engine.js';

export const SUPPORTED_NOTE_MODES = ['meeting', 'lecture', 'incident', 'executive'];

function splitSentences(text) {
  return String(text || '')
    .replace(/\r\n/g, '\n')
    .split(/(?<=[.!?])\s+|\n+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

function extractActionItems(sentences) {
  const actionPattern =
    /\b(?:todo|action item|need to|must|will|should|assign(?:ed)? to|follow up|deploy|fix|patch|rotate|audit|investigate|schedule)\b/i;
  const matches = sentences.filter((s) => actionPattern.test(s));
  return matches.length > 0 ? matches : sentences.slice(0, 2);
}

function extractDecisionsOrKeyPoints(sentences) {
  const decisionPattern =
    /\b(?:decided|agreed|approved|architecture|selected|migrated|confirmed|concluded|key takeaway|important|root cause|resolved)\b/i;
  const matches = sentences.filter((s) => decisionPattern.test(s));
  return matches.length > 0 ? matches : sentences.slice(0, 3);
}

function extractRisksOrTimeline(sentences) {
  const riskPattern =
    /\b(?:error|outage|latency|leak|vulnerability|timeout|failed|crash|alert|sev[0-9]|incident|risk|blocker|warning|degraded)\b/i;
  const matches = sentences.filter((s) => riskPattern.test(s));
  return matches.length > 0 ? matches : sentences.slice(0, 2);
}

/**
 * Structure raw transcript or engineering notes into deterministic Markdown with automatic 4-layer PII scrubbing.
 * @param {string} rawText
 * @param {object} [options]
 * @param {'meeting'|'lecture'|'incident'|'executive'} [options.mode='meeting']
 * @param {boolean} [options.autoScrub=true]
 * @param {PIIEngine} [options.piiEngine]
 * @returns {{ mode: string, markdown: string, scrubbedText: string, vaultMap: object, piiStats: object, sections: object }}
 */
export function structureTranscript(rawText, options = {}) {
  const mode = SUPPORTED_NOTE_MODES.includes(options.mode)
    ? options.mode
    : 'meeting';
  const autoScrub = options.autoScrub !== false;
  const engine = options.piiEngine || new PIIEngine(options.piiOptions || {});

  const scrubResult = autoScrub
    ? engine.scrub(String(rawText || ''))
    : {
        scrubbedText: String(rawText || ''),
        vaultMap: {},
        detections: [],
        stats: { totalRedacted: 0, byLayer: { 1: 0, 2: 0, 3: 0, 4: 0 }, byType: {} }
      };

  const cleanText = scrubResult.scrubbedText.trim();
  const sentences = splitSentences(cleanText);
  const summarySentences = sentences.slice(0, 2).join(' ') || 'No transcript content provided.';
  const keyPoints = extractDecisionsOrKeyPoints(sentences);
  const actionItems = extractActionItems(sentences);
  const risksOrEvents = extractRisksOrTimeline(sentences);

  let markdown = '';
  const sections = {
    summary: summarySentences,
    keyPoints,
    actionItems,
    risksOrEvents
  };

  if (mode === 'meeting') {
    markdown = [
      '# Engineering Meeting & Architecture Sync',
      '',
      `**Privacy Status:** ${scrubResult.stats.totalRedacted} sensitive token(s) scrubbed locally`,
      '',
      '## 1. Executive Summary',
      summarySentences,
      '',
      '## 2. Key Technical Decisions',
      ...keyPoints.map((pt) => `- ${pt}`),
      '',
      '## 3. Action Items & Owners',
      ...actionItems.map((act) => `- [ ] ${act}`),
      '',
      '## 4. Risks & Blockers',
      ...risksOrEvents.map((r) => `- ${r}`)
    ].join('\n');
  } else if (mode === 'lecture') {
    markdown = [
      '# Technical Lecture & Systems Study Notes',
      '',
      `**Privacy Status:** ${scrubResult.stats.totalRedacted} sensitive token(s) scrubbed locally`,
      '',
      '## 1. Core Thesis & Overview',
      summarySentences,
      '',
      '## 2. Key Concepts & Mechanisms',
      ...keyPoints.map((pt) => `- ${pt}`),
      '',
      '## 3. Practical Takeaways & Lab Exercises',
      ...actionItems.map((act) => `- ${act}`),
      '',
      '## 4. Edge Cases & Exam Pitfalls',
      ...risksOrEvents.map((r) => `- ${r}`)
    ].join('\n');
  } else if (mode === 'incident') {
    markdown = [
      '# SRE Incident Post-Mortem (RCA)',
      '',
      `**Privacy Status:** ${scrubResult.stats.totalRedacted} sensitive token(s) scrubbed locally`,
      '',
      '## 1. Incident Summary & Impact',
      summarySentences,
      '',
      '## 2. Root Cause & Trigger Analysis',
      ...keyPoints.map((pt) => `- ${pt}`),
      '',
      '## 3. Timeline & Detection Signals',
      ...risksOrEvents.map((r) => `- ${r}`),
      '',
      '## 4. Remediation & Prevention Action Items',
      ...actionItems.map((act) => `- [ ] ${act}`)
    ].join('\n');
  } else if (mode === 'executive') {
    markdown = [
      '# Executive Engineering Brief',
      '',
      `**Privacy Status:** ${scrubResult.stats.totalRedacted} sensitive token(s) scrubbed locally`,
      '',
      '## 1. Bottom-Line Up Front (BLUF)',
      summarySentences,
      '',
      '## 2. Strategic Outcomes & Decisions',
      ...keyPoints.map((pt) => `- ${pt}`),
      '',
      '## 3. Operational Risks & Resource Exposure',
      ...risksOrEvents.map((r) => `- ${r}`),
      '',
      '## 4. Next Milestones',
      ...actionItems.map((act) => `- ${act}`)
    ].join('\n');
  }

  return {
    mode,
    markdown,
    scrubbedText: cleanText,
    vaultMap: scrubResult.vaultMap,
    piiStats: scrubResult.stats,
    sections
  };
}
