/** Deterministic note formatter. It extracts source sentences; it does not invent summaries. */
import { PIIEngine } from './pii-engine.js';

export const SUPPORTED_NOTE_MODES = Object.freeze(['meeting', 'lecture', 'incident', 'executive']);
const EMPTY = 'No explicit items identified in the supplied text.';
function splitSentences(text) { return String(text || '').replace(/\r\n?/g, '\n').split(/(?<=[.!?])\s+|\n+/).map((s) => s.trim()).filter(Boolean); }
function bullets(items, empty = EMPTY) { return items.length ? items.map((s) => `- ${s}`) : [`- ${empty}`]; }
const ACTION = /\b(?:todo|action item|need to|must|will|should|assign(?:ed)? to|follow up|deploy|fix|patch|rotate|audit|investigate|schedule|implement|review|update|create|complete)\b/i;
const DECISION = /\b(?:decided|agreed|approved|architecture|selected|migrated|confirmed|concluded|key takeaway|important|root cause|resolved|designed|chosen|implemented)\b/i;
const RISK = /\b(?:error|outage|latency|leak|vulnerability|timeout|failed|crash|alert|sev[0-9]|incident|risk|blocker|warning|degraded|downtime|regression|breach|unavailable)\b/i;

export function structureTranscript(rawText, options = {}) {
  const mode = SUPPORTED_NOTE_MODES.includes(options.mode) ? options.mode : 'meeting';
  const original = typeof rawText === 'string' ? rawText : '';
  const engine = options.piiEngine && typeof options.piiEngine.scrub === 'function' ? options.piiEngine : new PIIEngine(options.piiOptions || {});
  const scrub = options.autoScrub === false
    ? { scrubbedText: original, vaultMap: {}, stats: { totalRedacted: 0, byLayer: { 1: 0, 2: 0, 3: 0, 4: 0 }, byType: {} } }
    : engine.scrub(original, options.scrubOptions || {});
  const clean = String(scrub.scrubbedText || '').trim();
  const sentences = splitSentences(clean);
  const summary = sentences.slice(0, 2).join(' ') || 'No transcript content provided.';
  const keyPoints = sentences.filter((s) => DECISION.test(s));
  const actionItems = sentences.filter((s) => ACTION.test(s));
  const risksOrEvents = sentences.filter((s) => RISK.test(s));
  const privacy = `**Privacy Status:** ${scrub.stats.totalRedacted} sensitive item(s) scrubbed locally`;
  let sections;
  if (mode === 'meeting') {
    sections = [['1. Executive Summary', summary], ['2. Key Technical Decisions', ...bullets(keyPoints)], ['3. Action Items & Owners', ...bullets(actionItems).map((x) => x.replace(/^- /, '- [ ] '))], ['4. Risks & Blockers', ...bullets(risksOrEvents)]];
  } else if (mode === 'lecture') {
    sections = [['1. Core Thesis & Overview', summary], ['2. Key Concepts & Mechanisms', ...bullets(keyPoints)], ['3. Practical Takeaways & Exercises', ...bullets(actionItems)], ['4. Edge Cases & Pitfalls', ...bullets(risksOrEvents)]];
  } else if (mode === 'incident') {
    sections = [['1. Incident Summary & Impact', summary], ['2. Root Cause & Trigger Analysis', ...bullets(keyPoints)], ['3. Timeline & Detection Signals', ...bullets(risksOrEvents)], ['4. Remediation & Prevention', ...bullets(actionItems).map((x) => x.replace(/^- /, '- [ ] '))]];
  } else {
    sections = [['1. Bottom Line', summary], ['2. Strategic Outcomes & Decisions', ...bullets(keyPoints)], ['3. Operational Risks', ...bullets(risksOrEvents)], ['4. Next Milestones', ...bullets(actionItems)]];
  }
  const title = { meeting: 'Engineering Meeting & Architecture Sync', lecture: 'Technical Lecture & Study Notes', incident: 'SRE Incident Post-Mortem', executive: 'Executive Engineering Brief' }[mode];
  const markdown = [`# ${title}`, '', privacy, '', ...sections.flatMap(([heading, ...body]) => [`## ${heading}`, ...body, ''])].join('\n').trim();
  return { mode, markdown, scrubbedText: clean, vaultMap: scrub.vaultMap || {}, piiStats: scrub.stats, sections: { summary, keyPoints, actionItems, risksOrEvents } };
}
