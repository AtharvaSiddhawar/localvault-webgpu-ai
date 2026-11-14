/**
 * Offline Audio Transcript Note-Structurer v2.0
 */

const ACTION_VERBS = /\b(?:need to|must|should|will|todo|action item|deadline|by friday|by monday|by tomorrow|follow up|schedule|prepare|submit|review|complete|deliver|assign|rotate|migrate|deploy)\b/i;
const QUESTION_PATTERN = /\?$/;

export function buildNoteStructuringMessages(transcript, mode = 'meeting') {
  const cleanTranscript = (transcript || '').trim();
  const systemPrompts = {
    meeting:
      'You are an offline meeting assistant running locally via WebGPU. Convert the transcript into clean Markdown with these exact sections: ## Executive Summary, ## Key Decisions & Insights, ## Action Items & Owners, and ## Open Questions.',
    lecture:
      'You are an academic lecture synthesizer running locally via WebGPU. Convert the lecture transcript into clean Markdown with these exact sections: ## Core Thesis, ## Key Concepts & Definitions, ## Architecture Highlights, and ## Study Review Questions.',
    incident:
      'You are a Principal Site Reliability Engineer running locally via WebGPU. Convert the incident transcript into a blameless post-mortem in Markdown with: ## Incident Summary, ## Root Cause & Impact, ## Remediation Action Items, and ## Security & Privacy Guardrails.',
    executive:
      'You are an executive briefing analyst. Distill the transcript into a crisp Markdown brief with: ## TL;DR (3 Bullet Points), ## Strategic Takeaways, and ## Immediate Next Steps.'
  };

  return [
    {
      role: 'system',
      content: systemPrompts[mode] || systemPrompts.meeting
    },
    {
      role: 'user',
      content: `Structure the following transcript into organized Markdown notes:\n\n${cleanTranscript.slice(0, 4200)}`
    }
  ];
}

export function structureTranscriptInstant(transcript, mode = 'meeting', meta = {}) {
  const text = (transcript || '').trim();
  if (!text) return '';

  const sentences = text
    .replace(/([.?!])\s+/g, '$1\n')
    .split(/\n+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 3);

  const wordCount = text.split(/\s+/).filter(Boolean).length;
  const estSpeakingMinutes = Math.max(1, Math.round(wordCount / 130));

  const stopWords = new Set([
    'the', 'and', 'that', 'this', 'with', 'from', 'have', 'will', 'your', 'about',
    'they', 'their', 'what', 'when', 'where', 'which', 'there', 'were', 'been',
    'into', 'more', 'some', 'very', 'just', 'also', 'than', 'then', 'them', 'these'
  ]);

  const freq = {};
  for (const word of text.toLowerCase().match(/[a-z]{4,}/g) || []) {
    if (!stopWords.has(word)) {
      freq[word] = (freq[word] || 0) + 1;
    }
  }

  const scoredSentences = sentences.map((sentence, idx) => {
    const words = sentence.toLowerCase().match(/[a-z]{4,}/g) || [];
    const score = words.reduce((acc, w) => acc + (freq[w] || 0), 0) / Math.max(4, words.length);
    return { sentence, idx, score };
  });

  const topSummary = [...scoredSentences]
    .sort((a, b) => b.score - a.score)
    .slice(0, Math.min(3, sentences.length))
    .sort((a, b) => a.idx - b.idx)
    .map((s) => s.sentence);

  const actionItems = sentences.filter((s) => ACTION_VERBS.test(s));
  const questions = sentences.filter((s) => QUESTION_PATTERN.test(s));

  const topKeywords = Object.entries(freq)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([word]) => `\`${word}\``)
    .join(', ');

  const titleMap = {
    meeting: '# Structured Meeting Notes',
    lecture: '# Structured Lecture Notes',
    incident: '# Engineering Incident Post-Mortem',
    executive: '# Executive Briefing'
  };

  const lines = [];
  lines.push(titleMap[mode] || titleMap.meeting);
  const piiTag = typeof meta.piiRedactedCount === 'number'
    ? ` | Auto-Scrubbed PII: ${meta.piiRedactedCount} entities`
    : '';
  lines.push(`> **Processed 100% Client-Side** | Words: ${wordCount} | Est. Audio: ~${estSpeakingMinutes} min${piiTag}`);
  if (topKeywords) {
    lines.push(`> **Core Topics:** ${topKeywords}`);
  }
  lines.push('');

  lines.push('## Executive Summary');
  for (const item of topSummary) {
    lines.push(`- ${item}`);
  }
  lines.push('');

  if (mode === 'lecture') {
    lines.push('## Key Concepts & Insights');
  } else if (mode === 'incident') {
    lines.push('## Root Cause & Architecture Observations');
  } else {
    lines.push('## Key Decisions & Takeaways');
  }

  const chunkCount = Math.max(1, Math.ceil(sentences.length / 3));
  for (let i = 0; i < sentences.length; i += chunkCount) {
    const group = sentences.slice(i, i + chunkCount);
    if (group.length > 0) {
      lines.push(`- ${group.join(' ')}`);
    }
  }
  lines.push('');

  lines.push('## Action Items & Follow-Ups');
  if (actionItems.length > 0) {
    for (const act of actionItems) {
      lines.push(`- [ ] ${act}`);
    }
  } else {
    lines.push('- [ ] Review transcript highlights and confirm next steps with team.');
  }
  lines.push('');

  if (questions.length > 0) {
    lines.push('## Open Questions');
    for (const q of questions) {
      lines.push(`- ${q}`);
    }
    lines.push('');
  }

  return lines.join('\n');
    }
