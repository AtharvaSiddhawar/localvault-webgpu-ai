/** Heuristic local PII and secret scanner. It is not a guarantee of detection. */
export const LOOPBACK_ALLOWLIST = new Set(['127.0.0.1', '0.0.0.0', 'localhost', '::1', '0:0:0:0:0:0:0:1', '::ffff:127.0.0.1']);

export function calculateShannonEntropy(value) {
  if (typeof value !== 'string' || value.length === 0) return 0;
  const counts = new Map();
  for (const char of value) counts.set(char, (counts.get(char) || 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(4));
}

export function isValidLuhn(value) {
  if (typeof value !== 'string') return false;
  const digits = value.replace(/[\s-]/g, '');
  if (!/^\d{13,19}$/.test(digits) || /^(\d)\1+$/.test(digits)) return false;
  let sum = 0;
  let doubleNext = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let digit = Number(digits[i]);
    if (doubleNext) { digit *= 2; if (digit > 9) digit -= 9; }
    sum += digit;
    doubleNext = !doubleNext;
  }
  return sum % 10 === 0;
}

export function isAllowlistedLoopback(value) {
  if (typeof value !== 'string') return false;
  const host = value.trim().toLowerCase();
  if (LOOPBACK_ALLOWLIST.has(host)) return true;
  if (!host.startsWith('127.')) return false;
  const octets = host.split('.');
  return octets.length === 4 && octets.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255);
}

const RULES = [
  ['PRIVATE_KEY', /-----BEGIN (?:RSA |OPENSSH |EC |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |OPENSSH |EC |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----/g],
  ['DB_URI', /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|amqp):\/\/[^\s'"`<>]+/gi],
  ['OPENAI_KEY', /\bsk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{20,}\b/g],
  ['ANTHROPIC_KEY', /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g],
  ['GITHUB_TOKEN', /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,255}\b|\bgithub_pat_[A-Za-z0-9_]{30,255}\b/g],
  ['AWS_KEY', /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g],
  ['SLACK_TOKEN', /\bxox[baprs]-[0-9A-Za-z-]{16,}\b/g],
  ['GOOGLE_API_KEY', /\bAIza[0-9A-Za-z_-]{35}\b/g],
  ['STRIPE_KEY', /\b(?:sk|rk|pk)_(?:live|test)_[0-9A-Za-z]{16,}\b/g],
  ['BEARER_TOKEN', /Authorization\s*:\s*Bearer\s+([A-Za-z0-9._~+\/-]{12,}=*)/gi],
  ['IBAN', /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/g],
  ['IPV6', /\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b/g],
  ['JWT_TOKEN', /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g],
  ['EMAIL', /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g],
  ['IPV4', /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g],
  ['PHONE', /(?:\+?\d{1,3}[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]\d{3}[\s.-]\d{4}\b/g],
  ['CREDIT_CARD', /\b(?:\d[ -]*?){13,19}\b/g]
];
const SECRET_ASSIGNMENT = /(\b(?:[A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|API_KEY|APIKEY|ACCESS_KEY|PRIVATE_KEY|AUTH_TOKEN|ACCESS_TOKEN|TOKEN)[A-Z0-9_]*|password|passwd|secret|apiKey|api_key|clientSecret|client_secret|accessToken|access_token|privateKey|private_key)\b\s*[:=]\s*['"`]?)([^\s'"`,;{}\]\[]+)(['"`]?)/g;
const escapeRegex = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

function emptyResult(input = '') {
  return { scrubbedText: input, vaultMap: {}, reverseMap: {}, detections: [], stats: { totalRedacted: 0, byLayer: { 1: 0, 2: 0, 3: 0, 4: 0 }, byType: {} } };
}

export class PIIEngine {
  constructor(options = {}) {
    this.customBlocklist = new Set((options.customBlocklist || []).filter((x) => typeof x === 'string').map((x) => x.trim()).filter(Boolean));
    this.customAllowlist = new Set((options.customAllowlist || []).filter((x) => typeof x === 'string').map((x) => x.trim().toLowerCase()));
    this.entropyThreshold = Number(options.entropyThreshold ?? 3.65);
    this.slmNerDetector = typeof options.slmNerDetector === 'function' ? options.slmNerDetector : null;
    this.runCounter = 0;
  }

  addBlocklistTerm(term) { if (typeof term === 'string' && term.trim()) this.customBlocklist.add(term.trim()); }
  removeBlocklistTerm(term) { if (typeof term === 'string') this.customBlocklist.delete(term.trim()); }
  isAllowlisted(value) { const v = String(value || '').trim().toLowerCase(); return this.customAllowlist.has(v) || isAllowlistedLoopback(v); }

  scrub(inputText, options = {}) {
    if (typeof inputText !== 'string' || inputText.length === 0) return emptyResult(typeof inputText === 'string' ? inputText : '');
    const run = ++this.runCounter;
    let text = inputText;
    const vaultMap = {};
    const reverseMap = {};
    const detections = [];
    const byLayer = { 1: 0, 2: 0, 3: 0, 4: 0 };
    const byType = {};
    const counts = {};
    const marker = (type) => {
      counts[type] = (counts[type] || 0) + 1;
      return run === 1 ? `[${type}_${counts[type]}]` : `[${type}_R${run}_${counts[type]}]`;
    };
    const add = (raw, type, layer) => {
      const value = String(raw).trim();
      if (!value || this.isAllowlisted(value) || Object.hasOwn(reverseMap, value)) return reverseMap[value] || raw;
      const placeholder = marker(type);
      vaultMap[placeholder] = value;
      reverseMap[value] = placeholder;
      byLayer[layer]++;
      byType[type] = (byType[type] || 0) + 1;
      detections.push({ placeholder, type, layer, length: value.length, entropy: calculateShannonEntropy(value) });
      return placeholder;
    };

    const blocklist = new Set([...this.customBlocklist, ...(options.customBlocklist || [])]);
    for (const term of blocklist) {
      if (typeof term !== 'string' || !term) continue;
      text = text.replace(new RegExp(escapeRegex(term), 'gi'), (match) => add(match, 'CUSTOM_BLOCK', 3));
    }

    for (const [type, regex] of RULES) {
      text = text.replace(regex, (...args) => {
        const match = args[0];
        if (type === 'BEARER_TOKEN') {
          const token = args[1];
          return match.replace(token, add(token, type, 2));
        }
        if (type === 'IPV6' && isAllowlistedLoopback(match)) return match;
        if (type === 'CREDIT_CARD' && !isValidLuhn(match)) return match;
        if (type === 'IPV4' && isAllowlistedLoopback(match)) return match;
        if (type === 'PHONE') {
          const digits = match.replace(/\D/g, '');
          if (digits.length < 10 || digits.length > 15 || isValidLuhn(digits)) return match;
        }
        return add(match, type, 1);
      });
    }

    text = text.replace(SECRET_ASSIGNMENT, (full, prefix, value, suffix) => {
      if (/^(?:true|false|null|undefined|none|localhost|development|production|staging)$/i.test(value) || /^\[[A-Z0-9_]+(?:_R\d+)?_\d+\]$/.test(value)) return full;
      return `${prefix}${add(value, 'ENV_SECRET', 2)}${suffix}`;
    });

    text = text.replace(/\b[A-Za-z0-9_+/-]{24,128}={0,2}\b/g, (token) => {
      if (/^\[[A-Z0-9_]+(?:_R\d+)?_\d+\]$/.test(token) || this.isAllowlisted(token)) return token;
      const classes = Number(/[A-Z]/.test(token)) + Number(/[a-z]/.test(token)) + Number(/\d/.test(token));
      const hex = /^[a-f\d]{32,128}$/i.test(token);
      if (classes < 3 && !hex) return token;
      const entropy = calculateShannonEntropy(token);
      return entropy >= this.entropyThreshold ? add(token, 'HIGH_ENTROPY_SECRET', 2) : token;
    });

    if (options.enableContextualNer !== false) {
      const personPattern = /\b(?:Patient|Client|Customer|Employee|User|Caller|Engineer|Dr\.|Mr\.|Mrs\.|Ms\.)\s+([A-Z][a-z]{2,20}(?:\s+[A-Z][a-z]{2,20})?)\b/g;
      text = text.replace(personPattern, (full, person) => this.isAllowlisted(person) ? full : full.replace(person, add(person, 'PERSON', 4)));
    }

    return { scrubbedText: text, vaultMap, reverseMap, detections, stats: { totalRedacted: detections.length, byLayer, byType } };
  }

  async scrubAsync(text, options = {}) {
    const result = this.scrub(text, options);
    if (!this.slmNerDetector) return result;
    try {
      const entities = await this.slmNerDetector(result.scrubbedText);
      if (!Array.isArray(entities)) return result;
      for (const entity of entities) {
        const value = typeof entity === 'string' ? entity : entity?.text;
        if (typeof value !== 'string' || value.length < 2 || this.isAllowlisted(value) || result.scrubbedText.indexOf(value) < 0) continue;
        const type = String(typeof entity === 'string' ? 'ENTITY' : entity?.type || 'ENTITY').toUpperCase().replace(/[^A-Z0-9_]/g, '_');
        const placeholder = `[${type}_R${this.runCounter}_${Object.keys(result.vaultMap).length + 1}]`;
        result.vaultMap[placeholder] = value;
        result.reverseMap[value] = placeholder;
        result.scrubbedText = result.scrubbedText.split(value).join(placeholder);
        result.stats.totalRedacted++;
        result.stats.byLayer[4]++;
        result.stats.byType[type] = (result.stats.byType[type] || 0) + 1;
        result.detections.push({ placeholder, type, layer: 4, length: value.length, entropy: calculateShannonEntropy(value) });
      }
    } catch { /* Preserve deterministic result if the optional detector fails. */ }
    return result;
  }

  rehydrate(text, vaultMap) { return rehydrateText(text, vaultMap); }
}

export function rehydrateText(text, vaultMap = {}) {
  if (typeof text !== 'string' || !vaultMap || typeof vaultMap !== 'object') return typeof text === 'string' ? text : '';
  let output = text;
  const lookup = new Map();
  for (const [placeholder, value] of Object.entries(vaultMap)) {
    if (typeof value !== 'string') continue;
    output = output.split(placeholder).join(value);
    const canonical = placeholder.replace(/^[\[\{<(]+|[\]\})>]+$/g, '').trim().toUpperCase().replace(/[\s-]+/g, '_');
    if (canonical) lookup.set(canonical, value);
  }
  const fuzzy = /(?:\{\{|\[\[|\{|\[|<|\()\s*([A-Za-z][A-Za-z0-9_\s-]*?[_\s-]\d+)\s*(?:\}\}|\]\]|\}|\]|>|\))/g;
  return output.replace(fuzzy, (whole, inner) => {
    const key = inner.trim().toUpperCase().replace(/[\s-]+/g, '_');
    return lookup.get(key) || whole;
  });
}

export function scrubText(text, options = {}) { return new PIIEngine(options).scrub(text, options); }
