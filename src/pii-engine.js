/**
 * LocalVault AI v2.0 — 4-Layer Hybrid PII & Secret Firewall (src/pii-engine.js)
 * Layer 1: Deterministic structural detection (SSH/PEM keys, DB URIs, API keys, Luhn credit cards, SSNs, IBAN/crypto, emails, phones, IPv4/IPv6)
 * Layer 2: Shannon Information Entropy (H(X) = -sum P(x) log2 P(x)) & AST Key-Value Scanner (.env, JSON, YAML, code secrets)
 * Layer 3: Developer loopback allowlist (127.0.0.1, localhost, 0.0.0.0, ::1) + custom blocklist terms
 * Layer 4: In-browser WebGPU SLM contextual Named Entity Recognition (NER) hook
 * Fuzzy-Resilient Re-Hydration: rehydrateText() restores original secrets even if LLMs mutate placeholder casing/brackets
 */

export const LOOPBACK_ALLOWLIST = new Set([
  '127.0.0.1',
  '0.0.0.0',
  'localhost',
  '::1',
  '0:0:0:0:0:0:0:1',
  'example.com',
  'test@example.com',
  'user@example.com'
]);

/**
 * Compute Shannon Information Entropy in bits per character:
 * H(X) = -sum P(x) * log2(P(x))
 * @param {string} str
 * @returns {number}
 */
export function calculateShannonEntropy(str) {
  if (!str || typeof str !== 'string' || str.length === 0) {
    return 0;
  }
  const freq = new Map();
  const len = str.length;
  for (let i = 0; i < len; i++) {
    const ch = str[i];
    freq.set(ch, (freq.get(ch) || 0) + 1);
  }
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(4));
}

/**
 * Validate payment card numbers via the ISO/IEC 7812 Luhn check-digit algorithm.
 * @param {string} rawDigits
 * @returns {boolean}
 */
export function isValidLuhn(rawDigits) {
  if (!rawDigits || typeof rawDigits !== 'string') return false;
  const digits = rawDigits.replace(/[\s-]/g, '');
  if (!/^\d{13,19}$/.test(digits)) return false;
  // Reject trivial all-same digit strings like 0000000000000000
  if (/^(\d)\1+$/.test(digits)) return false;

  let sum = 0;
  let shouldDouble = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let digit = digits.charCodeAt(i) - 48;
    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    shouldDouble = !shouldDouble;
  }
  return sum % 10 === 0;
}

/**
 * Check if a token or IP address is a safe developer loopback/local address.
 * @param {string} value
 * @returns {boolean}
 */
export function isAllowlistedLoopback(value) {
  if (!value || typeof value !== 'string') return false;
  const trimmed = value.trim().toLowerCase();
  if (LOOPBACK_ALLOWLIST.has(trimmed)) return true;
  if (trimmed.startsWith('127.')) return true;
  if (trimmed === '::ffff:127.0.0.1') return true;
  return false;
}

const LAYER1_PATTERNS = [
  {
    type: 'PRIVATE_KEY',
    layer: 1,
    regex: /-----BEGIN (?:RSA |OPENSSH |EC |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |OPENSSH |EC |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----/g
  },
  {
    type: 'DB_URI',
    layer: 1,
    regex: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|amqp|cockroachdb):\/\/[^\s'"`<>]+/gi
  },
  {
    type: 'OPENAI_KEY',
    layer: 1,
    regex: /\bsk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{20,}\b/g
  },
  {
    type: 'ANTHROPIC_KEY',
    layer: 1,
    regex: /\bsk-ant-(?:api03-)?[A-Za-z0-9_-]{20,}\b/g
  },
  {
    type: 'GITHUB_TOKEN',
    layer: 1,
    regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,255}\b|\bgithub_pat_[A-Za-z0-9_]{30,255}\b/g
  },
  {
    type: 'AWS_KEY',
    layer: 1,
    regex: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g
  },
  {
    type: 'STRIPE_KEY',
    layer: 1,
    regex: /\b(?:sk|rk|pk)_(?:live|test)_[0-9a-zA-Z]{16,}\b/g
  },
  {
    type: 'SLACK_TOKEN',
    layer: 1,
    regex: /\bxox[baprs]-[0-9A-Za-z-]{16,}\b/g
  },
  {
    type: 'GOOGLE_API_KEY',
    layer: 1,
    regex: /\bAIza[0-9A-Za-z_-]{35}\b/g
  },
  {
    type: 'JWT_TOKEN',
    layer: 1,
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g
  },
  {
    type: 'BEARER_TOKEN',
    layer: 2,
    regex: /Authorization\s*:\s*Bearer\s+([A-Za-z0-9._~+\/-]{12,}=*)/gi,
    groupIndex: 1
  },
  {
    type: 'CRYPTO_WALLET',
    layer: 1,
    regex: /\b(?:0x[a-fA-F0-9]{40}|(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39})\b/g
  },
  {
    type: 'IBAN',
    layer: 1,
    regex: /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/g
  },
  {
    type: 'CREDIT_CARD',
    layer: 1,
    regex: /\b(?:\d[ -]*?){13,19}\b/g,
    validator: (match) => isValidLuhn(match)
  },
  {
    type: 'SSN',
    layer: 1,
    regex: /\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g
  },
  {
    type: 'EMAIL',
    layer: 1,
    regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    validator: (match) => !isAllowlistedLoopback(match)
  },
  {
    type: 'IPV4',
    layer: 1,
    regex: /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g,
    validator: (match) => !isAllowlistedLoopback(match)
  },
  {
    type: 'IPV6',
    layer: 1,
    regex: /\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b/g,
    validator: (match) => !isAllowlistedLoopback(match)
  },
  {
    type: 'PHONE',
    layer: 1,
    regex: /(?:\+?\d{1,3}[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]\d{3}[\s.-]\d{4}\b/g,
    validator: (match) => {
      const digits = match.replace(/\D/g, '');
      return digits.length >= 10 && digits.length <= 15 && !isValidLuhn(digits);
    }
  }
];

/**
 * Layer 2: AST / Key-Value & High-Entropy Secret Scanner for .env, JSON, YAML, and JS/TS/Python assignments.
 * Detects assignments to keys like PASSWORD, SECRET, TOKEN, API_KEY, PRIVATE_KEY, PASSWD, CREDENTIAL, AUTH
 * as well as standalone high-entropy hex/base64 secret tokens.
 */
const SECRET_KEY_ASSIGNMENT_REGEX =
  /(\b(?:[A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|API_KEY|APIKEY|ACCESS_KEY|CLIENT_SECRET|PRIVATE_KEY|AUTH_TOKEN|ACCESS_TOKEN|REFRESH_TOKEN|BEARER_TOKEN|WEBHOOK_SECRET|ENCRYPTION_KEY|SIGNING_KEY|MASTER_KEY|TOKEN)[A-Z0-9_]*|password|passwd|secret|apiKey|api_key|clientSecret|client_secret|accessToken|access_token|privateKey|private_key|authToken)\b\s*(?:[:=])\s*['"`]?)(?!\[REDACTED_|\{\{REDACTED_)([^'"`\s,;\n\r}{\]\[]+)(['"`]?)/g;

export class PIIEngine {
  /**
   * @param {object} options
   * @param {string[]} [options.customBlocklist]
   * @param {string[]} [options.customAllowlist]
   * @param {number} [options.entropyThreshold]
   * @param {Function} [options.slmNerDetector] - Optional Layer 4 async WebGPU SLM NER callback
   */
  constructor(options = {}) {
    this.customBlocklist = new Set(
      (options.customBlocklist || []).map((t) => t.trim()).filter(Boolean)
    );
    this.customAllowlist = new Set([
      ...LOOPBACK_ALLOWLIST,
      ...(options.customAllowlist || []).map((t) => t.trim().toLowerCase()).filter(Boolean)
    ]);
    this.entropyThreshold = options.entropyThreshold ?? 3.65;
    this.slmNerDetector = options.slmNerDetector || null;
  }

  addBlocklistTerm(term) {
    if (term && typeof term === 'string' && term.trim()) {
      this.customBlocklist.add(term.trim());
    }
  }

  removeBlocklistTerm(term) {
    if (term && typeof term === 'string') {
      this.customBlocklist.delete(term.trim());
    }
  }

  isAllowlisted(value) {
    if (!value) return false;
    const lower = value.trim().toLowerCase();
    if (this.customAllowlist.has(lower)) return true;
    return isAllowlistedLoopback(lower);
  }

  /**
   * Run synchronous 4-layer PII & secret scrubbing (Layers 1–3 + heuristic NER fallback for Layer 4).
   * @param {string} inputText
   * @param {object} [opts]
   * @returns {{ scrubbedText: string, vaultMap: Record<string, string>, reverseMap: Record<string, string>, detections: Array<object>, stats: object }}
   */
  scrub(inputText, opts = {}) {
    if (typeof inputText !== 'string' || inputText.length === 0) {
      return {
        scrubbedText: inputText || '',
        vaultMap: {},
        reverseMap: {},
        detections: [],
        stats: { totalRedacted: 0, byLayer: { 1: 0, 2: 0, 3: 0, 4: 0 }, byType: {} }
      };
    }

    let workingText = inputText;
    const vaultMap = {};
    const reverseMap = {};
    const detections = [];
    const counters = {};
    const byLayer = { 1: 0, 2: 0, 3: 0, 4: 0 };
    const byType = {};

    const registerSecret = (rawValue, type, layer, entropy = null) => {
      const cleanVal = rawValue.trim();
      if (!cleanVal || this.isAllowlisted(cleanVal)) {
        return rawValue;
      }
      if (/^\[[A-Z0-9_]+_\d+\]$/.test(cleanVal)) {
        return rawValue;
      }
      if (reverseMap[cleanVal]) {
        return reverseMap[cleanVal];
      }
      counters[type] = (counters[type] || 0) + 1;
      const placeholder = `[${type}_${counters[type]}]`;
      vaultMap[placeholder] = cleanVal;
      reverseMap[cleanVal] = placeholder;
      byLayer[layer] = (byLayer[layer] || 0) + 1;
      byType[type] = (byType[type] || 0) + 1;
      detections.push({
        placeholder,
        type,
        layer,
        length: cleanVal.length,
        entropy: entropy ?? calculateShannonEntropy(cleanVal),
        preview:
          cleanVal.length > 8
            ? `${cleanVal.slice(0, 3)}***${cleanVal.slice(-2)}`
            : '***'
      });
      return placeholder;
    };

    // Layer 3A: Custom Blocklist Terms (highest user priority)
    const blocklistArray = [
      ...this.customBlocklist,
      ...((opts.customBlocklist || []).map((t) => t.trim()).filter(Boolean))
    ];
    for (const term of blocklistArray) {
      if (!term) continue;
      const escaped = term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const re = new RegExp(escaped, 'gi');
      workingText = workingText.replace(re, (match) =>
        registerSecret(match, 'CUSTOM_BLOCK', 3)
      );
    }

    // Layer 1: Deterministic structural patterns
    for (const rule of LAYER1_PATTERNS) {
      workingText = workingText.replace(rule.regex, (...args) => {
        const fullMatch = args[0];
        if (rule.groupIndex) {
          const groupVal = args[rule.groupIndex];
          if (!groupVal || this.isAllowlisted(groupVal)) return fullMatch;
          const ph = registerSecret(groupVal, rule.type, rule.layer);
          return fullMatch.replace(groupVal, ph);
        }
        if (rule.validator && !rule.validator(fullMatch)) {
          return fullMatch;
        }
        if (this.isAllowlisted(fullMatch)) {
          return fullMatch;
        }
        return registerSecret(fullMatch, rule.type, rule.layer);
      });
    }

    // Layer 2A: AST / Key-Value Secret Scanner (.env, JSON, YAML, code configs)
    workingText = workingText.replace(
      SECRET_KEY_ASSIGNMENT_REGEX,
      (fullMatch, prefix, value, suffix) => {
        if (!value || value.length < 4) return fullMatch;
        if (
          /^(?:true|false|null|undefined|none|localhost|development|production|staging)$/i.test(
            value
          )
        ) {
          return fullMatch;
        }
        if (/^\[[A-Z0-9_]+_\d+\]$/.test(value)) {
          return fullMatch;
        }
        const ent = calculateShannonEntropy(value);
        const placeholder = registerSecret(value, 'ENV_SECRET', 2, ent);
        return `${prefix}${placeholder}${suffix}`;
      }
    );

    // Layer 2B: Standalone High-Entropy Secret Scanner (unlabeled API keys / hex / base64 secrets)
    const highEntropyTokenRegex = /\b[A-Za-z0-9_+\/-]{24,128}={0,2}\b/g;
    workingText = workingText.replace(highEntropyTokenRegex, (token) => {
      if (/^\[[A-Z0-9_]+_\d+\]$/.test(token)) return token;
      if (this.isAllowlisted(token)) return token;
      // Avoid scrubbing plain English camelCase / path words without mixed char classes
      const hasUpper = /[A-Z]/.test(token);
      const hasLower = /[a-z]/.test(token);
      const hasDigit = /\d/.test(token);
      const isHex = /^[a-fA-F0-9]{32,128}$/.test(token);
      const classCount = (hasUpper ? 1 : 0) + (hasLower ? 1 : 0) + (hasDigit ? 1 : 0);
      if (classCount < 3 && !isHex) return token;

      const entropy = calculateShannonEntropy(token);
      if (entropy >= this.entropyThreshold) {
        return registerSecret(token, 'HIGH_ENTROPY_SECRET', 2, entropy);
      }
      return token;
    });

    // Layer 4 (Contextual Named Entity Recognition heuristic & custom entity patterns)
    if (opts.enableContextualNer !== false) {
      const contextualPersonRegex =
        /\b(?:Patient|Client|Customer|Employee|User|Caller|Suspect|Applicant|Commander|Engineer|Dr\.|Mr\.|Mrs\.|Ms\.)\s+([A-Z][a-z]{2,20}(?:\s+[A-Z][a-z]{2,20})?)\b/g;
      workingText = workingText.replace(contextualPersonRegex, (fullMatch, personName) => {
        if (this.isAllowlisted(personName)) return fullMatch;
        const ph = registerSecret(personName, 'PERSON', 4);
        return fullMatch.replace(personName, ph);
      });
    }

    return {
      scrubbedText: workingText,
      vaultMap,
      reverseMap,
      detections,
      stats: {
        totalRedacted: detections.length,
        byLayer,
        byType
      }
    };
  }

  /**
   * Async 4-Layer Scrubbing including WebGPU SLM NER (Layer 4) when an SLM worker/detector is attached.
   * @param {string} inputText
   * @param {object} [opts]
   */
  async scrubAsync(inputText, opts = {}) {
    const baseResult = this.scrub(inputText, opts);
    if (typeof this.slmNerDetector === 'function') {
      try {
        const entities = await this.slmNerDetector(baseResult.scrubbedText);
        if (Array.isArray(entities) && entities.length > 0) {
          let text = baseResult.scrubbedText;
          for (const entity of entities) {
            const val = typeof entity === 'string' ? entity : entity?.text;
            const label = (entity?.type || 'ENTITY').toUpperCase().replace(/[^A-Z0-9_]/g, '_');
            if (!val || val.length < 2 || this.isAllowlisted(val)) continue;
            if (baseResult.reverseMap[val]) continue;
            const idx = Object.keys(baseResult.vaultMap).length + 1;
            const placeholder = `[${label}_${idx}]`;
            baseResult.vaultMap[placeholder] = val;
            baseResult.reverseMap[val] = placeholder;
            baseResult.stats.byLayer[4] = (baseResult.stats.byLayer[4] || 0) + 1;
            baseResult.stats.byType[label] = (baseResult.stats.byType[label] || 0) + 1;
            baseResult.stats.totalRedacted += 1;
            baseResult.detections.push({
              placeholder,
              type: label,
              layer: 4,
              length: val.length,
              entropy: calculateShannonEntropy(val),
              preview: `${val.slice(0, 2)}***`
            });
            text = text.split(val).join(placeholder);
          }
          baseResult.scrubbedText = text;
        }
      } catch {
        // Fallback gracefully to synchronous 4-layer output if WebGPU SLM is offline
      }
    }
    return baseResult;
  }

  /**
   * Fuzzy-Resilient Re-Hydration: restores placeholders even if an LLM mutates casing,
   * brackets, or separators (e.g. [EMAIL_1] -> [email_1], {{EMAIL_1}}, <email-1>, (EMAIL 1)).
   * @param {string} text
   * @param {Record<string, string>} vaultMap
   * @returns {string}
   */
  rehydrate(text, vaultMap) {
    return rehydrateText(text, vaultMap);
  }
}

/**
 * Standalone Fuzzy-Resilient Re-Hydration helper.
 * Restores original secrets from vaultMap even when LLMs mutate brackets, casing, or delimiters:
 * e.g. [EMAIL_1] -> [email_1], {{EMAIL_1}}, {{email-1}}, <EMAIL_1>, (email_1), $EMAIL_1
 * @param {string} mutatedText
 * @param {Record<string, string>} vaultMap
 * @returns {string}
 */
export function rehydrateText(mutatedText, vaultMap = {}) {
  if (typeof mutatedText !== 'string' || !vaultMap || typeof vaultMap !== 'object') {
    return mutatedText || '';
  }

  let output = mutatedText;
  const entries = Object.entries(vaultMap);
  if (entries.length === 0) return output;

  // Build canonical lookup map keyed by normalized TYPE + ID (e.g., "EMAIL_1")
  const normalizedLookup = new Map();

  for (const [rawKey, secretValue] of entries) {
    // Direct exact match replacement first
    if (output.includes(rawKey)) {
      output = output.split(rawKey).join(secretValue);
    }
    const core = rawKey
      .replace(/^[\[\{\(<$]+|[\]\}\)>]+$/g, '')
      .trim()
      .toUpperCase()
      .replace(/[\s-]+/g, '_');

    if (core) {
      normalizedLookup.set(core, secretValue);
    }
  }

  // Match any bracketed/braced/angled/parenthesized or token-style mutated placeholder:
  // Supports [email_1], {{EMAIL_1}}, {[email-1]}, <email_1>, (EMAIL 1), etc.
  const fuzzyPlaceholderRegex =
    /(?:\{\{|\[\[|\{|\[|<|\()\s*([A-Za-z][A-Za-z0-9_\s-]*?[\s_-]\d+)\s*(?:\}\}|\]\]|\}|\]|>|\))/g;

  output = output.replace(fuzzyPlaceholderRegex, (fullMatch, innerToken) => {
    const canonical = innerToken
      .trim()
      .toUpperCase()
      .replace(/[\s-]+/g, '_');
    if (normalizedLookup.has(canonical)) {
      return normalizedLookup.get(canonical);
    }
    return fullMatch;
  });

  return output;
}

export function scrubText(text, options = {}) {
  const engine = new PIIEngine(options);
  return engine.scrub(text, options);
}
