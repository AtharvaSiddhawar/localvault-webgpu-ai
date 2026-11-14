
/**
 * LocalVault AI v2.0 — PII and Secret Scrubber
 *
 * Detects common credentials, private keys, personal identifiers,
 * high-entropy tokens and contextual person names.
 *
 * Important: This is a heuristic client-side scrubber, not a guarantee
 * that every sensitive value will be detected.
 */

export const LOOPBACK_ALLOWLIST = new Set([
  '127.0.0.1',
  '0.0.0.0',
  'localhost',
  '::1',
  '0:0:0:0:0:0:0:1'
]);

export function calculateShannonEntropy(str) {
  if (typeof str !== 'string' || !str.length) return 0;

  const counts = new Map();
  for (const char of str) {
    counts.set(char, (counts.get(char) || 0) + 1);
  }

  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / str.length;
    entropy -= probability * Math.log2(probability);
  }

  return Number(entropy.toFixed(4));
}

export function isValidLuhn(rawDigits) {
  if (typeof rawDigits !== 'string') return false;

  const digits = rawDigits.replace(/[\s-]/g, '');
  if (!/^\d{13,19}$/.test(digits)) return false;
  if (/^(\d)\1+$/.test(digits)) return false;

  let sum = 0;
  let doubleDigit = false;

  for (let i = digits.length - 1; i >= 0; i--) {
    let digit = Number(digits[i]);

    if (doubleDigit) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }

    sum += digit;
    doubleDigit = !doubleDigit;
  }

  return sum % 10 === 0;
}

/**
 * Recognizes actual IPv4 loopback addresses, IPv6 loopback addresses,
 * and the explicitly retained local development aliases.
 */
export function isAllowlistedLoopback(value) {
  if (typeof value !== 'string' || !value.trim()) return false;

  const address = value.trim().toLowerCase();

  if (LOOPBACK_ALLOWLIST.has(address)) return true;
  if (address === '::ffff:127.0.0.1') return true;

  if (address.startsWith('127.')) {
    const parts = address.split('.');
    return parts.length === 4 && parts.every(
      part => /^\d{1,3}$/.test(part) && Number(part) <= 255
    );
  }

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
    validator: isValidLuhn
  },
  {
    type: 'SSN',
    layer: 1,
    regex: /\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g
  },
  {
    type: 'EMAIL',
    layer: 1,
    regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g
  },
  {
    type: 'IPV4',
    layer: 1,
    regex: /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g,
    validator: match => !isAllowlistedLoopback(match)
  },
  {
    type: 'IPV6',
    layer: 1,
    regex: /\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b/g,
    validator: match => !isAllowlistedLoopback(match)
  },
  {
    type: 'PHONE',
    layer: 1,
    regex: /(?:\+?\d{1,3}[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]\d{3}[\s.-]\d{4}\b/g,
    validator: match => {
      const digits = match.replace(/\D/g, '');
      return digits.length >= 10 && digits.length <= 15 &&
        !isValidLuhn(digits);
    }
  }
];

const SECRET_KEY_ASSIGNMENT_REGEX =
  /(\b(?:[A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|API_KEY|APIKEY|ACCESS_KEY|CLIENT_SECRET|PRIVATE_KEY|AUTH_TOKEN|ACCESS_TOKEN|REFRESH_TOKEN|BEARER_TOKEN|WEBHOOK_SECRET|ENCRYPTION_KEY|SIGNING_KEY|MASTER_KEY|TOKEN)[A-Z0-9_]*|password|passwd|secret|apiKey|api_key|clientSecret|client_secret|accessToken|access_token|privateKey|private_key|authToken)\b\s*(?:[:=])\s*['"`]?)(?!\[REDACTED_|\{\{REDACTED_)([^'"`\s,;\n\r}{\]\[]+)(['"`]?)/g;

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function emptyResult(input = '') {
  return {
    scrubbedText: input,
    vaultMap: {},
    reverseMap: {},
    detections: [],
    stats: {
      totalRedacted: 0,
      byLayer: { 1: 0, 2: 0, 3: 0, 4: 0 },
      byType: {}
    }
  };
}

export class PIIEngine {
  constructor(options = {}) {
    this.customBlocklist = new Set(
      (options.customBlocklist || [])
        .filter(value => typeof value === 'string')
        .map(value => value.trim())
        .filter(Boolean)
    );

    this.customAllowlist = new Set(
      (options.customAllowlist || [])
        .filter(value => typeof value === 'string')
        .map(value => value.trim().toLowerCase())
        .filter(Boolean)
    );

    this.entropyThreshold = options.entropyThreshold ?? 3.65;
    this.slmNerDetector =
      typeof options.slmNerDetector === 'function'
        ? options.slmNerDetector
        : null;
  }

  addBlocklistTerm(term) {
    if (typeof term === 'string' && term.trim()) {
      this.customBlocklist.add(term.trim());
    }
  }

  removeBlocklistTerm(term) {
    if (typeof term === 'string') {
      this.customBlocklist.delete(term.trim());
    }
  }

  isAllowlisted(value) {
    if (typeof value !== 'string') return false;

    const normalized = value.trim().toLowerCase();

    return this.customAllowlist.has(normalized) ||
      isAllowlistedLoopback(normalized);
  }

  scrub(inputText, opts = {}) {
    if (typeof inputText !== 'string' || !inputText.length) {
      return emptyResult(inputText || '');
    }

    let workingText = inputText;
    const vaultMap = {};
    const reverseMap = {};
    const detections = [];
    const counters = {};
    const byLayer = { 1: 0, 2: 0, 3: 0, 4: 0 };
    const byType = {};

    const registerSecret = (rawValue, type, layer, entropy = null) => {
      const cleanValue = rawValue.trim();

      if (!cleanValue || this.isAllowlisted(cleanValue)) {
        return rawValue;
      }

      if (/^\[[A-Z0-9_]+_\d+\]$/.test(cleanValue)) {
        return rawValue;
      }

      if (Object.hasOwn(reverseMap, cleanValue)) {
        return reverseMap[cleanValue];
      }

      counters[type] = (counters[type] || 0) + 1;

      const placeholder = `[${type}_${counters[type]}]`;

      vaultMap[placeholder] = cleanValue;
      reverseMap[cleanValue] = placeholder;

      byLayer[layer] = (byLayer[layer] || 0) + 1;
      byType[type] = (byType[type] || 0) + 1;

      detections.push({
        placeholder,
        type,
        layer,
        length: cleanValue.length,
        entropy: entropy ?? calculateShannonEntropy(cleanValue),
        preview: cleanValue.length > 8
          ? `${cleanValue.slice(0, 3)}***${cleanValue.slice(-2)}`
          : '***'
      });

      return placeholder;
    };

    // Layer 3: User-defined blocklist.
    const blocklist = new Set([
      ...this.customBlocklist,
      ...(opts.customBlocklist || [])
        .filter(value => typeof value === 'string')
        .map(value => value.trim())
        .filter(Boolean)
    ]);

    for (const term of blocklist) {
      if (!term) continue;

      const regex = new RegExp(escapeRegex(term), 'gi');

      workingText = workingText.replace(regex, match =>
        registerSecret(match, 'CUSTOM_BLOCK', 3)
      );
    }

    // Layer 1: Deterministic structural detection.
    for (const rule of LAYER1_PATTERNS) {
      workingText = workingText.replace(rule.regex, (...args) => {
        const fullMatch = args[0];

        if (rule.groupIndex) {
          const groupValue = args[rule.groupIndex];

          if (!groupValue || this.isAllowlisted(groupValue)) {
            return fullMatch;
          }

          const placeholder = registerSecret(
            groupValue,
            rule.type,
            rule.layer
          );

          return fullMatch.replace(groupValue, placeholder);
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

    // Layer 2A: Secret assignments in configuration and source text.
    workingText = workingText.replace(
      SECRET_KEY_ASSIGNMENT_REGEX,
      (fullMatch, prefix, value, suffix) => {
        if (!value || value.length < 4) return fullMatch;

        if (/^(?:true|false|null|undefined|none|localhost|development|production|staging)$/i.test(value)) {
          return fullMatch;
        }

        if (/^\[[A-Z0-9_]+_\d+\]$/.test(value)) {
          return fullMatch;
        }

        const entropy = calculateShannonEntropy(value);
        const placeholder = registerSecret(
          value,
          'ENV_SECRET',
          2,
          entropy
        );

        return `${prefix}${placeholder}${suffix}`;
      }
    );

    // Layer 2B: Unlabelled high-entropy strings.
    const highEntropyTokenRegex =
      /\b[A-Za-z0-9_+\/-]{24,128}={0,2}\b/g;

    workingText = workingText.replace(
      highEntropyTokenRegex,
      token => {
        if (/^\[[A-Z0-9_]+_\d+\]$/.test(token)) return token;
        if (this.isAllowlisted(token)) return token;

        const hasUpper = /[A-Z]/.test(token);
        const hasLower = /[a-z]/.test(token);
        const hasDigit = /\d/.test(token);
        const isHex = /^[a-fA-F0-9]{32,128}$/.test(token);

        const characterClasses =
          Number(hasUpper) + Number(hasLower) + Number(hasDigit);

        if (characterClasses < 3 && !isHex) return token;

        const entropy = calculateShannonEntropy(token);

        if (entropy >= this.entropyThreshold) {
          return registerSecret(
            token,
            'HIGH_ENTROPY_SECRET',
            2,
            entropy
          );
        }

        return token;
      }
    );

    // Layer 4 fallback: Context-based person-name heuristic.
    // This is not a full named-entity recognition model.
    if (opts.enableContextualNer !== false) {
      const personRegex =
        /\b(?:Patient|Client|Customer|Employee|User|Caller|Suspect|Applicant|Commander|Engineer|Dr\.|Mr\.|Mrs\.|Ms\.)\s+([A-Z][a-z]{2,20}(?:\s+[A-Z][a-z]{2,20})?)\b/g;

      workingText = workingText.replace(
        personRegex,
        (fullMatch, personName) => {
          if (this.isAllowlisted(personName)) return fullMatch;

          const placeholder = registerSecret(
            personName,
            'PERSON',
            4
          );

          return fullMatch.replace(personName, placeholder);
        }
      );
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

  async scrubAsync(inputText, opts = {}) {
    const result = this.scrub(inputText, opts);

    if (!this.slmNerDetector) return result;

    try {
      const entities = await this.slmNerDetector(
        result.scrubbedText
      );

      if (!Array.isArray(entities)) return result;

      let text = result.scrubbedText;

      for (const entity of entities) {
        const value = typeof entity === 'string'
          ? entity
          : entity?.text;

        if (
          typeof value !== 'string' ||
          value.length < 2 ||
          this.isAllowlisted(value) ||
          Object.hasOwn(result.reverseMap, value) ||
          !text.includes(value)
        ) {
          continue;
        }

        const label = (
          typeof entity === 'string'
            ? 'ENTITY'
            : entity?.type || 'ENTITY'
        )
          .toUpperCase()
          .replace(/[^A-Z0-9_]/g, '_');

        const placeholder =
          `[${label}_${Object.keys(result.vaultMap).length + 1}]`;

        result.vaultMap[placeholder] = value;
        result.reverseMap[value] = placeholder;

        result.stats.byLayer[4]++;
        result.stats.byType[label] =
          (result.stats.byType[label] || 0) + 1;
        result.stats.totalRedacted++;

        result.detections.push({
          placeholder,
          type: label,
          layer: 4,
          length: value.length,
          entropy: calculateShannonEntropy(value),
          preview: value.length > 8
            ? `${value.slice(0, 2)}***${value.slice(-2)}`
            : '***'
        });

        // Replace occurrences without splitting or corrupting other text.
        text = text.replace(
          new RegExp(escapeRegex(value), 'g'),
          placeholder
        );
      }

      result.scrubbedText = text;
    } catch {
      // Keep the synchronous scrub result if the optional detector fails.
    }

    return result;
  }

  rehydrate(text, vaultMap) {
    return rehydrateText(text, vaultMap);
  }
}

export function rehydrateText(mutatedText, vaultMap = {}) {
  if (typeof mutatedText !== 'string') return '';
  if (!vaultMap || typeof vaultMap !== 'object') return mutatedText;

  let output = mutatedText;
  const lookup = new Map();

  for (const [rawKey, secretValue] of Object.entries(vaultMap)) {
    if (typeof secretValue !== 'string') continue;

    output = output.split(rawKey).join(secretValue);

    const canonical = rawKey
      .replace(/^[\[\{\(<$]+|[\]\}\)>]+$/g, '')
      .trim()
      .toUpperCase()
      .replace(/[\s-]+/g, '_');

    if (canonical) lookup.set(canonical, secretValue);
  }

  const fuzzyPlaceholderRegex =
    /(?:\{\{|\[\[|\{|\[|<|\()\s*([A-Za-z][A-Za-z0-9_\s-]*?[\s_-]\d+)\s*(?:\}\}|\]\]|\}|\]|>|\))/g;

  output = output.replace(
    fuzzyPlaceholderRegex,
    (fullMatch, innerToken) => {
      const canonical = innerToken
        .trim()
        .toUpperCase()
        .replace(/[\s-]+/g, '_');

      return lookup.has(canonical)
        ? lookup.get(canonical)
        : fullMatch;
    }
  );

  return output;
}

export function scrubText(text, options = {}) {
  return new PIIEngine(options).scrub(text, options);
}
