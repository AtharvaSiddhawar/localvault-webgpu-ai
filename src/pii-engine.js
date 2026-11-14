/**
 * LocalVault AI v2.0 — 4-Layer Hybrid PII & Secret Firewall
 */

export const PII_CATEGORIES = {
  PRIVATE_KEY: { label: 'SSH / PEM Private Key', prefix: 'PRIV_KEY', severity: 35, defaultEnabled: true },
  CONN_URI: { label: 'DB / Cloud Connection URI', prefix: 'CONN_URI', severity: 30, defaultEnabled: true },
  API_KEY: { label: 'API Key / Cloud Secret', prefix: 'SECRET', severity: 25, defaultEnabled: true },
  HIGH_ENTROPY: { label: 'High-Entropy Password/Secret', prefix: 'ENTROPY_SEC', severity: 22, defaultEnabled: true },
  CREDIT_CARD: { label: 'Credit Card (Luhn)', prefix: 'CARD', severity: 25, defaultEnabled: true },
  SSN_ID: { label: 'SSN / Government ID', prefix: 'GOV_ID', severity: 25, defaultEnabled: true },
  FINANCIAL: { label: 'IBAN / Crypto Wallet', prefix: 'FIN_ACCT', severity: 20, defaultEnabled: true },
  EMAIL: { label: 'Email Address', prefix: 'EMAIL', severity: 10, defaultEnabled: true },
  PHONE: { label: 'Phone Number', prefix: 'PHONE', severity: 10, defaultEnabled: true },
  IP_ADDRESS: { label: 'IP Address (IPv4/IPv6)', prefix: 'IP_ADDR', severity: 8, defaultEnabled: true },
  PERSON: { label: 'Person / Client Name', prefix: 'PERSON', severity: 8, defaultEnabled: true },
  CUSTOM: { label: 'Custom Blocklist Entity', prefix: 'CUSTOM', severity: 15, defaultEnabled: true }
};

const LOOPBACK_ALLOWLIST = new Set([
  '127.0.0.1',
  '0.0.0.0',
  'localhost',
  '::1',
  '255.255.255.255',
  '255.255.255.0'
]);

export function calculateShannonEntropy(str) {
  if (!str || typeof str !== 'string' || str.length === 0) return 0;
  const len = str.length;
  const freq = {};
  for (let i = 0; i < len; i++) {
    const ch = str[i];
    freq[ch] = (freq[ch] || 0) + 1;
  }
  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(3));
}

export function isValidLuhn(rawNumber) {
  const digits = String(rawNumber || '').replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  if (/^(\d)\1+$/.test(digits)) return false;
  let sum = 0;
  let shouldDouble = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let digit = parseInt(digits.charAt(i), 10);
    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    shouldDouble = !shouldDouble;
  }
  return sum % 10 === 0;
}

const DETERMINISTIC_RULES = [
  {
    category: 'PRIVATE_KEY',
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----/g
  },
  {
    category: 'CONN_URI',
    regex: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis(?:s)?|amqp(?:s)?):\/\/[^\s"'<>]+/gi
  },
  {
    category: 'API_KEY',
    regex: /\b(?:sk-ant-[a-zA-Z0-9_-]{20,}|sk-[a-zA-Z0-9_-]{20,}|AIza[0-9A-Za-z_-]{35}|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{22,}|AKIA[0-9A-Z]{16}|hf_[a-zA-Z0-9]{24,}|npm_[a-zA-Z0-9]{24,}|xox[baprs]-[0-9a-zA-Z-]{10,}|(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{16,}|eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g
  },
  {
    category: 'EMAIL',
    regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g
  },
  {
    category: 'CREDIT_CARD',
    regex: /\b(?:\d[ -]*?){13,19}\b/g,
    validate: (match) => isValidLuhn(match)
  },
  {
    category: 'SSN_ID',
    regex: /\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g
  },
  {
    category: 'FINANCIAL',
    regex: /\b(?:[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16}|0x[a-fA-F0-9]{40}|(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39})\b/g
  },
  {
    category: 'IP_ADDRESS',
    regex: /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b|(?:\b(?:[A-Fa-f0-9]{1,4}:){3,7}[A-Fa-f0-9]{1,4}\b)/g,
    validate: (match, options) => {
      if (options.preserveLocalhost !== false && LOOPBACK_ALLOWLIST.has(match.toLowerCase())) {
        return false;
      }
      return true;
    }
  },
  {
    category: 'PHONE',
    regex: /(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b/g,
    validate: (match) => {
      const digits = match.replace(/\D/g, '');
      return digits.length >= 10 && digits.length <= 15;
    }
  },
  {
    category: 'PERSON',
    regex: /(?:\b(?:Mr|Mrs|Ms|Dr|Prof)\.?\s+[A-Z][a-z]{1,20}(?:\s+[A-Z][a-z]{1,20}){1,2}\b)|(?:(?<=\b(?:Patient|Client|Customer|Employee|Candidate|Contact|Author|Manager|Reported by|Assigned to|User|Owner):\s*)[A-Z][a-z]{1,20}(?:\s+[A-Z][a-z]{1,20}){1,2}\b)/g
  }
];

const KEY_VALUE_SECRET_REGEX =
  /(\b(?:[A-Z0-9_]*(?:PASSWORD|PASSWD|PWD|SECRET|API_KEY|APIKEY|ACCESS_KEY|PRIVATE_KEY|AUTH_TOKEN|ACCESS_TOKEN|CLIENT_SECRET|WEBHOOK_SECRET|ENCRYPTION_KEY|MASTER_KEY)[A-Z0-9_]*|Authorization)\s*(?:[:=])\s*(?:Bearer\s+)?["']?)([^"'\s,;\n\r}{\]]{6,})(["']?)/gi;

export function computePrivacyRisk(byCategory = {}) {
  let rawScore = 0;
  for (const [cat, count] of Object.entries(byCategory)) {
    const weight = PII_CATEGORIES[cat]?.severity || 10;
    rawScore += weight * count;
  }
  const score = Math.min(100, rawScore);
  let level = 'SAFE';
  if (score >= 70) level = 'CRITICAL';
  else if (score >= 40) level = 'HIGH';
  else if (score >= 15) level = 'MODERATE';
  else if (score > 0) level = 'LOW';

  return { score, level };
}

export function scrubText(rawText, options = {}) {
  if (!rawText || typeof rawText !== 'string') {
    return {
      scrubbedText: '',
      entities: [],
      tokenToOriginal: {},
      stats: {
        totalRedactions: 0,
        uniqueEntities: 0,
        byCategory: {},
        risk: { score: 0, level: 'SAFE' }
      }
    };
  }

  const enabledCategories = options.enabledCategories || Object.fromEntries(
    Object.entries(PII_CATEGORIES).map(([k, v]) => [k, v.defaultEnabled])
  );
  const redactionStyle = options.redactionStyle || 'token';
  const preserveLocalhost = options.preserveLocalhost !== false;
  const extraEntities = Array.isArray(options.extraEntities) ? options.extraEntities : [];
  const customTerms = Array.isArray(options.customTerms) ? options.customTerms : [];

  const categoryCounters = {};
  const originalToEntity = new Map();
  const tokenToOriginal = {};
  const byCategory = {};
  let totalRedactions = 0;

  function getOrCreateEntity(originalValue, category) {
    const trimmed = originalValue.trim();
    const key = `${category}:::${trimmed}`;
    if (originalToEntity.has(key)) {
      const existing = originalToEntity.get(key);
      existing.count += 1;
      totalRedactions += 1;
      byCategory[category] = (byCategory[category] || 0) + 1;
      return existing.token;
    }

    const prefix = PII_CATEGORIES[category]?.prefix || category;
    categoryCounters[prefix] = (categoryCounters[prefix] || 0) + 1;
    const token = redactionStyle === 'mask'
      ? `[REDACTED_${prefix}]`
      : `[${prefix}_${categoryCounters[prefix]}]`;

    const entropy = calculateShannonEntropy(trimmed);
    const entityObj = {
      token,
      original: trimmed,
      category,
      entropy,
      count: 1
    };
    originalToEntity.set(key, entityObj);
    tokenToOriginal[token] = trimmed;
    totalRedactions += 1;
    byCategory[category] = (byCategory[category] || 0) + 1;
    return token;
  }

  let workingText = rawText;

  for (const rule of DETERMINISTIC_RULES) {
    if (!enabledCategories[rule.category]) continue;

    workingText = workingText.replace(rule.regex, (match) => {
      if (match.startsWith('[') && match.endsWith(']')) return match;
      if (rule.validate && !rule.validate(match, { preserveLocalhost })) return match;
      return getOrCreateEntity(match, rule.category);
    });
  }

  if (enabledCategories.HIGH_ENTROPY !== false) {
    workingText = workingText.replace(
      KEY_VALUE_SECRET_REGEX,
      (fullMatch, prefixGroup, secretValue, suffixQuote) => {
        if (
          secretValue.startsWith('[') ||
          /^(?:true|false|null|undefined|none|changeme|your_api_key_here)$/i.test(secretValue)
        ) {
          return fullMatch;
        }
        const token = getOrCreateEntity(secretValue, 'HIGH_ENTROPY');
        return `${prefixGroup}${token}${suffixQuote}`;
      }
    );
  }

  const mergedExtras = [
    ...customTerms.map((t) => ({ text: t, category: 'CUSTOM' })),
    ...extraEntities
  ]
    .filter((e) => e && typeof e.text === 'string' && e.text.trim().length >= 2)
    .sort((a, b) => b.text.length - a.text.length);

  for (const item of mergedExtras) {
    const category = PII_CATEGORIES[item.category] ? item.category : 'CUSTOM';
    if (enabledCategories[category] === false) continue;
    const escaped = item.text.trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const reg = new RegExp(`\\b${escaped}\\b`, 'gi');
    workingText = workingText.replace(reg, (match) => getOrCreateEntity(match, category));
  }

  const entities = Array.from(originalToEntity.values());
  const risk = computePrivacyRisk(byCategory);

  return {
    scrubbedText: workingText,
    entities,
    tokenToOriginal,
    stats: {
      totalRedactions,
      uniqueEntities: entities.length,
      byCategory,
      risk
    }
  };
}

export function rehydrateText(anonymizedText, tokenToOriginal = {}) {
  if (!anonymizedText || typeof anonymizedText !== 'string') return '';
  let output = anonymizedText;
  const tokens = Object.keys(tokenToOriginal).sort((a, b) => b.length - a.length);

  for (const token of tokens) {
    const originalValue = tokenToOriginal[token];
    const core = token.replace(/^\[|\]$/g, '');
    const parts = core.split('_');
    const idNum = parts.pop();
    const prefixPart = parts.join('[_\-]');

    const fuzzyPattern = new RegExp(
      `(?:\[+|\{\{+|\<+)?\b${prefixPart}[_\-]${idNum}\b(?:\]+|\}\}+|\>+)?`,
      'gi'
    );
    output = output.replace(fuzzyPattern, () => originalValue);
  }
  return output;
}

export function buildContextualPiiPrompt(scrubbedPreview) {
  return [
    {
      role: 'system',
      content:
        'You are a strict privacy entity extractor. Identify any remaining person names, physical street addresses, or private organization codenames in the text. Reply ONLY with a JSON array of objects like [{"text":"Jane Doe","category":"PERSON"}]. If none exist, reply [].'
    },
    {
      role: 'user',
      content: `Extract remaining private entities from this text as JSON:\n\n${scrubbedPreview.slice(0, 1600)}`
    }
  ];
}

export function parseLlmEntityResponse(rawLlmText) {
  if (!rawLlmText || typeof rawLlmText !== 'string') return [];
  try {
    const match = rawLlmText.match(/\[[\s\S]*\]/);
    if (!match) return [];
    const parsed = JSON.parse(match[0]);
    if (!Array.isArray(parsed)) return [];
    return parsed
      .filter((item) => item && typeof item.text === 'string' && item.text.trim().length > 1)
      .map((item) => ({
        text: item.text.trim(),
        category: PII_CATEGORIES[item.category] ? item.category : 'PERSON'
      }));
  } catch {
    return [];
  }
    }
                                        
