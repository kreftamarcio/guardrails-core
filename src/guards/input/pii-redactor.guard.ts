import type { BaseGuard, GuardResult } from '../base.guard.js';

export type PIIEntityType =
  | 'email' | 'phone' | 'cpf' | 'cnpj' | 'credit_card'
  | 'ip_address' | 'name' | 'address' | 'date_of_birth';

export interface PIIConfig {
  enabled: boolean;
  action: 'redact' | 'block' | 'warn';
  entities: PIIEntityType[];
  customPatterns?: Array<{ name: string; regex: RegExp; replacement?: string }>;
}

interface PIIMatch {
  type: PIIEntityType | string;
  value: string;
  start: number;
  end: number;
  replacement: string;
}

/**
 * PII Redaction Guard
 *
 * Detects and redacts Personally Identifiable Information from text.
 * Supports Brazilian document formats (CPF, CNPJ) and international patterns.
 *
 * Detection strategies:
 * 1. Regex-based pattern matching (high precision, known formats)
 * 2. Contextual heuristics (phone numbers with area codes, etc.)
 * 3. Checksum validation (CPF, CNPJ, credit cards via Luhn algorithm)
 *
 * Redaction modes:
 * - `redact`: Replace with [ENTITY_TYPE] placeholder
 * - `block`: Reject the entire input
 * - `warn`: Pass through but flag in audit log
 */
export class PIIRedactorGuard implements BaseGuard {
  readonly name = 'pii-redactor';
  private readonly config: PIIConfig;
  private readonly detectors: Map<string, PIIDetector>;

  constructor(config: PIIConfig) {
    this.config = config;
    this.detectors = this.initializeDetectors();
  }

  async check(input: string): Promise<GuardResult> {
    const matches = this.detectAll(input);

    if (matches.length === 0) {
      return { guard: this.name, action: 'pass', score: 0 };
    }

    switch (this.config.action) {
      case 'block':
        return {
          guard: this.name,
          action: 'block',
          reason: `PII detected: ${matches.map(m => m.type).join(', ')}`,
          score: 1,
          details: { entities: matches.map(m => ({ type: m.type, redacted: m.replacement })) },
        };

      case 'redact': {
        const redacted = this.redact(input, matches);
        return {
          guard: this.name,
          action: 'transform',
          transformedValue: redacted,
          score: matches.length / 10, // Normalized
          details: { entitiesRedacted: matches.length, types: [...new Set(matches.map(m => m.type))] },
        };
      }

      case 'warn':
        return {
          guard: this.name,
          action: 'warn',
          reason: `PII found but not redacted: ${matches.map(m => m.type).join(', ')}`,
          score: 0.5,
        };
    }
  }

  /**
   * Detect all PII entities in text.
   */
  private detectAll(input: string): PIIMatch[] {
    const matches: PIIMatch[] = [];

    for (const entityType of this.config.entities) {
      const detector = this.detectors.get(entityType);
      if (!detector) continue;

      const entityMatches = detector.detect(input);
      matches.push(...entityMatches);
    }

    // Custom patterns
    if (this.config.customPatterns) {
      for (const custom of this.config.customPatterns) {
        let match: RegExpExecArray | null;
        const regex = new RegExp(custom.regex, 'g');
        while ((match = regex.exec(input)) !== null) {
          matches.push({
            type: custom.name,
            value: match[0],
            start: match.index,
            end: match.index + match[0].length,
            replacement: custom.replacement ?? `[${custom.name.toUpperCase()}]`,
          });
        }
      }
    }

    // Sort by position and deduplicate overlaps
    return this.deduplicateOverlaps(matches.sort((a, b) => a.start - b.start));
  }

  /**
   * Apply redactions to text (process from end to preserve offsets).
   */
  private redact(input: string, matches: PIIMatch[]): string {
    let result = input;
    // Process from end to beginning to preserve character offsets
    for (let i = matches.length - 1; i >= 0; i--) {
      const match = matches[i]!;
      result = result.substring(0, match.start) + match.replacement + result.substring(match.end);
    }
    return result;
  }

  private deduplicateOverlaps(sorted: PIIMatch[]): PIIMatch[] {
    const result: PIIMatch[] = [];
    let lastEnd = -1;

    for (const match of sorted) {
      if (match.start >= lastEnd) {
        result.push(match);
        lastEnd = match.end;
      }
    }

    return result;
  }

  private initializeDetectors(): Map<string, PIIDetector> {
    const detectors = new Map<string, PIIDetector>();

    detectors.set('email', new RegexDetector(
      'email',
      /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
      '[EMAIL]',
    ));

    detectors.set('phone', new RegexDetector(
      'phone',
      /(?:\+55\s?)?(?:\(?\d{2}\)?\s?)(?:9\s?)?\d{4}[-\s]?\d{4}/g,
      '[PHONE]',
    ));

    detectors.set('cpf', new CPFDetector());
    detectors.set('cnpj', new CNPJDetector());

    detectors.set('credit_card', new CreditCardDetector());

    detectors.set('ip_address', new RegexDetector(
      'ip_address',
      /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
      '[IP_ADDRESS]',
      (match) => {
        const octets = match.split('.').map(Number);
        return octets.every(o => o >= 0 && o <= 255);
      },
    ));

    return detectors;
  }
}

// --- Detector implementations ---

interface PIIDetector {
  detect(input: string): PIIMatch[];
}

class RegexDetector implements PIIDetector {
  constructor(
    private readonly type: PIIEntityType,
    private readonly pattern: RegExp,
    private readonly replacement: string,
    private readonly validator?: (match: string) => boolean,
  ) {}

  detect(input: string): PIIMatch[] {
    const matches: PIIMatch[] = [];
    const regex = new RegExp(this.pattern, 'g');
    let match: RegExpExecArray | null;

    while ((match = regex.exec(input)) !== null) {
      if (this.validator && !this.validator(match[0])) continue;

      matches.push({
        type: this.type,
        value: match[0],
        start: match.index,
        end: match.index + match[0].length,
        replacement: this.replacement,
      });
    }

    return matches;
  }
}

/**
 * CPF Detector with checksum validation.
 * Format: XXX.XXX.XXX-XX or XXXXXXXXXXX
 */
class CPFDetector implements PIIDetector {
  detect(input: string): PIIMatch[] {
    const pattern = /\b(\d{3}\.\d{3}\.\d{3}-\d{2}|\d{11})\b/g;
    const matches: PIIMatch[] = [];
    let match: RegExpExecArray | null;

    while ((match = pattern.exec(input)) !== null) {
      const digits = match[0].replace(/\D/g, '');
      if (this.isValidCPF(digits)) {
        matches.push({
          type: 'cpf',
          value: match[0],
          start: match.index,
          end: match.index + match[0].length,
          replacement: '[CPF]',
        });
      }
    }

    return matches;
  }

  /**
   * CPF validation algorithm:
   * 1. Reject if all digits are the same
   * 2. Calculate first check digit using weights 10-2
   * 3. Calculate second check digit using weights 11-2
   */
  private isValidCPF(cpf: string): boolean {
    if (cpf.length !== 11) return false;
    if (/^(\d)\1{10}$/.test(cpf)) return false; // All same digits

    // First check digit
    let sum = 0;
    for (let i = 0; i < 9; i++) {
      sum += parseInt(cpf[i]!) * (10 - i);
    }
    let remainder = (sum * 10) % 11;
    if (remainder === 10) remainder = 0;
    if (remainder !== parseInt(cpf[9]!)) return false;

    // Second check digit
    sum = 0;
    for (let i = 0; i < 10; i++) {
      sum += parseInt(cpf[i]!) * (11 - i);
    }
    remainder = (sum * 10) % 11;
    if (remainder === 10) remainder = 0;
    if (remainder !== parseInt(cpf[10]!)) return false;

    return true;
  }
}

/**
 * CNPJ Detector with checksum validation.
 * Format: XX.XXX.XXX/XXXX-XX or XXXXXXXXXXXXXX
 */
class CNPJDetector implements PIIDetector {
  detect(input: string): PIIMatch[] {
    const pattern = /\b(\d{2}\.\d{3}\.\d{3}\/\d{4}-\d{2}|\d{14})\b/g;
    const matches: PIIMatch[] = [];
    let match: RegExpExecArray | null;

    while ((match = pattern.exec(input)) !== null) {
      const digits = match[0].replace(/\D/g, '');
      if (this.isValidCNPJ(digits)) {
        matches.push({
          type: 'cnpj',
          value: match[0],
          start: match.index,
          end: match.index + match[0].length,
          replacement: '[CNPJ]',
        });
      }
    }

    return matches;
  }

  private isValidCNPJ(cnpj: string): boolean {
    if (cnpj.length !== 14) return false;
    if (/^(\d)\1{13}$/.test(cnpj)) return false;

    const weights1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
    const weights2 = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];

    let sum = 0;
    for (let i = 0; i < 12; i++) {
      sum += parseInt(cnpj[i]!) * weights1[i]!;
    }
    let remainder = sum % 11;
    const digit1 = remainder < 2 ? 0 : 11 - remainder;
    if (digit1 !== parseInt(cnpj[12]!)) return false;

    sum = 0;
    for (let i = 0; i < 13; i++) {
      sum += parseInt(cnpj[i]!) * weights2[i]!;
    }
    remainder = sum % 11;
    const digit2 = remainder < 2 ? 0 : 11 - remainder;
    if (digit2 !== parseInt(cnpj[13]!)) return false;

    return true;
  }
}

/**
 * Credit Card Detector with Luhn algorithm validation.
 */
class CreditCardDetector implements PIIDetector {
  detect(input: string): PIIMatch[] {
    const pattern = /\b(\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}|\d{16})\b/g;
    const matches: PIIMatch[] = [];
    let match: RegExpExecArray | null;

    while ((match = pattern.exec(input)) !== null) {
      const digits = match[0].replace(/\D/g, '');
      if (this.luhnCheck(digits)) {
        matches.push({
          type: 'credit_card',
          value: match[0],
          start: match.index,
          end: match.index + match[0].length,
          replacement: '[CREDIT_CARD]',
        });
      }
    }

    return matches;
  }

  /**
   * Luhn algorithm (mod 10) for credit card validation.
   */
  private luhnCheck(number: string): boolean {
    let sum = 0;
    let isEven = false;

    for (let i = number.length - 1; i >= 0; i--) {
      let digit = parseInt(number[i]!);

      if (isEven) {
        digit *= 2;
        if (digit > 9) digit -= 9;
      }

      sum += digit;
      isEven = !isEven;
    }

    return sum % 10 === 0;
  }
}
