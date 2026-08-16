/**
 * Schema Validator Guard: ensures LLM output conforms to expected structure.
 *
 * Problem: LLMs produce unpredictable output. When your system depends on
 * structured data (JSON, specific fields, enum values), malformed responses
 * cascade into runtime errors downstream.
 *
 * Solution: Validate LLM output against a Zod schema. On failure:
 *   1. Attempt auto-repair (common fixable issues like trailing commas)
 *   2. Retry with structured error feedback to the model
 *   3. Reject with detailed validation errors for debugging
 *
 * This guard operates on the OUTPUT side of the pipeline (post-generation).
 */

import { z } from 'zod';
import type { ZodSchema, ZodError, ZodIssue } from 'zod';

export interface SchemaValidatorConfig {
  /** Maximum auto-repair attempts before failing */
  maxRepairAttempts?: number;
  /** Whether to attempt JSON repair on parse failure */
  autoRepair?: boolean;
  /** Whether to strip unknown keys from the output */
  stripUnknown?: boolean;
  /** Custom repair function (receives raw output, returns attempted fix) */
  customRepair?: (raw: string, errors: ZodIssue[]) => string;
}

export interface ValidationResult<T> {
  success: boolean;
  data?: T;
  raw: string;
  errors?: ZodIssue[];
  repaired: boolean;
  repairAttempts: number;
}

const DEFAULT_CONFIG: Required<Omit<SchemaValidatorConfig, 'customRepair'>> = {
  maxRepairAttempts: 3,
  autoRepair: true,
  stripUnknown: true,
};

export class SchemaValidatorGuard<T> {
  private readonly config: typeof DEFAULT_CONFIG & SchemaValidatorConfig;

  constructor(
    private readonly schema: ZodSchema<T>,
    config?: SchemaValidatorConfig,
  ) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Validate LLM output against the schema.
   * Attempts repair if autoRepair is enabled.
   */
  validate(output: string): ValidationResult<T> {
    let raw = output;
    let repairAttempts = 0;

    // Step 1: Extract JSON from potential markdown code blocks
    const extracted = this.extractJSON(raw);
    if (extracted) raw = extracted;

    // Step 2: Try parsing directly
    const directResult = this.tryParse(raw);
    if (directResult.success) {
      return { success: true, data: directResult.data, raw: output, repaired: false, repairAttempts: 0 };
    }

    if (!this.config.autoRepair) {
      return {
        success: false,
        raw: output,
        errors: directResult.errors,
        repaired: false,
        repairAttempts: 0,
      };
    }

    // Step 3: Attempt repairs
    let lastErrors = directResult.errors;
    let currentRaw = raw;

    while (repairAttempts < this.config.maxRepairAttempts) {
      repairAttempts++;

      // Try custom repair first
      if (this.config.customRepair) {
        currentRaw = this.config.customRepair(currentRaw, lastErrors ?? []);
      } else {
        currentRaw = this.autoRepairJSON(currentRaw);
      }

      const result = this.tryParse(currentRaw);
      if (result.success) {
        return {
          success: true,
          data: result.data,
          raw: output,
          repaired: true,
          repairAttempts,
        };
      }

      lastErrors = result.errors;
    }

    return {
      success: false,
      raw: output,
      errors: lastErrors,
      repaired: false,
      repairAttempts,
    };
  }

  /**
   * Generate a structured error message suitable for LLM retry prompts.
   * Tells the model exactly what went wrong and how to fix it.
   */
  formatErrorForRetry(result: ValidationResult<T>): string {
    if (result.success || !result.errors) return '';

    const issues = result.errors.map(issue => {
      const path = issue.path.length > 0 ? `at "${issue.path.join('.')}"` : 'at root';
      return `- ${path}: ${issue.message} (expected: ${issue.code})`;
    });

    return [
      'Your previous response did not match the required schema.',
      'Please fix the following issues:',
      ...issues,
      '',
      'Expected schema:',
      this.getSchemaDescription(),
    ].join('\n');
  }

  private tryParse(raw: string): { success: true; data: T } | { success: false; errors: ZodIssue[] } {
    try {
      const parsed = JSON.parse(raw);
      const result = this.schema.safeParse(parsed);

      if (result.success) {
        return { success: true, data: result.data };
      }
      return { success: false, errors: result.error.issues };
    } catch {
      return {
        success: false,
        errors: [{
          code: 'custom',
          path: [],
          message: 'Invalid JSON: could not parse output as JSON',
        } as ZodIssue],
      };
    }
  }

  private extractJSON(text: string): string | null {
    // Try markdown code block extraction
    const codeBlockMatch = text.match(/```(?:json)?\s*\n?([\s\S]*?)\n?```/);
    if (codeBlockMatch?.[1]) {
      return codeBlockMatch[1].trim();
    }

    // Try finding JSON object/array boundaries
    const jsonStart = text.indexOf('{');
    const jsonEnd = text.lastIndexOf('}');
    if (jsonStart !== -1 && jsonEnd > jsonStart) {
      return text.slice(jsonStart, jsonEnd + 1);
    }

    const arrStart = text.indexOf('[');
    const arrEnd = text.lastIndexOf(']');
    if (arrStart !== -1 && arrEnd > arrStart) {
      return text.slice(arrStart, arrEnd + 1);
    }

    return null;
  }

  /**
   * Attempt common JSON repairs:
   *   - Remove trailing commas
   *   - Fix single quotes to double quotes
   *   - Add missing closing brackets
   *   - Remove comments
   *   - Fix unquoted keys
   */
  private autoRepairJSON(raw: string): string {
    let repaired = raw;

    // Remove JS-style comments
    repaired = repaired.replace(/\/\/[^\n]*/g, '');
    repaired = repaired.replace(/\/\*[\s\S]*?\*\//g, '');

    // Fix trailing commas before } or ]
    repaired = repaired.replace(/,\s*([}\]])/g, '$1');

    // Fix single quotes
    repaired = repaired.replace(/'/g, '"');

    // Fix unquoted keys: { key: value } -> { "key": value }
    repaired = repaired.replace(/([{,]\s*)(\w+)\s*:/g, '$1"$2":');

    // Fix missing closing brace
    const openBraces = (repaired.match(/{/g) ?? []).length;
    const closeBraces = (repaired.match(/}/g) ?? []).length;
    if (openBraces > closeBraces) {
      repaired += '}'.repeat(openBraces - closeBraces);
    }

    // Fix missing closing bracket
    const openBrackets = (repaired.match(/\[/g) ?? []).length;
    const closeBrackets = (repaired.match(/]/g) ?? []).length;
    if (openBrackets > closeBrackets) {
      repaired += ']'.repeat(openBrackets - closeBrackets);
    }

    return repaired;
  }

  private getSchemaDescription(): string {
    try {
      // Zod doesn't have a built-in toJSON, but we can describe the shape
      if ('shape' in this.schema && typeof this.schema.shape === 'object') {
        return JSON.stringify(
          Object.keys(this.schema.shape as Record<string, unknown>),
          null,
          2,
        );
      }
      return '(complex schema - refer to API documentation)';
    } catch {
      return '(schema description unavailable)';
    }
  }
}

/**
 * Factory: create a schema validator from a Zod schema.
 */
export function createSchemaGuard<T>(schema: ZodSchema<T>, config?: SchemaValidatorConfig) {
  return new SchemaValidatorGuard(schema, config);
}
