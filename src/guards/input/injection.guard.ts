import type { BaseGuard, GuardResult } from '../base.guard.js';

export interface InjectionConfig {
  enabled: boolean;
  threshold: number;
  customPatterns?: RegExp[];
  allowList?: string[];
}

/**
 * Prompt Injection Detection Guard
 *
 * Multi-layer detection strategy:
 *
 * Layer 1: Pattern Matching (fast, low false-positive)
 *   - Known attack templates: "ignore previous", "DAN mode", role-play hijack
 *   - Unicode tricks: homoglyphs, invisible characters, RTL override
 *   - Encoding attacks: base64 instructions, hex encoding
 *
 * Layer 2: Structural Analysis (medium speed)
 *   - Instruction density: ratio of imperative sentences to total
 *   - Context switching: abrupt topic/persona changes
 *   - Delimiter abuse: excessive markdown, XML tags, system markers
 *
 * Layer 3: Semantic Analysis (slower, highest accuracy)
 *   - Embedding similarity to known injection corpus
 *   - Intent classification: informational vs. manipulative
 *
 * Scoring: Weighted combination of all layers
 *   final_score = 0.3 * pattern + 0.3 * structural + 0.4 * semantic
 */
export class InjectionGuard implements BaseGuard {
  readonly name = 'injection';
  private readonly config: InjectionConfig;
  private readonly patterns: RegExp[];

  constructor(config: InjectionConfig) {
    this.config = config;
    this.patterns = [
      ...DEFAULT_INJECTION_PATTERNS,
      ...(config.customPatterns ?? []),
    ];
  }

  async check(input: string): Promise<GuardResult> {
    // Allow-list bypass
    if (this.config.allowList?.some(safe => input.includes(safe))) {
      return this.pass();
    }

    // Layer 1: Pattern matching
    const patternScore = this.patternAnalysis(input);

    // Layer 2: Structural analysis
    const structuralScore = this.structuralAnalysis(input);

    // Layer 3: Semantic analysis (simplified without external model)
    const semanticScore = this.heuristicSemanticAnalysis(input);

    // Weighted final score
    const finalScore = (
      0.3 * patternScore +
      0.3 * structuralScore +
      0.4 * semanticScore
    );

    if (finalScore >= this.config.threshold) {
      return {
        guard: this.name,
        action: 'block',
        reason: `Prompt injection detected (confidence: ${(finalScore * 100).toFixed(1)}%)`,
        score: finalScore,
        details: { patternScore, structuralScore, semanticScore },
      };
    }

    // Warn on borderline cases
    if (finalScore >= this.config.threshold * 0.7) {
      return {
        guard: this.name,
        action: 'warn',
        reason: `Possible injection attempt (confidence: ${(finalScore * 100).toFixed(1)}%)`,
        score: finalScore,
      };
    }

    return this.pass();
  }

  /**
   * Pattern-based detection.
   * Returns 0-1 score based on matched patterns.
   */
  private patternAnalysis(input: string): number {
    const normalizedInput = input.toLowerCase().trim();
    let matchCount = 0;
    let maxWeight = 0;

    for (const pattern of this.patterns) {
      if (pattern.test(normalizedInput)) {
        matchCount++;
        // Critical patterns get higher weight
        const weight = PATTERN_WEIGHTS.get(pattern.source) ?? 0.5;
        maxWeight = Math.max(maxWeight, weight);
      }
    }

    if (matchCount === 0) return 0;

    // Single critical match is enough
    if (maxWeight >= 0.9) return maxWeight;

    // Multiple weak matches compound
    return Math.min(1, maxWeight + (matchCount - 1) * 0.1);
  }

  /**
   * Structural analysis.
   * Detects instruction-heavy inputs, delimiter abuse, encoding tricks.
   */
  private structuralAnalysis(input: string): number {
    let score = 0;

    // Check instruction density (imperative sentences)
    const sentences = input.split(/[.!?]\s+/);
    const imperatives = sentences.filter(s =>
      /^(you must|you should|always|never|do not|ignore|forget|disregard|override|bypass)/i.test(s.trim()),
    );
    const instructionRatio = sentences.length > 0 ? imperatives.length / sentences.length : 0;
    score += instructionRatio * 0.4;

    // Check for system prompt markers
    const systemMarkers = [
      '```system', '<<SYS>>', '[INST]', '<|im_start|>system',
      'SYSTEM:', '### System:', '## Instructions:',
    ];
    if (systemMarkers.some(m => input.includes(m))) {
      score += 0.7;
    }

    // Check for encoding tricks
    if (this.hasEncodingTricks(input)) {
      score += 0.5;
    }

    // Check for invisible characters
    if (this.hasInvisibleChars(input)) {
      score += 0.3;
    }

    return Math.min(1, score);
  }

  /**
   * Heuristic semantic analysis without external model.
   * Checks for manipulation intent signals.
   */
  private heuristicSemanticAnalysis(input: string): number {
    let score = 0;
    const lower = input.toLowerCase();

    // Role-play hijack attempts
    const rolePlaySignals = [
      'you are now', 'act as', 'pretend to be', 'roleplay as',
      'new persona', 'your new role', 'from now on you',
    ];
    if (rolePlaySignals.some(s => lower.includes(s))) {
      score += 0.6;
    }

    // Output manipulation
    const outputManipulation = [
      'respond only with', 'output format:', 'reply with exactly',
      'say nothing else', 'just output', 'print only',
    ];
    if (outputManipulation.some(s => lower.includes(s))) {
      score += 0.3;
    }

    // Context window stuffing
    if (input.length > 5000 && /(.{50,})\1{3,}/.test(input)) {
      score += 0.5; // Repeated blocks (padding attack)
    }

    return Math.min(1, score);
  }

  private hasEncodingTricks(input: string): boolean {
    // Base64 detection (long base64-like strings)
    if (/[A-Za-z0-9+/]{50,}={0,2}/.test(input)) return true;

    // Hex encoding
    if (/\\x[0-9a-f]{2}/i.test(input)) return true;

    // Unicode escapes
    if (/\\u[0-9a-f]{4}/i.test(input)) return true;

    return false;
  }

  private hasInvisibleChars(input: string): boolean {
    // Zero-width characters, soft hyphens, RTL overrides
    return /[\u200B\u200C\u200D\u200E\u200F\u00AD\u202A-\u202E\uFEFF]/.test(input);
  }

  private pass(): GuardResult {
    return { guard: this.name, action: 'pass', score: 0 };
  }
}

// Known injection patterns (curated from real-world attacks)
const DEFAULT_INJECTION_PATTERNS: RegExp[] = [
  /ignore (all |any )?(previous|prior|above) (instructions|prompts|rules)/i,
  /disregard (all |any )?(previous|prior|above)/i,
  /forget (everything|all|your) (you|instructions|rules)/i,
  /you are (now |)(DAN|jailbroken|unfiltered|uncensored)/i,
  /enter (DAN|developer|god|sudo) mode/i,
  /\bDAN\b.*\bmode\b/i,
  /do anything now/i,
  /bypass (your |all |any )?(safety|content|ethical) (filters|guidelines|restrictions)/i,
  /override (your |the )?(system|safety|content) (prompt|instructions|policy)/i,
  /new (system |)prompt:/i,
  /\[system\].*\[\/system\]/is,
  /reveal (your |the )(system |initial |)(prompt|instructions)/i,
  /what (is|are) your (system |initial |)(prompt|instructions|rules)/i,
  /repeat (the |your )(system |initial |)(prompt|instructions)/i,
];

const PATTERN_WEIGHTS = new Map<string, number>([
  [DEFAULT_INJECTION_PATTERNS[0]!.source, 0.9],  // ignore previous
  [DEFAULT_INJECTION_PATTERNS[3]!.source, 0.95], // DAN mode
  [DEFAULT_INJECTION_PATTERNS[7]!.source, 0.85], // bypass filters
  [DEFAULT_INJECTION_PATTERNS[8]!.source, 0.85], // override system
]);
