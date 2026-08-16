/**
 * Guard contract and pipeline.
 *
 * A guard returns one of four actions rather than a boolean:
 *
 *   pass       continue unchanged
 *   transform  continue with a modified value
 *   warn       continue, but flag it in the audit trail
 *   block      halt the pipeline immediately
 *
 * A boolean would force every guard to be a gate. Real guards do different things:
 * redaction rewrites the input, budget enforcement truncates it, detection rejects
 * it. Modelling the action explicitly is what allows PII redaction and injection
 * detection to compose in one ordered pipeline instead of requiring bespoke wiring
 * per combination.
 */

export type GuardAction = 'pass' | 'transform' | 'warn' | 'block';

export interface GuardResult {
  /** Guard that produced this result. Required, because an audit entry without it
   *  is unattributable. */
  guard: string;
  action: GuardAction;
  /** Required when action is 'block' or 'warn'. */
  reason?: string;
  /** Required when action is 'transform'. */
  transformedValue?: string;
  /** Confidence or severity in [0,1], where applicable. */
  score?: number;
  /** Structured detail for the audit log. Must not contain raw PII. */
  details?: Record<string, unknown>;
  /** Wall-clock cost of this guard, filled in by the pipeline. */
  latencyMs?: number;
}

export interface BaseGuard {
  readonly name: string;
  check(input: string): Promise<GuardResult> | GuardResult;
}

export interface PipelineOutcome {
  /** True when no guard blocked. */
  passed: boolean;
  /** Input after every transform was applied, in order. */
  value: string;
  /** Every guard that ran, in execution order. */
  results: GuardResult[];
  /** Set when a guard blocked. */
  blockedBy?: { guard: string; reason: string };
  /** Guards that returned warn. Non-blocking, but worth surfacing. */
  warnings: GuardResult[];
  /** Guards that never ran because an earlier one blocked. */
  skipped: string[];
  totalLatencyMs: number;
}

export interface PipelineConfig {
  /**
   * Cap on total guard latency. When exceeded, remaining guards are skipped and
   * the input passes.
   *
   * Fail-open is the correct default HERE and only here: guards protect an LLM call
   * that is itself about to take hundreds of milliseconds, and a guard stack that
   * makes the product unusable gets disabled entirely, which protects nothing.
   * Set failClosed to invert this for a high-stakes path.
   */
  maxTotalLatencyMs?: number;
  /** When true, a latency budget overrun blocks instead of passing. */
  failClosed?: boolean;
  /** Called for every result, including passes. Used to feed the audit logger. */
  onResult?: (result: GuardResult) => void;
}

/**
 * Ordered guard pipeline.
 *
 * Guards run in registration order and the order is the caller's declaration of
 * cost: cheap deterministic checks belong before expensive probabilistic ones, so a
 * blocked input never pays for a classifier it did not need.
 *
 * A transform feeds its modified value into the next guard. That is the mechanism
 * that lets PII redaction sit in front of injection detection: the detector sees the
 * redacted text, so a phone number cannot be mistaken for an encoded payload.
 */
export class GuardPipeline {
  private readonly guards: BaseGuard[] = [];
  private readonly config: PipelineConfig;

  constructor(config: PipelineConfig = {}) {
    this.config = config;
  }

  add(guard: BaseGuard): this {
    if (this.guards.some((g) => g.name === guard.name)) {
      throw new Error(
        `Guard "${guard.name}" is already registered. Audit entries are attributed ` +
          'by name, so duplicates make attribution ambiguous.',
      );
    }
    this.guards.push(guard);
    return this;
  }

  async run(input: string): Promise<PipelineOutcome> {
    const startedAt = performance.now();
    const results: GuardResult[] = [];
    const warnings: GuardResult[] = [];

    let current = input;

    for (let i = 0; i < this.guards.length; i++) {
      const guard = this.guards[i]!;
      const elapsed = performance.now() - startedAt;

      if (this.config.maxTotalLatencyMs !== undefined && elapsed > this.config.maxTotalLatencyMs) {
        const skipped = this.guards.slice(i).map((g) => g.name);

        if (this.config.failClosed) {
          return {
            passed: false,
            value: current,
            results,
            blockedBy: {
              guard: 'pipeline',
              reason:
                `Guard latency budget of ${this.config.maxTotalLatencyMs}ms exceeded ` +
                `after ${elapsed.toFixed(0)}ms. Failing closed, so ${skipped.length} ` +
                'guard(s) did not run and the input is rejected rather than passed ' +
                'unchecked.',
            },
            warnings,
            skipped,
            totalLatencyMs: elapsed,
          };
        }

        return {
          passed: true,
          value: current,
          results,
          warnings,
          skipped,
          totalLatencyMs: elapsed,
        };
      }

      const guardStart = performance.now();
      let result: GuardResult;

      try {
        result = await guard.check(current);
      } catch (error) {
        // A guard that throws is a defect in the guard, not evidence about the
        // input. Treated as a warning so a broken detector cannot silently start
        // rejecting all traffic, while still being loud in the audit trail.
        result = {
          guard: guard.name,
          action: 'warn',
          reason:
            `Guard "${guard.name}" threw and was skipped: ` +
            `${error instanceof Error ? error.message : String(error)}. ` +
            'This is a guard defect, not a judgement about the input.',
          score: 0,
        };
      }

      result.latencyMs = performance.now() - guardStart;
      results.push(result);
      this.config.onResult?.(result);

      switch (result.action) {
        case 'block':
          return {
            passed: false,
            value: current,
            results,
            blockedBy: {
              guard: result.guard,
              reason: result.reason ?? 'blocked without a stated reason',
            },
            warnings,
            skipped: this.guards.slice(i + 1).map((g) => g.name),
            totalLatencyMs: performance.now() - startedAt,
          };

        case 'transform':
          if (result.transformedValue === undefined) {
            throw new Error(
              `Guard "${result.guard}" returned action "transform" without a ` +
                'transformedValue. Silently keeping the original would make a ' +
                'redaction guard appear to work while leaking everything it claimed ' +
                'to redact.',
            );
          }
          current = result.transformedValue;
          break;

        case 'warn':
          warnings.push(result);
          break;

        case 'pass':
          break;
      }
    }

    return {
      passed: true,
      value: current,
      results,
      warnings,
      skipped: [],
      totalLatencyMs: performance.now() - startedAt,
    };
  }

  /**
   * Per-guard latency and action distribution.
   *
   * Useful for the question the pipeline exists to answer over time: which guard is
   * expensive, and which one is doing nothing? A guard that has never returned
   * anything but 'pass' across a large sample is either unnecessary or broken.
   */
  static summarize(outcomes: readonly PipelineOutcome[]): Record<
    string,
    { runs: number; blocks: number; warns: number; transforms: number; avgLatencyMs: number }
  > {
    const summary: Record<
      string,
      { runs: number; blocks: number; warns: number; transforms: number; totalLatency: number }
    > = {};

    for (const outcome of outcomes) {
      for (const result of outcome.results) {
        const entry = (summary[result.guard] ??= {
          runs: 0,
          blocks: 0,
          warns: 0,
          transforms: 0,
          totalLatency: 0,
        });

        entry.runs++;
        entry.totalLatency += result.latencyMs ?? 0;
        if (result.action === 'block') entry.blocks++;
        if (result.action === 'warn') entry.warns++;
        if (result.action === 'transform') entry.transforms++;
      }
    }

    return Object.fromEntries(
      Object.entries(summary).map(([guard, e]) => [
        guard,
        {
          runs: e.runs,
          blocks: e.blocks,
          warns: e.warns,
          transforms: e.transforms,
          avgLatencyMs: e.runs > 0 ? Math.round(e.totalLatency / e.runs) : 0,
        },
      ]),
    );
  }

  get registered(): string[] {
    return this.guards.map((g) => g.name);
  }
}
