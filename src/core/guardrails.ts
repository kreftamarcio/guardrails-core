import { z } from 'zod';
import type { GuardrailsConfig, GuardResult, ExecutionResult } from './config.js';
import { InjectionGuard } from '../guards/input/injection.guard.js';
import { PIIRedactorGuard } from '../guards/input/pii-redactor.guard.js';
import { TopicGuard } from '../guards/input/topic.guard.js';
import { TokenBudgetGuard } from '../guards/input/token-budget.guard.js';
import { SchemaGuard } from '../guards/output/schema.guard.js';
import { PIIScannerGuard } from '../guards/output/pii-scanner.guard.js';
import { ToxicityGuard } from '../guards/output/toxicity.guard.js';
import { AuditLogger } from '../audit/logger.js';
import type { BaseGuard } from '../guards/base.guard.js';

export class Guardrails {
  private readonly inputGuards: BaseGuard[] = [];
  private readonly outputGuards: BaseGuard[] = [];
  private readonly auditLogger: AuditLogger | null;

  constructor(private readonly config: GuardrailsConfig) {
    // Initialize input guards
    if (config.input.injection?.enabled) {
      this.inputGuards.push(new InjectionGuard(config.input.injection));
    }
    if (config.input.pii?.enabled) {
      this.inputGuards.push(new PIIRedactorGuard(config.input.pii));
    }
    if (config.input.topics) {
      this.inputGuards.push(new TopicGuard(config.input.topics));
    }
    if (config.input.tokenBudget) {
      this.inputGuards.push(new TokenBudgetGuard(config.input.tokenBudget));
    }

    // Initialize output guards
    if (config.output.schema) {
      this.outputGuards.push(new SchemaGuard(config.output.schema, config.output.maxRetries));
    }
    if (config.output.pii?.enabled) {
      this.outputGuards.push(new PIIScannerGuard(config.output.pii));
    }
    if (config.output.toxicity?.enabled) {
      this.outputGuards.push(new ToxicityGuard(config.output.toxicity));
    }

    // Initialize audit
    this.auditLogger = config.audit?.enabled
      ? new AuditLogger(config.audit)
      : null;
  }

  /**
   * Execute an LLM call wrapped with input/output guards.
   *
   * Flow:
   * 1. Run all input guards sequentially (fail-fast on block)
   * 2. Execute the LLM function with sanitized input
   * 3. Run all output guards on the response
   * 4. Log the full execution to audit trail
   * 5. Return result with guard metadata
   */
  async execute<T>(params: {
    input: string;
    fn: (sanitizedInput: string) => Promise<T>;
    metadata?: Record<string, unknown>;
  }): Promise<ExecutionResult<T>> {
    const startTime = performance.now();
    const executionId = crypto.randomUUID();
    let currentInput = params.input;
    const guardResults: GuardResult[] = [];

    // Phase 1: Input guards
    for (const guard of this.inputGuards) {
      const result = await guard.check(currentInput);
      guardResults.push(result);

      if (result.action === 'block') {
        const execution = this.buildBlockedResult<T>(
          executionId,
          result.guard,
          result.reason,
          guardResults,
          startTime,
        );
        await this.audit(execution, params.metadata);
        return execution;
      }

      if (result.action === 'transform') {
        currentInput = result.transformedValue ?? currentInput;
      }
    }

    // Phase 2: LLM execution
    let output: T;
    try {
      output = await params.fn(currentInput);
    } catch (error) {
      const execution: ExecutionResult<T> = {
        id: executionId,
        blocked: true,
        reason: 'execution_error',
        error: (error as Error).message,
        guardResults,
        latencyMs: performance.now() - startTime,
      };
      await this.audit(execution, params.metadata);
      return execution;
    }

    // Phase 3: Output guards
    const outputStr = typeof output === 'string' ? output : JSON.stringify(output);

    for (const guard of this.outputGuards) {
      const result = await guard.check(outputStr);
      guardResults.push(result);

      if (result.action === 'block') {
        const execution = this.buildBlockedResult<T>(
          executionId,
          result.guard,
          result.reason,
          guardResults,
          startTime,
        );
        await this.audit(execution, params.metadata);
        return execution;
      }
    }

    // Phase 4: Success
    const execution: ExecutionResult<T> = {
      id: executionId,
      blocked: false,
      output,
      guardResults,
      latencyMs: performance.now() - startTime,
    };

    await this.audit(execution, params.metadata);
    return execution;
  }

  /**
   * Validate a single input without executing an LLM call.
   * Useful for pre-flight checks in streaming scenarios.
   */
  async validateInput(input: string): Promise<{
    valid: boolean;
    results: GuardResult[];
    sanitized: string;
  }> {
    let currentInput = input;
    const results: GuardResult[] = [];

    for (const guard of this.inputGuards) {
      const result = await guard.check(currentInput);
      results.push(result);

      if (result.action === 'block') {
        return { valid: false, results, sanitized: currentInput };
      }

      if (result.action === 'transform') {
        currentInput = result.transformedValue ?? currentInput;
      }
    }

    return { valid: true, results, sanitized: currentInput };
  }

  private buildBlockedResult<T>(
    id: string,
    guard: string,
    reason: string,
    guardResults: GuardResult[],
    startTime: number,
  ): ExecutionResult<T> {
    return {
      id,
      blocked: true,
      reason: `${guard}: ${reason}`,
      guardResults,
      latencyMs: performance.now() - startTime,
    };
  }

  private async audit(
    execution: ExecutionResult<unknown>,
    metadata?: Record<string, unknown>,
  ): Promise<void> {
    if (!this.auditLogger) return;

    await this.auditLogger.log({
      executionId: execution.id,
      timestamp: new Date().toISOString(),
      blocked: execution.blocked,
      reason: execution.blocked ? execution.reason : undefined,
      guardResults: execution.guardResults,
      latencyMs: execution.latencyMs,
      metadata,
    });
  }
}
