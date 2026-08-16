/**
 * guardrails-core: an AI safety layer that fails as a value, not an exception.
 *
 * Hallucination and prompt injection are treated as BOUNDARY problems rather than
 * prompting problems. Nothing a model produced reaches application state, another
 * agent, or persistence until it has passed a gate that can reject it.
 *
 * Four composable pieces:
 *
 *   GuardPipeline      ordered guards with pass | transform | warn | block
 *   InjectionGuard     three-layer prompt injection detection
 *   PIIRedactorGuard   checksum-validated PII detection and redaction
 *   AuditLogger        append-only log with a tamper-evident hash chain
 */

export { GuardPipeline } from './guards/base.guard.js';
export type {
  BaseGuard,
  GuardAction,
  GuardResult,
  PipelineConfig,
  PipelineOutcome,
} from './guards/base.guard.js';

export { InjectionGuard } from './guards/input/injection.guard.js';
export type { InjectionConfig } from './guards/input/injection.guard.js';

export { PIIRedactorGuard } from './guards/input/pii-redactor.guard.js';
export type { PIIConfig, PIIEntityType } from './guards/input/pii-redactor.guard.js';

export { AuditLogger } from './audit/logger.js';
export type { AuditConfig, AuditEntry } from './audit/logger.js';

export { Guardrails } from './core/guardrails.js';

import { GuardPipeline, type BaseGuard, type PipelineConfig } from './guards/base.guard.js';
import { InjectionGuard, type InjectionConfig } from './guards/input/injection.guard.js';
import {
  PIIRedactorGuard,
  type PIIConfig,
} from './guards/input/pii-redactor.guard.js';

/**
 * Defaults chosen so the common case is safe without configuration.
 *
 * Injection threshold is 0.8 rather than lower: these detectors are heuristic, and a
 * guard that blocks legitimate traffic gets disabled entirely, which protects nothing.
 * Start conservative, observe `warn` results against real traffic, then tighten.
 */
export const DEFAULT_INJECTION_CONFIG: InjectionConfig = {
  enabled: true,
  threshold: 0.8,
};

/**
 * Redact rather than block by default.
 *
 * Blocking on any PII makes a support tool unusable, since users legitimately paste
 * their own email into a support request. Redaction keeps the request serviceable
 * while stopping the value from reaching a third-party provider.
 */
export const DEFAULT_PII_CONFIG: PIIConfig = {
  enabled: true,
  action: 'redact',
  entities: ['email', 'phone', 'cpf', 'cnpj', 'credit_card'],
};

export interface ComposeOptions {
  injection?: InjectionConfig | false;
  pii?: PIIConfig | false;
  pipeline?: PipelineConfig;
  /** Appended after the built-ins, so they see already-redacted input. */
  extra?: BaseGuard[];
}

/**
 * Build a standard input pipeline.
 *
 * The ORDER here is a correctness property, not a preference:
 *
 *   1. PII redaction runs FIRST. The injection detector then sees redacted text, so a
 *      phone number cannot be mistaken for an encoded payload, and the raw value never
 *      reaches a detector that might log it.
 *
 *   2. Injection detection runs SECOND, on the redacted text. It is the more expensive
 *      of the two, and running it after means a redaction transform is already applied
 *      when it evaluates.
 *
 * Reversing them produces both a false-positive source and a leak path, which is why
 * this helper exists rather than leaving assembly to each caller.
 */
export function composeInputGuards(options: ComposeOptions = {}): GuardPipeline {
  const pipeline = new GuardPipeline(options.pipeline ?? {});

  if (options.pii !== false) {
    pipeline.add(new PIIRedactorGuard(options.pii ?? DEFAULT_PII_CONFIG));
  }

  if (options.injection !== false) {
    pipeline.add(new InjectionGuard(options.injection ?? DEFAULT_INJECTION_CONFIG));
  }

  for (const guard of options.extra ?? []) {
    pipeline.add(guard);
  }

  return pipeline;
}
