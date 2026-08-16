/**
 * Topic Boundary Guard: prevents the model from going off-topic.
 *
 * Problem: In production AI systems, models must stay within defined boundaries.
 * A customer support bot shouldn't give medical advice. A code assistant
 * shouldn't produce legal opinions.
 *
 * Solution: Define allowed/blocked topic categories. Score the output
 * against these categories and block responses that cross boundaries.
 *
 * Methods:
 *   1. Keyword-based (fast, low accuracy)
 *   2. Embedding similarity to topic exemplars (medium speed, good accuracy)
 *   3. LLM-as-judge classification (slow, highest accuracy)
 *
 * In production: combine all three with early-exit optimization.
 */

export interface TopicBoundaryConfig {
  /** Topics the model IS allowed to discuss */
  allowedTopics: TopicDefinition[];
  /** Topics the model must NEVER discuss */
  blockedTopics: TopicDefinition[];
  /** Scoring method */
  method: 'keyword' | 'embedding' | 'classifier';
  /** Threshold for blocking (0-1) */
  blockThreshold?: number;
  /** Embedding function (required if method is 'embedding') */
  embed?: (texts: string[]) => Promise<number[][]>;
  /** Classifier function (required if method is 'classifier') */
  classify?: (text: string, categories: string[]) => Promise<Record<string, number>>;
  /** Action on boundary violation */
  onViolation?: 'block' | 'warn' | 'redirect';
  /** Redirect message when topic is blocked */
  redirectMessage?: string;
}

export interface TopicDefinition {
  name: string;
  description: string;
  keywords?: string[];
  exemplars?: string[];
}

export interface BoundaryCheckResult {
  allowed: boolean;
  matchedTopic?: string;
  confidence: number;
  method: string;
  action: 'pass' | 'block' | 'warn' | 'redirect';
  redirectMessage?: string;
}

export class TopicBoundaryGuard {
  private readonly blockThreshold: number;
  private readonly onViolation: 'block' | 'warn' | 'redirect';

  constructor(private readonly config: TopicBoundaryConfig) {
    this.blockThreshold = config.blockThreshold ?? 0.7;
    this.onViolation = config.onViolation ?? 'block';
  }

  /**
   * Check if output stays within topic boundaries.
   */
  async check(output: string): Promise<BoundaryCheckResult> {
    // First: check blocked topics
    const blockedResult = await this.checkBlockedTopics(output);
    if (blockedResult) {
      return blockedResult;
    }

    // Second: if allowedTopics is non-empty, verify output is within bounds
    if (this.config.allowedTopics.length > 0) {
      const allowedResult = await this.checkAllowedTopics(output);
      if (!allowedResult.allowed) {
        return allowedResult;
      }
    }

    return { allowed: true, confidence: 1, method: this.config.method, action: 'pass' };
  }

  private async checkBlockedTopics(output: string): Promise<BoundaryCheckResult | null> {
    for (const topic of this.config.blockedTopics) {
      const score = await this.scoreTopic(output, topic);

      if (score >= this.blockThreshold) {
        return {
          allowed: false,
          matchedTopic: topic.name,
          confidence: score,
          method: this.config.method,
          action: this.onViolation,
          redirectMessage: this.config.redirectMessage,
        };
      }
    }
    return null;
  }

  private async checkAllowedTopics(output: string): Promise<BoundaryCheckResult> {
    let bestScore = 0;
    let bestTopic = '';

    for (const topic of this.config.allowedTopics) {
      const score = await this.scoreTopic(output, topic);
      if (score > bestScore) {
        bestScore = score;
        bestTopic = topic.name;
      }
    }

    if (bestScore < this.blockThreshold) {
      return {
        allowed: false,
        matchedTopic: bestTopic || undefined,
        confidence: 1 - bestScore,
        method: this.config.method,
        action: this.onViolation,
        redirectMessage: this.config.redirectMessage,
      };
    }

    return { allowed: true, matchedTopic: bestTopic, confidence: bestScore, method: this.config.method, action: 'pass' };
  }

  private async scoreTopic(text: string, topic: TopicDefinition): Promise<number> {
    switch (this.config.method) {
      case 'keyword':
        return this.keywordScore(text, topic);
      case 'embedding':
        return this.embeddingScore(text, topic);
      case 'classifier':
        return this.classifierScore(text, topic);
      default:
        return this.keywordScore(text, topic);
    }
  }

  private keywordScore(text: string, topic: TopicDefinition): number {
    if (!topic.keywords || topic.keywords.length === 0) return 0;

    const lower = text.toLowerCase();
    let matches = 0;

    for (const keyword of topic.keywords) {
      if (lower.includes(keyword.toLowerCase())) {
        matches++;
      }
    }

    return matches / topic.keywords.length;
  }

  private async embeddingScore(text: string, topic: TopicDefinition): Promise<number> {
    if (!this.config.embed || !topic.exemplars || topic.exemplars.length === 0) {
      return this.keywordScore(text, topic);
    }

    const embeddings = await this.config.embed([text, ...topic.exemplars]);
    const textEmb = embeddings[0]!;

    let maxSim = 0;
    for (let i = 1; i < embeddings.length; i++) {
      const sim = this.cosineSimilarity(textEmb, embeddings[i]!);
      if (sim > maxSim) maxSim = sim;
    }

    return maxSim;
  }

  private async classifierScore(text: string, topic: TopicDefinition): Promise<number> {
    if (!this.config.classify) {
      return this.keywordScore(text, topic);
    }

    const scores = await this.config.classify(text, [topic.name]);
    return scores[topic.name] ?? 0;
  }

  private cosineSimilarity(a: number[], b: number[]): number {
    let dot = 0, normA = 0, normB = 0;
    for (let i = 0; i < a.length; i++) {
      dot += a[i]! * b[i]!;
      normA += a[i]! * a[i]!;
      normB += b[i]! * b[i]!;
    }
    const denom = Math.sqrt(normA) * Math.sqrt(normB);
    return denom === 0 ? 0 : dot / denom;
  }
}
