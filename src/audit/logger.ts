import CryptoJS from 'crypto-js';

export interface AuditConfig {
  enabled: boolean;
  storage: 'postgres' | 'memory';
  connectionString?: string;
  maskPII?: boolean;
  retentionDays?: number;
}

export interface AuditEntry {
  executionId: string;
  timestamp: string;
  blocked: boolean;
  reason?: string;
  guardResults: Array<{
    guard: string;
    action: string;
    score?: number;
    reason?: string;
  }>;
  latencyMs: number;
  metadata?: Record<string, unknown>;
}

interface StoredEntry extends AuditEntry {
  id: number;
  hash: string;
  previousHash: string;
}

/**
 * Immutable Audit Logger
 *
 * Every guard execution is logged with a cryptographic hash chain,
 * making the audit trail tamper-evident.
 *
 * Properties:
 * - Append-only: entries cannot be modified or deleted
 * - Hash chain: each entry includes hash of previous entry
 * - Verifiable: any modification breaks the chain
 * - LGPD-ready: PII in logs is masked before storage
 *
 * Hash chain construction:
 *   hash(entry_n) = SHA-256(entry_n.data + hash(entry_n-1))
 *
 * Verification:
 *   For each entry, recompute hash and compare.
 *   If any hash doesn't match, the chain is broken.
 */
export class AuditLogger {
  private readonly config: AuditConfig;
  private lastHash: string = '0'.repeat(64); // Genesis hash
  private store: AuditStore;

  constructor(config: AuditConfig) {
    this.config = config;
    this.store = config.storage === 'postgres'
      ? new PostgresAuditStore(config.connectionString!)
      : new MemoryAuditStore();
  }

  /**
   * Log an audit entry with hash chain linking.
   */
  async log(entry: AuditEntry): Promise<string> {
    // Mask PII in metadata if configured
    const sanitizedEntry = this.config.maskPII
      ? this.maskPIIInEntry(entry)
      : entry;

    // Compute hash (includes previous hash for chain integrity)
    const entryData = JSON.stringify(sanitizedEntry);
    const hash = this.computeHash(entryData, this.lastHash);

    const storedEntry: StoredEntry = {
      ...sanitizedEntry,
      id: Date.now(),
      hash,
      previousHash: this.lastHash,
    };

    await this.store.append(storedEntry);
    this.lastHash = hash;

    return hash;
  }

  /**
   * Verify the integrity of the audit chain.
   * Returns true if the chain is intact, false if tampered.
   */
  async verify(): Promise<{
    valid: boolean;
    entriesChecked: number;
    brokenAt?: number;
  }> {
    const entries = await this.store.getAll();
    let previousHash = '0'.repeat(64);
    let entriesChecked = 0;

    for (const entry of entries) {
      entriesChecked++;

      // Verify previous hash linkage
      if (entry.previousHash !== previousHash) {
        return { valid: false, entriesChecked, brokenAt: entry.id };
      }

      // Recompute hash and verify
      const { hash, previousHash: _, id, ...data } = entry;
      const expectedHash = this.computeHash(JSON.stringify(data), previousHash);

      if (hash !== expectedHash) {
        return { valid: false, entriesChecked, brokenAt: entry.id };
      }

      previousHash = hash;
    }

    return { valid: true, entriesChecked };
  }

  /**
   * Query audit entries with filters.
   */
  async query(filters: {
    startDate?: string;
    endDate?: string;
    blocked?: boolean;
    guard?: string;
    executionId?: string;
  }): Promise<AuditEntry[]> {
    return this.store.query(filters);
  }

  /**
   * Get audit statistics for a time period.
   */
  async stats(period: { start: string; end: string }): Promise<{
    total: number;
    blocked: number;
    blockRate: number;
    byGuard: Record<string, { triggered: number; blocked: number }>;
    avgLatencyMs: number;
  }> {
    const entries = await this.store.query({
      startDate: period.start,
      endDate: period.end,
    });

    const blocked = entries.filter(e => e.blocked);
    const byGuard: Record<string, { triggered: number; blocked: number }> = {};

    for (const entry of entries) {
      for (const gr of entry.guardResults) {
        if (!byGuard[gr.guard]) {
          byGuard[gr.guard] = { triggered: 0, blocked: 0 };
        }
        if (gr.action !== 'pass') {
          byGuard[gr.guard]!.triggered++;
        }
        if (gr.action === 'block') {
          byGuard[gr.guard]!.blocked++;
        }
      }
    }

    const avgLatency = entries.length > 0
      ? entries.reduce((sum, e) => sum + e.latencyMs, 0) / entries.length
      : 0;

    return {
      total: entries.length,
      blocked: blocked.length,
      blockRate: entries.length > 0 ? blocked.length / entries.length : 0,
      byGuard,
      avgLatencyMs: Math.round(avgLatency),
    };
  }

  private computeHash(data: string, previousHash: string): string {
    return CryptoJS.SHA256(data + previousHash).toString();
  }

  private maskPIIInEntry(entry: AuditEntry): AuditEntry {
    // Remove any raw PII from audit metadata
    const masked = { ...entry };
    if (masked.metadata) {
      masked.metadata = this.recursiveMask(masked.metadata);
    }
    return masked;
  }

  private recursiveMask(obj: Record<string, unknown>): Record<string, unknown> {
    const result: Record<string, unknown> = {};
    const sensitiveKeys = ['email', 'phone', 'cpf', 'cnpj', 'password', 'token', 'key'];

    for (const [key, value] of Object.entries(obj)) {
      if (sensitiveKeys.some(sk => key.toLowerCase().includes(sk))) {
        result[key] = '[MASKED]';
      } else if (typeof value === 'object' && value !== null) {
        result[key] = this.recursiveMask(value as Record<string, unknown>);
      } else {
        result[key] = value;
      }
    }

    return result;
  }
}

// --- Storage implementations ---

interface AuditStore {
  append(entry: StoredEntry): Promise<void>;
  getAll(): Promise<StoredEntry[]>;
  query(filters: Record<string, unknown>): Promise<AuditEntry[]>;
}

class MemoryAuditStore implements AuditStore {
  private entries: StoredEntry[] = [];

  async append(entry: StoredEntry): Promise<void> {
    this.entries.push(entry);
  }

  async getAll(): Promise<StoredEntry[]> {
    return [...this.entries];
  }

  async query(filters: Record<string, unknown>): Promise<AuditEntry[]> {
    let results = [...this.entries];

    if (filters.blocked !== undefined) {
      results = results.filter(e => e.blocked === filters.blocked);
    }
    if (filters.executionId) {
      results = results.filter(e => e.executionId === filters.executionId);
    }

    return results;
  }
}

class PostgresAuditStore implements AuditStore {
  constructor(private readonly connectionString: string) {}

  async append(_entry: StoredEntry): Promise<void> {
    // INSERT INTO audit_log (execution_id, timestamp, blocked, ...)
    throw new Error('PostgreSQL store not yet implemented');
  }

  async getAll(): Promise<StoredEntry[]> {
    throw new Error('PostgreSQL store not yet implemented');
  }

  async query(_filters: Record<string, unknown>): Promise<AuditEntry[]> {
    throw new Error('PostgreSQL store not yet implemented');
  }
}
