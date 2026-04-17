// Attack Categories and Scenarios
export type AttackCategory = 
  | 'jailbreak'
  | 'prompt-injection'
  | 'prompt-extraction'
  | 'data-exfiltration'
  | 'credential-theft'
  | 'policy-evasion'
  | 'indirect-injection'
  | 'tool-misuse'
  | 'code-vulnerability';

export type TargetModel = 
  | 'gpt-4o'
  | 'gpt-4o-mini'
  | 'gpt-35-turbo'
  | 'custom-endpoint';

export interface AttackScenario {
  id: string;
  name: string;
  category: AttackCategory;
  description: string;
  prompt: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  expectedBehavior: string;
  narratorNotes: string;
}

// Attack Execution
export interface AttackConfig {
  category: AttackCategory;
  scenarioId: string;
  targetModel: TargetModel;
  shieldEnabled: boolean;
}

export interface AttackResult {
  id: string;
  timestamp: string;
  config: AttackConfig;
  scenario: AttackScenario;
  normalizedPrompt: string;
  response: string;
  status: 'blocked' | 'passed' | 'flagged' | 'error';
  verdicts: {
    shield: VerdictDetail;
    model: VerdictDetail;
    evaluator: VerdictDetail;
  };
  overallOutcome: 'safe' | 'vulnerable' | 'partial';
  correlationId: string;
  latencyMs: number;
  tokensUsed: number;
  evidenceLinks: EvidenceLink[];
  // Foundry context for traceability
  foundryResourceName: string;
  deploymentName: string;
  // Telemetry
  telemetryStatus: 'captured' | 'partial' | 'failed' | 'disabled' | 'pending';
}

export interface VerdictDetail {
  result: 'blocked' | 'allowed' | 'flagged' | 'n/a';
  confidence: number;
  reason: string;
}

export interface EvidenceLink {
  label: string;
  type: 'app-insights' | 'content-safety' | 'log-analytics' | 'defender';
  url: string;
}

// Campaign
export interface Campaign {
  id: string;
  correlationId: string;
  name: string;
  createdAt: string;
  completedAt: string | null;
  status: 'running' | 'completed' | 'failed';
  // Foundry context
  foundryResourceName: string;
  deploymentName: string;
  targetName: string;
  shieldEnabled: boolean;
  // Core statistics
  totalAttacks: number;
  blocked: number;
  passed: number;
  flagged: number;
  // Detailed outcome breakdown
  safeRefusalCount: number;
  unsafeSuccessCount: number;
  suspiciousSuccessCount: number;
  errorCount: number;
  // Computed metrics
  attackSuccessRate: number;
  blockedRate: number;
  averageLatencyMs: number;
  totalLatencyMs: number;
  // Telemetry
  telemetryStatus: 'captured' | 'partial' | 'failed' | 'disabled' | 'pending';
  results: AttackResult[];
}

// Metrics
export interface DashboardMetrics {
  totalAttacks: number;
  blockedCount: number;
  passedCount: number;
  flaggedCount: number;
  avgLatencyMs: number;
  blockRate: number;
}
