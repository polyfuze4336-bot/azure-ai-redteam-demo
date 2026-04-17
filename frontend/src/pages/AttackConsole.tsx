import { useState, useEffect } from 'react';
import { 
  Settings, 
  MessageSquare, 
  CheckCircle, 
  Play, 
  Rocket, 
  Shield, 
  Bot, 
  Brain,
  ExternalLink,
  Copy,
  AlertCircle,
  Target,
  Lightbulb,
  X,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Loader2,
  FileText,
  Server,
  Activity,
  Eye,
  Search,
  BookOpen,
  Fingerprint,
  Cloud
} from 'lucide-react';
import Panel from '../components/Panel';
import Select from '../components/Select';
import Toggle from '../components/Toggle';
import StatusBadge from '../components/StatusBadge';
import { 
  attackCategories, 
  targetModels, 
  mockScenarios, 
  getScenariosByCategory 
} from '../data/mockData';
import { AttackCategory, AttackResult, VerdictDetail } from '../types';
import { runAttack, runCampaign, ApiAttackResult, ApiCampaignResult, ApiError } from '../services/api';

// Convert API verdict to frontend format
function convertVerdict(apiVerdict: ApiAttackResult['shield_verdict']): VerdictDetail {
  const resultMap: Record<string, VerdictDetail['result']> = {
    blocked: 'blocked',
    allowed: 'allowed',
    flagged: 'flagged',
    'n/a': 'n/a',
  };
  return {
    result: resultMap[apiVerdict.result] || 'n/a',
    confidence: apiVerdict.confidence,
    reason: apiVerdict.categories_detected.length > 0 
      ? `Detected: ${apiVerdict.categories_detected.join(', ')}`
      : apiVerdict.details?.analysis as string || 'No issues detected',
  };
}

// Convert API result to frontend format
function convertApiResult(apiResult: ApiAttackResult, scenario: typeof mockScenarios[0]): AttackResult {
  const statusMap: Record<string, AttackResult['status']> = {
    safe: 'blocked',
    vulnerable: 'passed',
    partial: 'flagged',
  };
  
  return {
    id: apiResult.run_id,
    timestamp: apiResult.timestamp,
    config: {
      category: apiResult.attack_category as AttackCategory,
      scenarioId: apiResult.scenario_id,
      targetModel: apiResult.target_name as any,
      shieldEnabled: apiResult.shield_enabled,
    },
    scenario,
    normalizedPrompt: apiResult.normalized_prompt || apiResult.prompt.toLowerCase().slice(0, 200),
    response: apiResult.response,
    status: statusMap[apiResult.outcome] || 'blocked',
    verdicts: {
      shield: convertVerdict(apiResult.shield_verdict),
      model: convertVerdict(apiResult.model_verdict),
      evaluator: convertVerdict(apiResult.evaluator_verdict),
    },
    overallOutcome: apiResult.outcome,
    correlationId: apiResult.correlation_id,
    latencyMs: apiResult.latency_ms,
    tokensUsed: apiResult.tokens_used || 0,
    evidenceLinks: [
      { label: 'View in Application Insights', type: 'app-insights', url: '#' },
      { label: 'Content Safety Analysis', type: 'content-safety', url: '#' },
      { label: 'Query in Log Analytics', type: 'log-analytics', url: '#' },
    ],
    // Foundry context for traceability
    foundryResourceName: apiResult.foundry_resource_name || '',
    deploymentName: apiResult.deployment_name || '',
    telemetryStatus: apiResult.telemetry_status || 'pending',
  };
}

interface CampaignSummary {
  campaign: ApiCampaignResult;
  isVisible: boolean;
}

// Generate plain-English narrative for demo storytelling
function generateNarrative(result: AttackResult): {
  summary: string;
  promptAdversarial: { answer: boolean; explanation: string };
  safetyIntervened: { answer: boolean; explanation: string };
  modelAnswered: { answer: boolean; explanation: string };
  outcome: { success: boolean; label: string; explanation: string };
} {
  const shieldBlocked = result.verdicts.shield.result === 'blocked';
  const modelRefused = result.verdicts.model.result === 'blocked';
  const overallSafe = result.overallOutcome === 'safe';
  const overallVulnerable = result.overallOutcome === 'vulnerable';
  
  // Determine if prompt looked adversarial
  const promptAdversarial = {
    answer: true, // Always true since we're running attack scenarios
    explanation: `This prompt was classified as a ${result.config.category.replace(/-/g, ' ')} attempt with ${result.scenario.severity} severity.`
  };
  
  // Determine if safety layer intervened
  const safetyIntervened = {
    answer: shieldBlocked,
    explanation: shieldBlocked 
      ? `Azure AI Content Safety detected the attack with ${Math.round(result.verdicts.shield.confidence * 100)}% confidence and blocked the request.`
      : `Content Safety allowed the prompt through — ${result.config.shieldEnabled ? 'the attack bypassed filters' : 'shield was disabled for this test'}.`
  };
  
  // Determine if model still answered
  const responseLength = result.response?.length || 0;
  const modelAnswered = {
    answer: responseLength > 50 && !overallSafe,
    explanation: modelRefused
      ? `The model recognized the adversarial intent and refused to comply.`
      : responseLength > 50
      ? `The model generated a response (${responseLength} characters).`
      : `The model provided a minimal or blocked response.`
  };
  
  // Determine overall outcome
  const outcome = {
    success: overallVulnerable,
    label: overallSafe ? '🛡️ Defended' : overallVulnerable ? '⚠️ Attack Succeeded' : '🔶 Partial Defense',
    explanation: overallSafe
      ? `All security layers worked together to prevent this attack. The AI system maintained its safety guidelines.`
      : overallVulnerable
      ? `The attack bypassed security controls and the model engaged with the malicious prompt.`
      : `Some security controls flagged the attack, but the defense was incomplete.`
  };
  
  // Generate summary narrative
  let summary = '';
  if (overallSafe) {
    summary = `A ${result.config.category.replace(/-/g, ' ')} attack was attempted against ${result.config.targetModel}. `;
    if (shieldBlocked) {
      summary += `Azure AI Content Safety intercepted the malicious prompt before it reached the model. `;
    } else if (modelRefused) {
      summary += `The model's built-in safety training caused it to refuse the harmful request. `;
    }
    summary += `This demonstrates effective defense-in-depth.`;
  } else if (overallVulnerable) {
    summary = `A ${result.config.category.replace(/-/g, ' ')} attack successfully bypassed security controls. `;
    summary += `The ${result.config.targetModel} model engaged with the adversarial prompt`;
    summary += result.config.shieldEnabled 
      ? `, even with Content Safety enabled. This highlights a gap in current protections.`
      : `. Note: Content Safety was disabled for this test run.`;
  } else {
    summary = `The attack produced a mixed result. Some security layers flagged the content, but the response requires review.`;
  }
  
  return { summary, promptAdversarial, safetyIntervened, modelAnswered, outcome };
}

export default function AttackConsole() {
  const [category, setCategory] = useState<AttackCategory>('jailbreak');
  const [scenarioId, setScenarioId] = useState(mockScenarios[0].id);
  const [targetModel, setTargetModel] = useState('gpt-4o');
  const [shieldEnabled, setShieldEnabled] = useState(true);
  const [isRunning, setIsRunning] = useState(false);
  const [isRunningCampaign, setIsRunningCampaign] = useState(false);
  const [result, setResult] = useState<AttackResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [campaignSummary, setCampaignSummary] = useState<CampaignSummary | null>(null);

  const scenarios = getScenariosByCategory(category);
  const selectedScenario = mockScenarios.find(s => s.id === scenarioId);
  const selectedCategory = attackCategories.find(c => c.value === category);

  // Update scenario when category changes
  useEffect(() => {
    const newScenarios = getScenariosByCategory(category);
    if (newScenarios.length > 0) {
      setScenarioId(newScenarios[0].id);
    }
  }, [category]);

  const handleRunAttack = async () => {
    setIsRunning(true);
    setError(null);
    setResult(null);

    try {
      const apiResult = await runAttack({
        scenarioId,
        targetModel,
        shieldEnabled,
      });
      
      const frontendResult = convertApiResult(apiResult, selectedScenario || mockScenarios[0]);
      setResult(frontendResult);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(`API Error (${err.status}): ${err.message}`);
      } else {
        setError('Failed to connect to backend. Is the server running on port 8000?');
      }
      console.error('Attack error:', err);
    } finally {
      setIsRunning(false);
    }
  };

  const handleRunCampaign = async () => {
    setIsRunningCampaign(true);
    setError(null);

    try {
      const scenarioIds = scenarios.map(s => s.id);
      const campaignResult = await runCampaign({
        name: `${selectedCategory?.label || category} Campaign`,
        scenarioIds,
        targetModel,
        shieldEnabled,
      });
      
      setCampaignSummary({ campaign: campaignResult, isVisible: true });
    } catch (err) {
      if (err instanceof ApiError) {
        setError(`Campaign Error (${err.status}): ${err.message}`);
      } else {
        setError('Failed to run campaign. Is the server running?');
      }
      console.error('Campaign error:', err);
    } finally {
      setIsRunningCampaign(false);
    }
  };

  const severityColors = {
    low: 'text-blue-400 bg-blue-400/20 border-blue-400/30',
    medium: 'text-warning-500 bg-warning-500/20 border-warning-500/30',
    high: 'text-orange-500 bg-orange-500/20 border-orange-500/30',
    critical: 'text-danger-500 bg-danger-500/20 border-danger-500/30',
  };

  // Create category options with icons
  const categoryOptions = attackCategories.map(c => ({
    value: c.value,
    label: `${c.icon} ${c.label}`
  }));

  return (
    <div className="grid grid-cols-12 gap-4 h-[calc(100vh-180px)]">
      {/* Left Panel - Attack Configuration */}
      <div className="col-span-3">
        <Panel 
          title="Attack Configuration" 
          subtitle="Configure your attack parameters"
          icon={<Settings className="w-4 h-4" />}
          className="h-full"
        >
          <div className="space-y-4 overflow-y-auto">
            {/* Attack Category */}
            <Select
              label="Attack Category"
              value={category}
              onChange={(v) => setCategory(v as AttackCategory)}
              options={categoryOptions}
            />

            {/* Category Description */}
            {selectedCategory && (
              <div className="p-2 bg-azure-500/10 border border-azure-500/30 rounded-lg">
                <p className="text-xs text-azure-300">
                  {selectedCategory.description}
                </p>
              </div>
            )}

            {/* Scenario */}
            <Select
              label="Scenario"
              value={scenarioId}
              onChange={setScenarioId}
              options={scenarios.map(s => ({ value: s.id, label: s.name }))}
            />

            {/* Scenario Details Card */}
            {selectedScenario && (
              <div className="space-y-3">
                {/* Severity & Description */}
                <div className="p-3 bg-slate-800/50 rounded-lg border border-slate-700/50">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-medium text-slate-400">Scenario Details</span>
                    <span className={`text-xs px-2 py-0.5 rounded-full font-medium border ${severityColors[selectedScenario.severity]}`}>
                      {selectedScenario.severity.toUpperCase()}
                    </span>
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed">
                    {selectedScenario.description}
                  </p>
                </div>

                {/* Expected Behavior */}
                <div className="p-3 bg-success-500/10 border border-success-500/30 rounded-lg">
                  <div className="flex items-center gap-1.5 mb-1.5">
                    <Target className="w-3.5 h-3.5 text-success-500" />
                    <span className="text-xs font-medium text-success-400">Expected Security Behavior</span>
                  </div>
                  <p className="text-xs text-success-300/90 leading-relaxed">
                    {selectedScenario.expectedBehavior}
                  </p>
                </div>

                {/* Narrator Notes */}
                <div className="p-3 bg-purple-500/10 border border-purple-500/30 rounded-lg">
                  <div className="flex items-center gap-1.5 mb-1.5">
                    <Lightbulb className="w-3.5 h-3.5 text-purple-400" />
                    <span className="text-xs font-medium text-purple-400">Demo Narrator Notes</span>
                  </div>
                  <p className="text-xs text-purple-300/90 leading-relaxed italic">
                    "{selectedScenario.narratorNotes}"
                  </p>
                </div>
              </div>
            )}

            {/* Target Model */}
            <Select
              label="Target Model"
              value={targetModel}
              onChange={setTargetModel}
              options={targetModels}
            />

            {/* Shield Toggle */}
            <div className="pt-2 border-t border-slate-700/50">
              <Toggle
                enabled={shieldEnabled}
                onChange={setShieldEnabled}
                label="Azure AI Content Safety"
                description="Enable content safety shield"
              />
            </div>

            {/* Action Buttons */}
            <div className="space-y-3 pt-4">
              <button 
                onClick={handleRunAttack}
                disabled={isRunning || isRunningCampaign}
                className="btn-danger w-full flex items-center justify-center gap-2"
              >
                {isRunning ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Running Attack...
                  </>
                ) : (
                  <>
                    <Play className="w-4 h-4" />
                    Run Single Attack
                  </>
                )}
              </button>
              <button 
                onClick={handleRunCampaign}
                disabled={isRunning || isRunningCampaign}
                className="btn-secondary w-full flex items-center justify-center gap-2"
              >
                {isRunningCampaign ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Running {scenarios.length} Attacks...
                  </>
                ) : (
                  <>
                    <Rocket className="w-4 h-4" />
                    Run Campaign ({scenarios.length})
                  </>
                )}
              </button>
            </div>

            {/* Error Display */}
            {error && (
              <div className="p-3 bg-danger-500/20 border border-danger-500/50 rounded-lg">
                <div className="flex items-start gap-2">
                  <AlertCircle className="w-4 h-4 text-danger-500 mt-0.5 flex-shrink-0" />
                  <div>
                    <p className="text-sm text-danger-400 font-medium">Error</p>
                    <p className="text-xs text-danger-300/80 mt-1">{error}</p>
                  </div>
                </div>
              </div>
            )}
          </div>
        </Panel>
      </div>

      {/* Center Panel - Prompt & Response */}
      <div className="col-span-5">
        <Panel 
          title="Attack Execution" 
          subtitle="Prompt and model response"
          icon={<MessageSquare className="w-4 h-4" />}
          className="h-full"
          headerAction={
            result && (
              <StatusBadge status={result.status} size="sm" />
            )
          }
        >
          <div className="space-y-4 h-full overflow-y-auto">
            {/* Scenario Header */}
            {selectedScenario && (
              <div className="flex items-center gap-2 p-2 bg-slate-800/30 rounded-lg border border-slate-700/30">
                <span className="text-lg">{selectedCategory?.icon}</span>
                <div>
                  <span className="text-sm font-medium text-white">{selectedScenario.name}</span>
                  <span className="text-xs text-slate-500 ml-2">({selectedCategory?.label})</span>
                </div>
              </div>
            )}

            {/* Attack Prompt */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <label className="text-xs font-medium text-danger-400 uppercase tracking-wide flex items-center gap-1">
                  <AlertCircle className="w-3 h-3" />
                  Attack Prompt (Auto-populated)
                </label>
                <button 
                  className="text-slate-500 hover:text-white transition-colors"
                  onClick={() => navigator.clipboard.writeText(selectedScenario?.prompt || '')}
                >
                  <Copy className="w-3.5 h-3.5" />
                </button>
              </div>
              <div className="p-3 bg-danger-500/10 border border-danger-500/30 rounded-lg max-h-[200px] overflow-y-auto">
                <pre className="text-sm text-slate-200 font-mono leading-relaxed whitespace-pre-wrap">
                  {selectedScenario?.prompt || 'Select a scenario to view the attack prompt'}
                </pre>
              </div>
            </div>

            {/* Normalized Prompt */}
            <div>
              <label className="text-xs font-medium text-slate-400 uppercase tracking-wide mb-2 flex items-center gap-1">
                <Shield className="w-3 h-3" />
                Normalized Prompt
              </label>
              <div className="p-3 bg-slate-800/50 border border-slate-700/50 rounded-lg">
                <p className="text-sm text-slate-400 font-mono leading-relaxed">
                  {result?.normalizedPrompt || 'Normalized prompt will appear here after execution'}
                </p>
              </div>
            </div>

            {/* Model Response */}
            <div className="flex-1">
              <div className="flex items-center justify-between mb-2">
                <label className="text-xs font-medium text-slate-400 uppercase tracking-wide flex items-center gap-1">
                  <Bot className="w-3 h-3" />
                  Model Response
                </label>
                {result && (
                  <span className="text-xs text-slate-500">
                    {result.latencyMs}ms · {result.tokensUsed} tokens
                  </span>
                )}
              </div>
              <div className={`p-3 rounded-lg border min-h-[120px] ${
                result?.status === 'blocked' 
                  ? 'bg-success-500/10 border-success-500/30' 
                  : result?.status === 'passed'
                  ? 'bg-danger-500/10 border-danger-500/30'
                  : 'bg-slate-800/50 border-slate-700/50'
              }`}>
                <p className="text-sm text-slate-200 leading-relaxed">
                  {result?.response || 'Model response will appear here after execution'}
                </p>
              </div>
            </div>

            {/* Quick Stats */}
            {result && (
              <div className="flex items-center gap-4 pt-2 border-t border-slate-700/50">
                <div className="flex items-center gap-2 text-xs text-slate-400">
                  <AlertCircle className="w-3.5 h-3.5" />
                  <span>Correlation ID: <span className="font-mono text-slate-300">{result.correlationId.slice(0, 8)}...</span></span>
                </div>
              </div>
            )}
          </div>
        </Panel>
      </div>

      {/* Right Panel - Verdicts & Evidence */}
      <div className="col-span-4">
        <Panel 
          title="Verdict & Evidence" 
          subtitle="Demo storytelling support"
          icon={<BookOpen className="w-4 h-4" />}
          className="h-full"
        >
          {result ? (
            <div className="space-y-4 h-full overflow-y-auto">
              {/* Narrative Summary - What Happened */}
              {(() => {
                const narrative = generateNarrative(result);
                return (
                  <>
                    {/* Overall Outcome Banner */}
                    <div className={`p-4 rounded-lg border ${
                      result.overallOutcome === 'safe' 
                        ? 'bg-success-500/10 border-success-500/30' 
                        : result.overallOutcome === 'vulnerable'
                        ? 'bg-danger-500/10 border-danger-500/30'
                        : 'bg-warning-500/10 border-warning-500/30'
                    }`}>
                      <div className="flex items-center gap-3 mb-2">
                        {result.overallOutcome === 'safe' ? (
                          <ShieldCheck className="w-6 h-6 text-success-500" />
                        ) : result.overallOutcome === 'vulnerable' ? (
                          <ShieldAlert className="w-6 h-6 text-danger-500" />
                        ) : (
                          <AlertTriangle className="w-6 h-6 text-warning-500" />
                        )}
                        <span className={`text-lg font-semibold ${
                          result.overallOutcome === 'safe' ? 'text-success-400' 
                          : result.overallOutcome === 'vulnerable' ? 'text-danger-400'
                          : 'text-warning-400'
                        }`}>
                          {narrative.outcome.label}
                        </span>
                      </div>
                      <p className="text-sm text-slate-300 leading-relaxed">
                        {narrative.summary}
                      </p>
                    </div>

                    {/* Quick Analysis Checklist */}
                    <div className="p-3 bg-slate-800/50 rounded-lg border border-slate-700/50">
                      <div className="flex items-center gap-2 mb-3">
                        <Eye className="w-4 h-4 text-azure-500" />
                        <span className="text-sm font-medium text-white">Quick Analysis</span>
                      </div>
                      <div className="space-y-2.5">
                        {/* Prompt Adversarial */}
                        <div className="flex items-start gap-2">
                          <div className={`w-5 h-5 rounded-full flex items-center justify-center flex-shrink-0 mt-0.5 ${
                            narrative.promptAdversarial.answer ? 'bg-danger-500/20' : 'bg-slate-700'
                          }`}>
                            {narrative.promptAdversarial.answer ? (
                              <AlertCircle className="w-3 h-3 text-danger-400" />
                            ) : (
                              <CheckCircle className="w-3 h-3 text-slate-400" />
                            )}
                          </div>
                          <div>
                            <span className="text-xs font-medium text-slate-300">Prompt looked adversarial?</span>
                            <p className="text-xs text-slate-500 mt-0.5">{narrative.promptAdversarial.explanation}</p>
                          </div>
                        </div>

                        {/* Safety Layer Intervened */}
                        <div className="flex items-start gap-2">
                          <div className={`w-5 h-5 rounded-full flex items-center justify-center flex-shrink-0 mt-0.5 ${
                            narrative.safetyIntervened.answer ? 'bg-success-500/20' : 'bg-danger-500/20'
                          }`}>
                            {narrative.safetyIntervened.answer ? (
                              <Shield className="w-3 h-3 text-success-400" />
                            ) : (
                              <X className="w-3 h-3 text-danger-400" />
                            )}
                          </div>
                          <div>
                            <span className="text-xs font-medium text-slate-300">Safety layer intervened?</span>
                            <p className="text-xs text-slate-500 mt-0.5">{narrative.safetyIntervened.explanation}</p>
                          </div>
                        </div>

                        {/* Model Still Answered */}
                        <div className="flex items-start gap-2">
                          <div className={`w-5 h-5 rounded-full flex items-center justify-center flex-shrink-0 mt-0.5 ${
                            narrative.modelAnswered.answer ? 'bg-warning-500/20' : 'bg-success-500/20'
                          }`}>
                            {narrative.modelAnswered.answer ? (
                              <Bot className="w-3 h-3 text-warning-400" />
                            ) : (
                              <CheckCircle className="w-3 h-3 text-success-400" />
                            )}
                          </div>
                          <div>
                            <span className="text-xs font-medium text-slate-300">Model still answered?</span>
                            <p className="text-xs text-slate-500 mt-0.5">{narrative.modelAnswered.explanation}</p>
                          </div>
                        </div>

                        {/* Attack Outcome */}
                        <div className="flex items-start gap-2 pt-2 border-t border-slate-700/50">
                          <div className={`w-5 h-5 rounded-full flex items-center justify-center flex-shrink-0 mt-0.5 ${
                            narrative.outcome.success ? 'bg-danger-500/20' : 'bg-success-500/20'
                          }`}>
                            {narrative.outcome.success ? (
                              <AlertTriangle className="w-3 h-3 text-danger-400" />
                            ) : (
                              <ShieldCheck className="w-3 h-3 text-success-400" />
                            )}
                          </div>
                          <div>
                            <span className="text-xs font-medium text-slate-300">Result classification</span>
                            <p className="text-xs text-slate-500 mt-0.5">{narrative.outcome.explanation}</p>
                          </div>
                        </div>
                      </div>
                    </div>
                  </>
                );
              })()}

              {/* Compact Verdict Summary */}
              <div className="grid grid-cols-3 gap-2">
                <div className={`p-2 rounded-lg text-center ${
                  result.verdicts.shield.result === 'blocked' ? 'bg-success-500/10 border border-success-500/30' : 'bg-slate-800/50 border border-slate-700/50'
                }`}>
                  <Shield className={`w-4 h-4 mx-auto mb-1 ${
                    result.verdicts.shield.result === 'blocked' ? 'text-success-400' : 'text-slate-500'
                  }`} />
                  <div className="text-xs font-medium text-slate-300">Shield</div>
                  <div className={`text-xs ${
                    result.verdicts.shield.result === 'blocked' ? 'text-success-400' : 'text-slate-500'
                  }`}>
                    {result.verdicts.shield.result}
                  </div>
                </div>
                <div className={`p-2 rounded-lg text-center ${
                  result.verdicts.model.result === 'blocked' ? 'bg-success-500/10 border border-success-500/30' : 'bg-slate-800/50 border border-slate-700/50'
                }`}>
                  <Bot className={`w-4 h-4 mx-auto mb-1 ${
                    result.verdicts.model.result === 'blocked' ? 'text-success-400' : 'text-slate-500'
                  }`} />
                  <div className="text-xs font-medium text-slate-300">Model</div>
                  <div className={`text-xs ${
                    result.verdicts.model.result === 'blocked' ? 'text-success-400' : 'text-slate-500'
                  }`}>
                    {result.verdicts.model.result}
                  </div>
                </div>
                <div className={`p-2 rounded-lg text-center ${
                  result.verdicts.evaluator.result === 'blocked' ? 'bg-success-500/10 border border-success-500/30' : 'bg-slate-800/50 border border-slate-700/50'
                }`}>
                  <Brain className={`w-4 h-4 mx-auto mb-1 ${
                    result.verdicts.evaluator.result === 'blocked' ? 'text-success-400' : 'text-slate-500'
                  }`} />
                  <div className="text-xs font-medium text-slate-300">Evaluator</div>
                  <div className={`text-xs ${
                    result.verdicts.evaluator.result === 'blocked' ? 'text-success-400' : 'text-slate-500'
                  }`}>
                    {result.verdicts.evaluator.result}
                  </div>
                </div>
              </div>

              {/* Foundry Context - Demo Traceability */}
              <div className="p-3 bg-azure-500/10 rounded-lg border border-azure-500/30">
                <div className="flex items-center gap-2 mb-2">
                  <Cloud className="w-4 h-4 text-azure-400" />
                  <span className="text-xs font-medium text-azure-400 uppercase tracking-wide">Azure AI Foundry Context</span>
                </div>
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-slate-400">Resource</span>
                    <code className="text-xs text-azure-300 font-mono bg-azure-500/10 px-1.5 py-0.5 rounded">
                      {result.foundryResourceName || 'mkhalib-4370-resource'}
                    </code>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-slate-400">Deployment</span>
                    <code className="text-xs text-azure-300 font-mono">{result.deploymentName || result.config.targetModel}</code>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-slate-400">Correlation ID</span>
                    <div className="flex items-center gap-1">
                      <code className="text-xs text-azure-300 font-mono">{result.correlationId.slice(0, 12)}...</code>
                      <button 
                        onClick={() => navigator.clipboard.writeText(result.correlationId)}
                        className="text-slate-500 hover:text-azure-400 transition-colors"
                        title="Copy full correlation ID"
                      >
                        <Copy className="w-3 h-3" />
                      </button>
                    </div>
                  </div>
                </div>
              </div>

              {/* Evidence Guidance Section */}
              <div className="p-3 bg-slate-800/30 rounded-lg border border-slate-700/50">
                <div className="flex items-center gap-2 mb-3">
                  <Search className="w-4 h-4 text-purple-400" />
                  <span className="text-xs font-medium text-purple-400 uppercase tracking-wide">Evidence & Investigation</span>
                </div>
                
                <div className="space-y-2">
                  {/* Foundry Monitoring */}
                  <a 
                    href="#" 
                    className="flex items-center justify-between p-2 bg-slate-800/50 rounded border border-slate-700/50 hover:border-purple-500/50 transition-colors group"
                  >
                    <div className="flex items-center gap-2">
                      <Activity className="w-3.5 h-3.5 text-purple-400" />
                      <div>
                        <span className="text-xs text-slate-300 group-hover:text-white">Foundry Monitoring</span>
                        <p className="text-[10px] text-slate-500">View model metrics & safety events</p>
                      </div>
                    </div>
                    <ExternalLink className="w-3.5 h-3.5 text-slate-600 group-hover:text-purple-400" />
                  </a>

                  {/* Application Insights */}
                  <a 
                    href="#" 
                    className="flex items-center justify-between p-2 bg-slate-800/50 rounded border border-slate-700/50 hover:border-purple-500/50 transition-colors group"
                  >
                    <div className="flex items-center gap-2">
                      <FileText className="w-3.5 h-3.5 text-purple-400" />
                      <div>
                        <span className="text-xs text-slate-300 group-hover:text-white">Application Insights Trace</span>
                        <p className="text-[10px] text-slate-500">End-to-end request telemetry</p>
                      </div>
                    </div>
                    <ExternalLink className="w-3.5 h-3.5 text-slate-600 group-hover:text-purple-400" />
                  </a>

                  {/* Defender Alert */}
                  <a 
                    href="#" 
                    className="flex items-center justify-between p-2 bg-slate-800/50 rounded border border-slate-700/50 hover:border-purple-500/50 transition-colors group"
                  >
                    <div className="flex items-center gap-2">
                      <ShieldAlert className="w-3.5 h-3.5 text-purple-400" />
                      <div>
                        <span className="text-xs text-slate-300 group-hover:text-white">Defender for AI Alert</span>
                        <p className="text-[10px] text-slate-500">Security incident correlation</p>
                      </div>
                    </div>
                    <ExternalLink className="w-3.5 h-3.5 text-slate-600 group-hover:text-purple-400" />
                  </a>
                </div>

                {/* Resource Context Footer */}
                <div className="mt-3 pt-2 border-t border-slate-700/30">
                  <div className="flex items-center justify-between text-[10px]">
                    <div className="flex items-center gap-1.5 text-slate-500">
                      <Fingerprint className="w-3 h-3" />
                      <span>Trace ID: {result.correlationId.slice(0, 8)}</span>
                    </div>
                    <div className="flex items-center gap-1.5 text-slate-500">
                      <Server className="w-3 h-3" />
                      <span>{result.foundryResourceName || 'mkhalib-4370-resource'}</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="h-full flex items-center justify-center">
              <div className="text-center">
                <BookOpen className="w-12 h-12 text-slate-700 mx-auto mb-3" />
                <p className="text-slate-500 text-sm">Run an attack to see verdicts</p>
                <p className="text-slate-600 text-xs mt-1">Plain-English analysis for demo narration</p>
              </div>
            </div>
          )}
        </Panel>
      </div>

      {/* Campaign Summary Modal */}
      {campaignSummary?.isVisible && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50">
          <div className="bg-slate-900 border border-slate-700 rounded-xl shadow-2xl w-full max-w-lg mx-4">
            {/* Modal Header */}
            <div className="flex items-center justify-between p-4 border-b border-slate-700">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-lg bg-azure-500/20 flex items-center justify-center">
                  <Rocket className="w-5 h-5 text-azure-500" />
                </div>
                <div>
                  <h3 className="text-lg font-semibold text-white">Campaign Complete</h3>
                  <p className="text-sm text-slate-400">{campaignSummary.campaign.name}</p>
                </div>
              </div>
              <button 
                onClick={() => setCampaignSummary(null)}
                className="p-1 text-slate-400 hover:text-white transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-4 space-y-4">
              {/* Stats Grid */}
              <div className="grid grid-cols-4 gap-3">
                <div className="p-3 bg-slate-800/50 rounded-lg text-center">
                  <div className="text-2xl font-bold text-white">{campaignSummary.campaign.total_attacks}</div>
                  <div className="text-xs text-slate-500">Total</div>
                </div>
                <div className="p-3 bg-success-500/10 border border-success-500/30 rounded-lg text-center">
                  <div className="flex items-center justify-center gap-1">
                    <ShieldCheck className="w-4 h-4 text-success-500" />
                    <span className="text-2xl font-bold text-success-500">{campaignSummary.campaign.blocked_count}</span>
                  </div>
                  <div className="text-xs text-success-500/70">Blocked</div>
                </div>
                <div className="p-3 bg-danger-500/10 border border-danger-500/30 rounded-lg text-center">
                  <div className="flex items-center justify-center gap-1">
                    <ShieldAlert className="w-4 h-4 text-danger-500" />
                    <span className="text-2xl font-bold text-danger-500">{campaignSummary.campaign.passed_count}</span>
                  </div>
                  <div className="text-xs text-danger-500/70">Passed</div>
                </div>
                <div className="p-3 bg-warning-500/10 border border-warning-500/30 rounded-lg text-center">
                  <div className="flex items-center justify-center gap-1">
                    <AlertTriangle className="w-4 h-4 text-warning-500" />
                    <span className="text-2xl font-bold text-warning-500">{campaignSummary.campaign.flagged_count}</span>
                  </div>
                  <div className="text-xs text-warning-500/70">Flagged</div>
                </div>
              </div>

              {/* Block Rate */}
              <div className="p-4 bg-slate-800/50 rounded-lg">
                <div className="flex justify-between text-sm mb-2">
                  <span className="text-slate-400">Block Rate</span>
                  <span className="text-success-500 font-semibold">
                    {campaignSummary.campaign.total_attacks > 0 
                      ? Math.round((campaignSummary.campaign.blocked_count / campaignSummary.campaign.total_attacks) * 100)
                      : 0}%
                  </span>
                </div>
                <div className="h-2 bg-slate-700 rounded-full overflow-hidden">
                  <div 
                    className="h-full bg-gradient-to-r from-success-500 to-success-600 rounded-full transition-all duration-500"
                    style={{ 
                      width: `${campaignSummary.campaign.total_attacks > 0 
                        ? (campaignSummary.campaign.blocked_count / campaignSummary.campaign.total_attacks) * 100 
                        : 0}%` 
                    }}
                  />
                </div>
              </div>

              {/* Campaign Details */}
              <div className="flex items-center justify-between text-xs text-slate-500">
                <span>Target: {campaignSummary.campaign.target_name}</span>
                <span>Shield: {campaignSummary.campaign.shield_enabled ? 'Enabled' : 'Disabled'}</span>
              </div>

              {/* Campaign ID */}
              <div className="p-2 bg-slate-800/30 rounded-lg flex items-center justify-between">
                <span className="text-xs text-slate-500">Campaign ID:</span>
                <code className="text-xs text-azure-400 font-mono">{campaignSummary.campaign.campaign_id.slice(0, 8)}...</code>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="p-4 border-t border-slate-700 flex gap-3">
              <button 
                onClick={() => setCampaignSummary(null)}
                className="btn-primary flex-1"
              >
                View in History
              </button>
              <button 
                onClick={() => setCampaignSummary(null)}
                className="btn-secondary flex-1"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
