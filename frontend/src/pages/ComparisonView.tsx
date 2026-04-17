import { useState, useEffect } from 'react';
import { 
  GitCompare, 
  Shield, 
  ShieldOff, 
  Play,
  Clock,
  Zap,
  AlertCircle,
  CheckCircle,
  XCircle,
  Target,
  Lightbulb,
  Server,
  Cloud,
  Loader2,
  TrendingUp,
  TrendingDown,
  Activity
} from 'lucide-react';
import Panel from '../components/Panel';
import Select from '../components/Select';
import StatusBadge from '../components/StatusBadge';
import { 
  runComparison, 
  getComparisonConfig,
  getScenarios,
  ApiComparisonResult,
  ApiComparisonConfig,
  ApiScenario,
  ApiError
} from '../services/api';

export default function ComparisonView() {
  // Configuration state
  const [config, setConfig] = useState<ApiComparisonConfig | null>(null);
  const [scenarios, setScenarios] = useState<ApiScenario[]>([]);
  const [category, setCategory] = useState<string>('jailbreak');
  const [scenarioId, setScenarioId] = useState<string>('');
  
  // Execution state
  const [isRunning, setIsRunning] = useState(false);
  const [result, setResult] = useState<ApiComparisonResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  
  // Load config and scenarios on mount
  useEffect(() => {
    loadConfig();
    loadScenarios();
  }, []);

  // Filter scenarios when category changes
  useEffect(() => {
    const filtered = scenarios.filter(s => s.category === category);
    if (filtered.length > 0 && !filtered.find(s => s.id === scenarioId)) {
      setScenarioId(filtered[0].id);
    }
  }, [category, scenarios]);

  const loadConfig = async () => {
    try {
      const configData = await getComparisonConfig();
      setConfig(configData);
    } catch (err) {
      console.error('Failed to load comparison config:', err);
    }
  };

  const loadScenarios = async () => {
    try {
      const scenarioData = await getScenarios();
      setScenarios(scenarioData);
      if (scenarioData.length > 0) {
        const jailbreakScenarios = scenarioData.filter(s => s.category === 'jailbreak');
        if (jailbreakScenarios.length > 0) {
          setScenarioId(jailbreakScenarios[0].id);
        } else {
          setScenarioId(scenarioData[0].id);
        }
      }
    } catch (err) {
      console.error('Failed to load scenarios:', err);
    }
  };

  const handleRunComparison = async () => {
    setIsRunning(true);
    setError(null);
    
    try {
      const comparisonResult = await runComparison({
        scenarioId,
        baselineShieldEnabled: false,
        guardedShieldEnabled: true,
      });
      setResult(comparisonResult);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(`Comparison failed (${err.status}): ${err.message}`);
      } else {
        setError('Failed to run comparison. Is the backend running?');
      }
      console.error('Comparison error:', err);
    } finally {
      setIsRunning(false);
    }
  };

  const selectedScenario = scenarios.find(s => s.id === scenarioId);
  const filteredScenarios = scenarios.filter(s => s.category === category);
  
  // Get unique categories  
  const categories = [...new Set(scenarios.map(s => s.category))];
  const categoryOptions = categories.map(c => ({
    value: c,
    label: c.split('-').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ')
  }));

  const getStatusFromOutcome = (outcome: string): 'blocked' | 'passed' | 'flagged' => {
    switch (outcome) {
      case 'safe': return 'blocked';
      case 'vulnerable': return 'passed';
      case 'partial': return 'flagged';
      default: return 'blocked';
    }
  };

  return (
    <div className="space-y-4 h-[calc(100vh-180px)] overflow-y-auto">
      {/* Foundry Context Header */}
      {config && (
        <div className="glass-panel p-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="w-10 h-10 rounded-lg bg-azure-500/20 flex items-center justify-center">
                <Cloud className="w-5 h-5 text-azure-400" />
              </div>
              <div>
                <h2 className="text-lg font-semibold text-white flex items-center gap-2">
                  Comparison Mode
                  <span className={`text-xs px-2 py-0.5 rounded ${
                    config.is_same_resource 
                      ? 'bg-azure-500/20 text-azure-400' 
                      : 'bg-purple-500/20 text-purple-400'
                  }`}>
                    {config.is_same_resource ? 'Same Resource' : 'Different Environments'}
                  </span>
                </h2>
                <p className="text-sm text-slate-400">
                  Azure AI Foundry: <span className="text-azure-400 font-medium">{config.foundry_resource_name}</span>
                </p>
              </div>
            </div>
            <div className="flex items-center gap-6 text-sm">
              <div className="text-center">
                <div className="text-slate-500">Baseline</div>
                <div className="text-white font-medium">{config.baseline.deployment_name}</div>
                <div className={`text-xs ${config.baseline.shield_enabled ? 'text-success-400' : 'text-slate-500'}`}>
                  Shield: {config.baseline.shield_enabled ? 'On' : 'Off'}
                </div>
              </div>
              <div className="text-2xl text-slate-600">vs</div>
              <div className="text-center">
                <div className="text-slate-500">Guarded</div>
                <div className="text-white font-medium">{config.guarded.deployment_name}</div>
                <div className={`text-xs ${config.guarded.shield_enabled ? 'text-success-400' : 'text-slate-500'}`}>
                  Shield: {config.guarded.shield_enabled ? 'On' : 'Off'}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Configuration Bar */}
      <div className="glass-panel p-4">
        <div className="flex items-center gap-6">
          <div className="flex items-center gap-2 text-azure-500">
            <GitCompare className="w-5 h-5" />
            <span className="font-medium text-white">Attack Selection</span>
          </div>
          
          <div className="flex-1 grid grid-cols-3 gap-4">
            <Select
              label=""
              value={category}
              onChange={setCategory}
              options={categoryOptions}
            />
            <Select
              label=""
              value={scenarioId}
              onChange={setScenarioId}
              options={filteredScenarios.map(s => ({ value: s.id, label: s.name }))}
            />
            <button 
              onClick={handleRunComparison}
              disabled={isRunning || !scenarioId}
              className="btn-primary flex items-center justify-center gap-2"
            >
              {isRunning ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Running...
                </>
              ) : (
                <>
                  <Play className="w-4 h-4" />
                  Run Comparison
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Error Display */}
      {error && (
        <div className="glass-panel p-4 bg-danger-500/10 border border-danger-500/30">
          <div className="flex items-center gap-2 text-danger-500">
            <AlertCircle className="w-5 h-5" />
            <span>{error}</span>
          </div>
        </div>
      )}

      {/* Attack Prompt & Expected Behavior */}
      <div className="glass-panel p-4">
        <div className="grid grid-cols-2 gap-4">
          {/* Prompt */}
          <div>
            <div className="flex items-center gap-2 mb-2">
              <AlertCircle className="w-4 h-4 text-danger-500" />
              <span className="text-sm font-medium text-white">Attack Prompt</span>
              {selectedScenario && (
                <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${
                  selectedScenario.severity === 'critical' ? 'text-danger-500 bg-danger-500/20' :
                  selectedScenario.severity === 'high' ? 'text-orange-500 bg-orange-500/20' :
                  'text-warning-500 bg-warning-500/20'
                }`}>
                  {selectedScenario.severity.toUpperCase()}
                </span>
              )}
            </div>
            <div className="p-3 bg-danger-500/10 border border-danger-500/30 rounded-lg max-h-[120px] overflow-y-auto">
              <pre className="text-sm text-slate-200 font-mono whitespace-pre-wrap">
                {selectedScenario?.prompt || 'Select a scenario to view the attack prompt'}
              </pre>
            </div>
          </div>

          {/* Expected Behavior */}
          <div>
            <div className="flex items-center gap-2 mb-2">
              <Target className="w-4 h-4 text-success-500" />
              <span className="text-sm font-medium text-white">Expected Security Behavior</span>
            </div>
            <div className="p-3 bg-success-500/10 border border-success-500/30 rounded-lg h-[120px] overflow-y-auto">
              <p className="text-sm text-success-300">
                {selectedScenario?.expected_defense || 'Expected behavior will appear here'}
              </p>
              {selectedScenario?.narrator_notes && (
                <div className="mt-2 pt-2 border-t border-success-500/20">
                  <p className="text-xs text-slate-400 italic flex items-start gap-1">
                    <Lightbulb className="w-3 h-3 mt-0.5 text-purple-400 flex-shrink-0" />
                    {selectedScenario.narrator_notes}
                  </p>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Comparison Summary (shown when result exists) */}
      {result && (
        <div className="glass-panel p-4">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-medium text-white flex items-center gap-2">
              <Activity className="w-4 h-4 text-azure-500" />
              Comparison Summary
            </h3>
            <span className="text-xs text-slate-500">
              {result.comparison_type.replace(/_/g, ' ')}
            </span>
          </div>
          <div className="grid grid-cols-4 gap-4">
            <div className="text-center p-3 bg-slate-800/50 rounded-lg">
              <div className="text-xs text-slate-500 mb-1">Shield Effectiveness</div>
              <div className={`text-sm font-medium ${
                !result.guarded_attack_success && result.baseline_attack_success 
                  ? 'text-success-500' 
                  : 'text-slate-400'
              }`}>
                {result.shield_effectiveness.split(' ').slice(0, 4).join(' ')}...
              </div>
            </div>
            <div className="text-center p-3 bg-slate-800/50 rounded-lg">
              <div className="text-xs text-slate-500 mb-1">Latency Difference</div>
              <div className={`text-sm font-medium flex items-center justify-center gap-1 ${
                result.latency_difference_ms > 0 ? 'text-warning-500' : 'text-success-500'
              }`}>
                {result.latency_difference_ms > 0 ? <TrendingUp className="w-3 h-3" /> : <TrendingDown className="w-3 h-3" />}
                {result.latency_difference_ms > 0 ? '+' : ''}{result.latency_difference_ms}ms
              </div>
            </div>
            <div className="text-center p-3 bg-slate-800/50 rounded-lg">
              <div className="text-xs text-slate-500 mb-1">Baseline Result</div>
              <div className={`text-sm font-medium ${result.baseline_attack_success ? 'text-danger-500' : 'text-success-500'}`}>
                {result.baseline_attack_success ? 'Attack Succeeded' : 'Blocked'}
              </div>
            </div>
            <div className="text-center p-3 bg-slate-800/50 rounded-lg">
              <div className="text-xs text-slate-500 mb-1">Guarded Result</div>
              <div className={`text-sm font-medium ${result.guarded_attack_success ? 'text-danger-500' : 'text-success-500'}`}>
                {result.guarded_attack_success ? 'Attack Succeeded' : 'Blocked'}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Side by Side Comparison */}
      <div className="grid grid-cols-2 gap-4 flex-1">
        {/* Baseline (No Shield) */}
        <Panel 
          title="Baseline Response"
          subtitle={result ? `${result.baseline.deployment_name} â€¢ Shield ${result.baseline.shield_enabled ? 'On' : 'Off'}` : 'Without Azure AI Content Safety'}
          icon={<ShieldOff className="w-4 h-4 text-slate-500" />}
          className="h-full"
          headerAction={
            result && <StatusBadge status={getStatusFromOutcome(result.baseline.outcome)} />
          }
        >
          {result ? (
            <div className="space-y-4">
              {/* Deployment Info */}
              <div className="flex items-center gap-4 text-xs text-slate-500 pb-2 border-b border-slate-700/50">
                <div className="flex items-center gap-1">
                  <Server className="w-3 h-3" />
                  <span>{result.baseline.foundry_resource_name}</span>
                </div>
                <div className="flex items-center gap-1">
                  <Target className="w-3 h-3" />
                  <span>{result.baseline.deployment_name}</span>
                </div>
              </div>

              {/* Response */}
              <div className={`p-4 rounded-lg border min-h-[150px] max-h-[250px] overflow-y-auto ${
                result.baseline.outcome === 'vulnerable'
                  ? 'bg-danger-500/10 border-danger-500/30'
                  : 'bg-success-500/10 border-success-500/30'
              }`}>
                <p className="text-sm text-slate-200 leading-relaxed">
                  {result.baseline.response}
                </p>
              </div>

              {/* Verdicts */}
              <div className="grid grid-cols-3 gap-2">
                <div className={`p-2 rounded text-center ${
                  result.baseline.shield_verdict.result === 'blocked' ? 'bg-success-500/10' : 'bg-slate-800/50'
                }`}>
                  <div className="text-xs text-slate-500">Shield</div>
                  <div className={`text-sm font-medium ${
                    result.baseline.shield_verdict.result === 'blocked' ? 'text-success-500' : 'text-slate-400'
                  }`}>
                    {result.baseline.shield_verdict.result}
                  </div>
                </div>
                <div className={`p-2 rounded text-center ${
                  result.baseline.model_verdict.result === 'blocked' ? 'bg-success-500/10' : 'bg-slate-800/50'
                }`}>
                  <div className="text-xs text-slate-500">Model</div>
                  <div className={`text-sm font-medium ${
                    result.baseline.model_verdict.result === 'blocked' ? 'text-success-500' : 'text-slate-400'
                  }`}>
                    {result.baseline.model_verdict.result}
                  </div>
                </div>
                <div className={`p-2 rounded text-center ${
                  result.baseline.evaluator_verdict.result === 'blocked' ? 'bg-success-500/10' : 'bg-slate-800/50'
                }`}>
                  <div className="text-xs text-slate-500">Evaluator</div>
                  <div className={`text-sm font-medium ${
                    result.baseline.evaluator_verdict.result === 'blocked' ? 'text-success-500' : 'text-slate-400'
                  }`}>
                    {result.baseline.evaluator_verdict.result}
                  </div>
                </div>
              </div>

              {/* Outcome Explanation */}
              <div className={`p-3 rounded-lg flex items-start gap-3 ${
                result.baseline.outcome === 'vulnerable'
                  ? 'bg-danger-500/10 border border-danger-500/30'
                  : 'bg-success-500/10 border border-success-500/30'
              }`}>
                {result.baseline.outcome === 'vulnerable' ? (
                  <XCircle className="w-5 h-5 text-danger-500 flex-shrink-0 mt-0.5" />
                ) : (
                  <CheckCircle className="w-5 h-5 text-success-500 flex-shrink-0 mt-0.5" />
                )}
                <div>
                  <p className={`text-sm font-medium ${
                    result.baseline.outcome === 'vulnerable' ? 'text-danger-500' : 'text-success-500'
                  }`}>
                    {result.baseline.outcome === 'vulnerable' ? 'Attack Succeeded' : 'Attack Blocked'}
                  </p>
                  <p className="text-xs text-slate-400 mt-1">
                    {result.baseline.outcome === 'vulnerable'
                      ? 'The model engaged with the malicious prompt without content safety filtering'
                      : 'Model\'s built-in safety measures blocked the attack'
                    }
                  </p>
                </div>
              </div>

              {/* Stats */}
              <div className="flex items-center gap-4 pt-2 border-t border-slate-700/50">
                <div className="flex items-center gap-1.5 text-xs text-slate-400">
                  <Clock className="w-3.5 h-3.5" />
                  <span>{result.baseline.latency_ms}ms</span>
                </div>
                <div className="flex items-center gap-1.5 text-xs text-slate-400">
                  <Zap className="w-3.5 h-3.5" />
                  <span>{result.baseline.tokens_used || 'N/A'} tokens</span>
                </div>
              </div>
            </div>
          ) : (
            <div className="h-full flex items-center justify-center min-h-[300px]">
              <div className="text-center text-slate-500">
                <ShieldOff className="w-12 h-12 mx-auto mb-3 opacity-50" />
                <p>Run a comparison to see baseline results</p>
              </div>
            </div>
          )}
        </Panel>

        {/* Guarded (With Shield) */}
        <Panel 
          title="Guarded Response" 
          subtitle={result ? `${result.guarded.deployment_name} â€¢ Shield ${result.guarded.shield_enabled ? 'On' : 'Off'}` : 'With Azure AI Content Safety'}
          icon={<Shield className="w-4 h-4 text-azure-500" />}
          className="h-full"
          headerAction={
            result && <StatusBadge status={getStatusFromOutcome(result.guarded.outcome)} />
          }
        >
          {result ? (
            <div className="space-y-4">
              {/* Deployment Info */}
              <div className="flex items-center gap-4 text-xs text-slate-500 pb-2 border-b border-slate-700/50">
                <div className="flex items-center gap-1">
                  <Server className="w-3 h-3" />
                  <span>{result.guarded.foundry_resource_name}</span>
                </div>
                <div className="flex items-center gap-1">
                  <Target className="w-3 h-3" />
                  <span>{result.guarded.deployment_name}</span>
                </div>
              </div>

              {/* Shield Action */}
              <div className="p-3 bg-azure-500/10 border border-azure-500/30 rounded-lg">
                <div className="flex items-center gap-2 mb-1">
                  <Shield className="w-4 h-4 text-azure-500" />
                  <span className="text-xs font-medium text-azure-400 uppercase tracking-wide">
                    Shield Verdict
                  </span>
                </div>
                <p className="text-sm text-slate-300">
                  {result.guarded.shield_verdict.result === 'blocked' 
                    ? `Blocked with ${(result.guarded.shield_verdict.confidence * 100).toFixed(0)}% confidence`
                    : result.guarded.shield_verdict.result === 'allowed'
                    ? 'Allowed to proceed'
                    : 'Flagged for review'
                  }
                </p>
              </div>

              {/* Response */}
              <div className={`p-4 rounded-lg border min-h-[150px] max-h-[200px] overflow-y-auto ${
                result.guarded.outcome === 'safe'
                  ? 'bg-success-500/10 border-success-500/30'
                  : 'bg-danger-500/10 border-danger-500/30'
              }`}>
                <p className="text-sm text-slate-200 leading-relaxed">
                  {result.guarded.response}
                </p>
              </div>

              {/* Verdicts */}
              <div className="grid grid-cols-3 gap-2">
                <div className={`p-2 rounded text-center ${
                  result.guarded.shield_verdict.result === 'blocked' ? 'bg-success-500/10' : 'bg-slate-800/50'
                }`}>
                  <div className="text-xs text-slate-500">Shield</div>
                  <div className={`text-sm font-medium ${
                    result.guarded.shield_verdict.result === 'blocked' ? 'text-success-500' : 'text-slate-400'
                  }`}>
                    {result.guarded.shield_verdict.result}
                  </div>
                </div>
                <div className={`p-2 rounded text-center ${
                  result.guarded.model_verdict.result === 'blocked' ? 'bg-success-500/10' : 'bg-slate-800/50'
                }`}>
                  <div className="text-xs text-slate-500">Model</div>
                  <div className={`text-sm font-medium ${
                    result.guarded.model_verdict.result === 'blocked' ? 'text-success-500' : 'text-slate-400'
                  }`}>
                    {result.guarded.model_verdict.result}
                  </div>
                </div>
                <div className={`p-2 rounded text-center ${
                  result.guarded.evaluator_verdict.result === 'blocked' ? 'bg-success-500/10' : 'bg-slate-800/50'
                }`}>
                  <div className="text-xs text-slate-500">Evaluator</div>
                  <div className={`text-sm font-medium ${
                    result.guarded.evaluator_verdict.result === 'blocked' ? 'text-success-500' : 'text-slate-400'
                  }`}>
                    {result.guarded.evaluator_verdict.result}
                  </div>
                </div>
              </div>

              {/* Outcome Explanation */}
              <div className={`p-3 rounded-lg flex items-start gap-3 ${
                result.guarded.outcome === 'safe'
                  ? 'bg-success-500/10 border border-success-500/30'
                  : 'bg-danger-500/10 border border-danger-500/30'
              }`}>
                {result.guarded.outcome === 'safe' ? (
                  <CheckCircle className="w-5 h-5 text-success-500 flex-shrink-0 mt-0.5" />
                ) : (
                  <XCircle className="w-5 h-5 text-danger-500 flex-shrink-0 mt-0.5" />
                )}
                <div>
                  <p className={`text-sm font-medium ${
                    result.guarded.outcome === 'safe' ? 'text-success-500' : 'text-danger-500'
                  }`}>
                    {result.guarded.outcome === 'safe' ? 'Attack Blocked' : 'Attack Succeeded'}
                  </p>
                  <p className="text-xs text-slate-400 mt-1">
                    {result.guarded.outcome === 'safe'
                      ? 'Azure AI Content Safety detected and blocked the adversarial prompt'
                      : 'The attack bypassed content safety measures'
                    }
                  </p>
                </div>
              </div>

              {/* Stats */}
              <div className="flex items-center gap-4 pt-2 border-t border-slate-700/50">
                <div className="flex items-center gap-1.5 text-xs text-slate-400">
                  <Clock className="w-3.5 h-3.5" />
                  <span>{result.guarded.latency_ms}ms</span>
                </div>
                <div className="flex items-center gap-1.5 text-xs text-slate-400">
                  <Zap className="w-3.5 h-3.5" />
                  <span>{result.guarded.tokens_used || 'N/A'} tokens</span>
                </div>
                <div className="flex items-center gap-1.5 text-xs text-slate-400 ml-auto">
                  <span className={result.latency_difference_ms > 0 ? 'text-warning-400' : 'text-success-400'}>
                    {result.latency_difference_ms > 0 ? '+' : ''}{result.latency_difference_ms}ms overhead
                  </span>
                </div>
              </div>
            </div>
          ) : (
            <div className="h-full flex items-center justify-center min-h-[300px]">
              <div className="text-center text-slate-500">
                <Shield className="w-12 h-12 mx-auto mb-3 opacity-50" />
                <p>Run a comparison to see guarded results</p>
              </div>
            </div>
          )}
        </Panel>
      </div>
    </div>
  );
}
