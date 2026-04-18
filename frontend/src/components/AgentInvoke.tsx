import { useState } from 'react';
import { 
  Bot,
  Eye,
  Activity,
  FileText,
  BookOpen,
  Sparkles,
  Loader2,
  X,
  Clock,
  CheckCircle,
  AlertCircle,
  Copy,
  Fingerprint
} from 'lucide-react';
import { 
  invokeAgent, 
  ApiInvokeAgentResponse,
  ApiError 
} from '../services/api';

// Agent metadata
const agentMeta: Record<string, {
  name: string;
  icon: typeof Bot;
  color: { bg: string; border: string; text: string; glow: string };
  description: string;
}> = {
  attack_observer: {
    name: 'Attack Observer',
    icon: Eye,
    color: {
      bg: 'bg-cyan-500/10',
      border: 'border-cyan-500/30',
      text: 'text-cyan-400',
      glow: 'shadow-cyan-500/20',
    },
    description: 'Narrates what happened in plain language',
  },
  telemetry_analyst: {
    name: 'Telemetry Analyst',
    icon: Activity,
    color: {
      bg: 'bg-violet-500/10',
      border: 'border-violet-500/30',
      text: 'text-violet-400',
      glow: 'shadow-violet-500/20',
    },
    description: 'Analyzes patterns across runs',
  },
  policy_explainer: {
    name: 'Policy Explainer',
    icon: BookOpen,
    color: {
      bg: 'bg-amber-500/10',
      border: 'border-amber-500/30',
      text: 'text-amber-400',
      glow: 'shadow-amber-500/20',
    },
    description: 'Explains why content was blocked or allowed',
  },
  campaign_reporter: {
    name: 'Campaign Reporter',
    icon: FileText,
    color: {
      bg: 'bg-emerald-500/10',
      border: 'border-emerald-500/30',
      text: 'text-emerald-400',
      glow: 'shadow-emerald-500/20',
    },
    description: 'Generates an executive summary',
  },
};

// Props for inline invoke button
interface AgentInvokeButtonProps {
  agentType: keyof typeof agentMeta;
  runId?: string;
  campaignId?: string;
  size?: 'sm' | 'md';
  variant?: 'primary' | 'secondary' | 'ghost';
  onResult?: (result: ApiInvokeAgentResponse) => void;
}

export function AgentInvokeButton({
  agentType,
  runId,
  campaignId,
  size = 'sm',
  variant = 'secondary',
  onResult,
}: AgentInvokeButtonProps) {
  const [isInvoking, setIsInvoking] = useState(false);
  const [showResult, setShowResult] = useState(false);
  const [result, setResult] = useState<ApiInvokeAgentResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const meta = agentMeta[agentType];
  if (!meta) return null;

  const Icon = meta.icon;

  const handleInvoke = async () => {
    setIsInvoking(true);
    setError(null);

    try {
      const response = await invokeAgent(agentType, {
        linked_run_id: runId,
        linked_campaign_id: campaignId,
      });
      setResult(response);
      setShowResult(true);
      onResult?.(response);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(`Failed: ${err.message}`);
      } else {
        setError('Failed to invoke agent');
      }
    } finally {
      setIsInvoking(false);
    }
  };

  const sizeClasses = {
    sm: 'px-2.5 py-1.5 text-xs gap-1.5',
    md: 'px-3 py-2 text-sm gap-2',
  };

  const variantClasses = {
    primary: `bg-azure-500 hover:bg-azure-600 text-white shadow-lg shadow-azure-500/20`,
    secondary: `${meta.color.bg} ${meta.color.border} border ${meta.color.text} hover:bg-opacity-20`,
    ghost: `text-slate-400 hover:text-white hover:bg-slate-800`,
  };

  return (
    <>
      <button
        onClick={handleInvoke}
        disabled={isInvoking}
        className={`
          inline-flex items-center rounded-lg font-medium transition-all duration-200
          ${sizeClasses[size]}
          ${variantClasses[variant]}
          ${isInvoking ? 'opacity-75 cursor-wait' : ''}
        `}
        title={meta.description}
      >
        {isInvoking ? (
          <Loader2 className="w-3.5 h-3.5 animate-spin" />
        ) : (
          <Icon className="w-3.5 h-3.5" />
        )}
        <span>{isInvoking ? 'Analyzing...' : meta.name}</span>
      </button>

      {/* Error Toast */}
      {error && (
        <div className="fixed bottom-4 right-4 z-50 flex items-center gap-2 px-4 py-3 bg-danger-500/20 border border-danger-500/50 rounded-lg shadow-lg">
          <AlertCircle className="w-4 h-4 text-danger-400" />
          <span className="text-sm text-danger-300">{error}</span>
          <button onClick={() => setError(null)} className="text-danger-400 hover:text-danger-300">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Result Drawer */}
      {showResult && result && (
        <AgentResultDrawer
          result={result}
          onClose={() => setShowResult(false)}
        />
      )}
    </>
  );
}

// Props for the result drawer
interface AgentResultDrawerProps {
  result: ApiInvokeAgentResponse;
  onClose: () => void;
}

export function AgentResultDrawer({ result, onClose }: AgentResultDrawerProps) {
  const { invocation, output } = result;
  const meta = agentMeta[invocation.agent_type] || agentMeta.attack_observer;
  const Icon = meta.icon;

  const formatTime = (timestamp: string) => {
    const date = new Date(timestamp);
    return date.toLocaleTimeString('en-US', { 
      hour: '2-digit', 
      minute: '2-digit', 
      second: '2-digit' 
    });
  };

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex justify-end z-50">
      {/* Backdrop click to close */}
      <div className="absolute inset-0" onClick={onClose} />
      
      {/* Drawer */}
      <div className="relative w-full max-w-xl bg-slate-900 border-l border-slate-700 shadow-2xl flex flex-col animate-slide-in-right">
        {/* Header */}
        <div className={`px-6 py-4 ${meta.color.bg} border-b ${meta.color.border} shrink-0`}>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className={`w-10 h-10 rounded-lg ${meta.color.bg} border ${meta.color.border} flex items-center justify-center`}>
                <Icon className={`w-5 h-5 ${meta.color.text}`} />
              </div>
              <div>
                <h3 className="font-semibold text-white">{meta.name}</h3>
                <div className="flex items-center gap-2 text-xs text-slate-400">
                  <CheckCircle className="w-3.5 h-3.5 text-success-400" />
                  <span>Analysis Complete</span>
                  <span className="text-slate-600">•</span>
                  <span>{invocation.latency_ms}ms</span>
                </div>
              </div>
            </div>
            <button
              onClick={onClose}
              className="p-2 hover:bg-slate-800 rounded-lg transition-colors"
            >
              <X className="w-5 h-5 text-slate-400" />
            </button>
          </div>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-5">
          {/* Summary Card */}
          <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
            <div className="flex items-center gap-2 mb-2">
              <Sparkles className="w-4 h-4 text-azure-400" />
              <span className="text-sm font-medium text-white">Summary</span>
            </div>
            <p className="text-sm text-slate-300 leading-relaxed">
              {invocation.output_summary}
            </p>
          </div>

          {/* Structured Output Visualization */}
          {output && typeof output === 'object' && (
            <div className="space-y-3">
              <div className="flex items-center gap-2">
                <Bot className="w-4 h-4 text-slate-400" />
                <span className="text-sm font-medium text-slate-300">Analysis Details</span>
              </div>
              
              {/* Render key fields nicely */}
              {renderStructuredOutput(output)}
            </div>
          )}

          {/* Metadata Footer */}
          <div className="p-4 bg-slate-800/30 rounded-lg border border-slate-700/30 space-y-2">
            <div className="flex items-center justify-between text-xs">
              <div className="flex items-center gap-2 text-slate-500">
                <Clock className="w-3.5 h-3.5" />
                <span>Timestamp</span>
              </div>
              <span className="text-slate-400 font-mono">{formatTime(invocation.timestamp)}</span>
            </div>
            
            <div className="flex items-center justify-between text-xs">
              <div className="flex items-center gap-2 text-slate-500">
                <Fingerprint className="w-3.5 h-3.5" />
                <span>Correlation ID</span>
              </div>
              <div className="flex items-center gap-1">
                <code className="text-azure-400 font-mono">{invocation.correlation_id.slice(0, 12)}...</code>
                <button
                  onClick={() => navigator.clipboard.writeText(invocation.correlation_id)}
                  className="text-slate-500 hover:text-azure-400 transition-colors"
                >
                  <Copy className="w-3 h-3" />
                </button>
              </div>
            </div>

            {invocation.linked_run_id && (
              <div className="flex items-center justify-between text-xs">
                <span className="text-slate-500">Linked Run</span>
                <code className="text-slate-400 font-mono">{invocation.linked_run_id.slice(0, 12)}...</code>
              </div>
            )}

            {invocation.linked_campaign_id && (
              <div className="flex items-center justify-between text-xs">
                <span className="text-slate-500">Linked Campaign</span>
                <code className="text-slate-400 font-mono">{invocation.linked_campaign_id.slice(0, 12)}...</code>
              </div>
            )}

            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-500">Invocation ID</span>
              <code className="text-slate-400 font-mono">{invocation.invocation_id.slice(0, 12)}...</code>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-slate-700 bg-slate-900/80 shrink-0">
          <button onClick={onClose} className="btn-primary w-full">
            Done
          </button>
        </div>
      </div>
    </div>
  );
}

// Helper to render structured output nicely
function renderStructuredOutput(output: Record<string, unknown>) {
  // Special handling for known output types
  const sections: JSX.Element[] = [];

  // Render string fields as cards
  Object.entries(output).forEach(([key, value]) => {
    if (typeof value === 'string' && value.length > 0) {
      const label = key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
      sections.push(
        <div key={key} className="p-3 bg-slate-800/30 rounded-lg border border-slate-700/30">
          <div className="text-xs font-medium text-slate-500 uppercase tracking-wide mb-1">{label}</div>
          <p className="text-sm text-slate-300 leading-relaxed">{value as string}</p>
        </div>
      );
    }
  });

  // Render arrays as lists
  Object.entries(output).forEach(([key, value]) => {
    if (Array.isArray(value) && value.length > 0) {
      const label = key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
      sections.push(
        <div key={key} className="p-3 bg-slate-800/30 rounded-lg border border-slate-700/30">
          <div className="text-xs font-medium text-slate-500 uppercase tracking-wide mb-2">{label}</div>
          <ul className="space-y-1">
            {(value as unknown[]).slice(0, 10).map((item, idx) => (
              <li key={idx} className="text-sm text-slate-300 flex items-start gap-2">
                <span className="text-azure-400 mt-1">•</span>
                <span>{typeof item === 'object' ? JSON.stringify(item) : String(item)}</span>
              </li>
            ))}
          </ul>
        </div>
      );
    }
  });

  // Render nested objects as JSON
  Object.entries(output).forEach(([key, value]) => {
    if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
      const label = key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
      sections.push(
        <div key={key} className="p-3 bg-slate-800/30 rounded-lg border border-slate-700/30">
          <div className="text-xs font-medium text-slate-500 uppercase tracking-wide mb-2">{label}</div>
          <pre className="text-xs text-slate-400 font-mono overflow-x-auto">
            {JSON.stringify(value, null, 2)}
          </pre>
        </div>
      );
    }
  });

  // Render numbers inline
  const numberFields = Object.entries(output).filter(([_, v]) => typeof v === 'number');
  if (numberFields.length > 0) {
    sections.push(
      <div key="numbers" className="grid grid-cols-2 gap-2">
        {numberFields.map(([key, value]) => {
          const label = key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
          return (
            <div key={key} className="p-2 bg-slate-800/30 rounded border border-slate-700/30">
              <div className="text-[10px] text-slate-500 uppercase">{label}</div>
              <div className="text-sm font-medium text-white">{String(value)}</div>
            </div>
          );
        })}
      </div>
    );
  }

  if (sections.length === 0) {
    // Fallback to raw JSON
    sections.push(
      <div key="raw" className="p-3 bg-slate-950 rounded-lg overflow-x-auto">
        <pre className="text-xs text-slate-400 font-mono whitespace-pre-wrap">
          {JSON.stringify(output, null, 2)}
        </pre>
      </div>
    );
  }

  return <div className="space-y-2">{sections}</div>;
}

// Re-export agentMeta for use elsewhere
export { agentMeta };
