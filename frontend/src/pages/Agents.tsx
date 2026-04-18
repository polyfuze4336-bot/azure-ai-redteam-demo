import { useState, useEffect } from 'react';
import { 
  Bot,
  Sparkles,
  Eye,
  Activity,
  FileText,
  BookOpen,
  Play,
  Clock,
  CheckCircle,
  AlertCircle,
  Loader2,
  RefreshCw,
  Zap,
  MessageSquare,
  X,
  History,
  ChevronRight,
  Fingerprint,
  Link2,
  Copy,
  ExternalLink
} from 'lucide-react';
import Panel from '../components/Panel';
import { 
  getAgents, 
  getInvocationSummary,
  getInvocations,
  invokeAgent,
  ApiAgentDefinition, 
  ApiInvocationSummary,
  ApiInvokeAgentResponse,
  ApiAgentInvocation,
  ApiError
} from '../services/api';

// Agent icon mapping
const agentIcons: Record<string, typeof Bot> = {
  attack_observer: Eye,
  telemetry_analyst: Activity,
  policy_explainer: BookOpen,
  campaign_reporter: FileText,
};

// Agent color mapping for visual distinction
const agentColors: Record<string, { bg: string; border: string; text: string; glow: string }> = {
  attack_observer: {
    bg: 'bg-cyan-500/10',
    border: 'border-cyan-500/30',
    text: 'text-cyan-400',
    glow: 'shadow-cyan-500/20',
  },
  telemetry_analyst: {
    bg: 'bg-violet-500/10',
    border: 'border-violet-500/30',
    text: 'text-violet-400',
    glow: 'shadow-violet-500/20',
  },
  policy_explainer: {
    bg: 'bg-amber-500/10',
    border: 'border-amber-500/30',
    text: 'text-amber-400',
    glow: 'shadow-amber-500/20',
  },
  campaign_reporter: {
    bg: 'bg-emerald-500/10',
    border: 'border-emerald-500/30',
    text: 'text-emerald-400',
    glow: 'shadow-emerald-500/20',
  },
};

// Status badge styles
const statusStyles: Record<string, { bg: string; text: string; dot: string }> = {
  active: {
    bg: 'bg-success-500/20',
    text: 'text-success-400',
    dot: 'bg-success-500',
  },
  inactive: {
    bg: 'bg-slate-500/20',
    text: 'text-slate-400',
    dot: 'bg-slate-500',
  },
  maintenance: {
    bg: 'bg-warning-500/20',
    text: 'text-warning-400',
    dot: 'bg-warning-500',
  },
};

function formatRelativeTime(dateString: string): string {
  const date = new Date(dateString);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);

  if (diffMins < 1) return 'Just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 7) return `${diffDays}d ago`;
  return date.toLocaleDateString();
}

interface AgentCardProps {
  agent: ApiAgentDefinition;
  invocationCount: number;
  lastInvocation: string | null;
  onInvoke: () => void;
  isInvoking: boolean;
}

function AgentCard({ agent, invocationCount, lastInvocation, onInvoke, isInvoking }: AgentCardProps) {
  const Icon = agentIcons[agent.agent_type] || Bot;
  const colors = agentColors[agent.agent_type] || agentColors.attack_observer;
  const status = statusStyles[agent.status] || statusStyles.inactive;

  return (
    <div className={`
      glass-panel p-6 
      hover:border-slate-600 hover:shadow-xl ${colors.glow}
      transition-all duration-300 group
    `}>
      {/* Header */}
      <div className="flex items-start justify-between mb-4">
        <div className={`
          w-12 h-12 rounded-xl ${colors.bg} ${colors.border} border
          flex items-center justify-center
          group-hover:scale-105 transition-transform duration-300
        `}>
          <Icon className={`w-6 h-6 ${colors.text}`} />
        </div>
        
        {/* Status Badge */}
        <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full ${status.bg}`}>
          <div className={`w-1.5 h-1.5 rounded-full ${status.dot} animate-pulse`} />
          <span className={`text-xs font-medium capitalize ${status.text}`}>
            {agent.status}
          </span>
        </div>
      </div>

      {/* Agent Name */}
      <h3 className="text-lg font-semibold text-white mb-1 group-hover:text-azure-400 transition-colors">
        {agent.agent_name}
      </h3>

      {/* Purpose */}
      <p className="text-sm text-slate-400 mb-4 leading-relaxed line-clamp-2">
        {agent.purpose}
      </p>

      {/* Input Types */}
      <div className="flex items-center gap-2 mb-4">
        <span className="text-xs text-slate-500">Accepts:</span>
        <div className="flex gap-1.5">
          {agent.supported_input_types.map((inputType) => (
            <span
              key={inputType}
              className="px-2 py-0.5 bg-slate-800 border border-slate-700 rounded text-xs text-slate-300 capitalize"
            >
              {inputType}
            </span>
          ))}
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 gap-3 mb-5">
        <div className="flex items-center gap-2 text-sm">
          <Zap className="w-4 h-4 text-azure-400" />
          <span className="text-slate-400">{invocationCount}</span>
          <span className="text-slate-500 text-xs">invocations</span>
        </div>
        <div className="flex items-center gap-2 text-sm">
          <Clock className="w-4 h-4 text-slate-500" />
          <span className="text-slate-400 text-xs">
            {lastInvocation ? formatRelativeTime(lastInvocation) : 'Never'}
          </span>
        </div>
      </div>

      {/* Invoke Button */}
      <button
        onClick={onInvoke}
        disabled={agent.status !== 'active' || isInvoking}
        className={`
          w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg
          font-medium text-sm transition-all duration-200
          ${agent.status === 'active'
            ? 'bg-azure-500 hover:bg-azure-600 text-white shadow-lg shadow-azure-500/20 hover:shadow-azure-500/40 active:scale-[0.98]'
            : 'bg-slate-800 text-slate-500 cursor-not-allowed'
          }
          ${isInvoking ? 'opacity-75' : ''}
        `}
      >
        {isInvoking ? (
          <>
            <Loader2 className="w-4 h-4 animate-spin" />
            Invoking...
          </>
        ) : (
          <>
            <Play className="w-4 h-4" />
            Invoke Agent
          </>
        )}
      </button>

      {/* Version Tag */}
      <div className="mt-4 pt-3 border-t border-slate-800 flex items-center justify-between">
        <span className="text-xs text-slate-600">v{agent.version}</span>
        <div className="flex gap-1">
          {agent.tags.slice(0, 2).map((tag) => (
            <span 
              key={tag} 
              className="px-1.5 py-0.5 bg-slate-800/50 rounded text-[10px] text-slate-500"
            >
              {tag}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}

// Invoke Modal Component
interface InvokeModalProps {
  agent: ApiAgentDefinition;
  onClose: () => void;
  onInvoke: (runId?: string, campaignId?: string) => void;
  isLoading: boolean;
}

function InvokeModal({ agent, onClose, onInvoke, isLoading }: InvokeModalProps) {
  const [runId, setRunId] = useState('');
  const [campaignId, setCampaignId] = useState('');
  const colors = agentColors[agent.agent_type] || agentColors.attack_observer;
  const Icon = agentIcons[agent.agent_type] || Bot;

  const canInvoke = runId.trim() || campaignId.trim();

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50">
      <div className="glass-panel w-full max-w-md mx-4 overflow-hidden">
        {/* Header */}
        <div className={`px-6 py-4 ${colors.bg} border-b ${colors.border}`}>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Icon className={`w-5 h-5 ${colors.text}`} />
              <div>
                <h3 className="font-semibold text-white">Run {agent.agent_name}</h3>
                <p className="text-xs text-slate-400">Select what to analyze</p>
              </div>
            </div>
            <button
              onClick={onClose}
              className="p-1.5 hover:bg-slate-700 rounded-lg transition-colors"
            >
              <X className="w-4 h-4 text-slate-400" />
            </button>
          </div>
        </div>

        {/* Content */}
        <div className="p-6 space-y-4">
          {agent.supported_input_types.includes('run') && (
            <div>
              <label className="label">Run ID</label>
              <input
                type="text"
                value={runId}
                onChange={(e) => setRunId(e.target.value)}
                placeholder="Paste a run ID from Attack Console..."
                className="input-field"
              />
              <p className="mt-1 text-xs text-slate-500">
                Copy a run ID from the Attack Console results panel
              </p>
            </div>
          )}

          {agent.supported_input_types.includes('campaign') && (
            <div>
              <label className="label">Campaign ID</label>
              <input
                type="text"
                value={campaignId}
                onChange={(e) => setCampaignId(e.target.value)}
                placeholder="Paste a campaign ID from Campaign History..."
                className="input-field"
              />
              <p className="mt-1 text-xs text-slate-500">
                Copy a campaign ID from Campaign History
              </p>
            </div>
          )}

          {/* Quick tip */}
          <div className="flex items-start gap-2 p-3 bg-azure-500/10 border border-azure-500/20 rounded-lg">
            <MessageSquare className="w-4 h-4 text-azure-400 mt-0.5 shrink-0" />
            <p className="text-xs text-slate-300">
              The agent will analyze the data and produce a summary you can share during demos.
            </p>
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-4 bg-slate-900/50 border-t border-slate-700 flex items-center justify-end gap-3">
          <button
            onClick={onClose}
            className="btn-secondary"
          >
            Cancel
          </button>
          <button
            onClick={() => onInvoke(runId.trim() || undefined, campaignId.trim() || undefined)}
            disabled={!canInvoke || isLoading}
            className={`btn-primary flex items-center gap-2 ${(!canInvoke || isLoading) ? 'opacity-50 cursor-not-allowed' : ''}`}
          >
            {isLoading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Processing...
              </>
            ) : (
              <>
                <Sparkles className="w-4 h-4" />
                Run Analysis
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
}

// Result Modal Component
interface ResultModalProps {
  result: ApiInvokeAgentResponse;
  onClose: () => void;
}

function ResultModal({ result, onClose }: ResultModalProps) {
  const { invocation, output } = result;
  const colors = agentColors[invocation.agent_type] || agentColors.attack_observer;

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="glass-panel w-full max-w-2xl max-h-[80vh] flex flex-col overflow-hidden">
        {/* Header */}
        <div className={`px-6 py-4 ${colors.bg} border-b ${colors.border} shrink-0`}>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-success-500/20 rounded-lg">
                <CheckCircle className="w-5 h-5 text-success-400" />
              </div>
              <div>
                <h3 className="font-semibold text-white">Analysis Complete</h3>
                <p className="text-xs text-slate-400">
                  {invocation.agent_name} • {invocation.latency_ms}ms
                </p>
              </div>
            </div>
            <button
              onClick={onClose}
              className="p-1.5 hover:bg-slate-700 rounded-lg transition-colors"
            >
              <X className="w-4 h-4 text-slate-400" />
            </button>
          </div>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6">
          {/* Summary */}
          <div className="mb-6">
            <h4 className="text-sm font-medium text-slate-300 mb-2">Summary</h4>
            <p className="text-sm text-slate-400 leading-relaxed">
              {invocation.output_summary}
            </p>
          </div>

          {/* Structured Output */}
          <div>
            <h4 className="text-sm font-medium text-slate-300 mb-2">Detailed Output</h4>
            <div className="bg-slate-950 rounded-lg p-4 overflow-x-auto">
              <pre className="text-xs text-slate-300 whitespace-pre-wrap">
                {JSON.stringify(output, null, 2)}
              </pre>
            </div>
          </div>

          {/* Metadata */}
          <div className="mt-6 grid grid-cols-2 gap-4 text-xs">
            <div className="flex items-center gap-2">
              <span className="text-slate-500">Invocation ID:</span>
              <code className="text-slate-400 font-mono">{invocation.invocation_id.slice(0, 8)}...</code>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-slate-500">Correlation ID:</span>
              <code className="text-slate-400 font-mono">{invocation.correlation_id.slice(0, 8)}...</code>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-4 bg-slate-900/50 border-t border-slate-700 shrink-0">
          <button onClick={onClose} className="btn-primary w-full">
            Done
          </button>
        </div>
      </div>
    </div>
  );
}

// Invocation status badge styles
const invocationStatusStyles: Record<string, { bg: string; text: string; dot: string }> = {
  completed: {
    bg: 'bg-success-500/20',
    text: 'text-success-400',
    dot: 'bg-success-500',
  },
  running: {
    bg: 'bg-azure-500/20',
    text: 'text-azure-400',
    dot: 'bg-azure-500',
  },
  pending: {
    bg: 'bg-slate-500/20',
    text: 'text-slate-400',
    dot: 'bg-slate-500',
  },
  failed: {
    bg: 'bg-danger-500/20',
    text: 'text-danger-400',
    dot: 'bg-danger-500',
  },
  timeout: {
    bg: 'bg-warning-500/20',
    text: 'text-warning-400',
    dot: 'bg-warning-500',
  },
};

// Invocation Detail Drawer Component
interface InvocationDetailDrawerProps {
  invocation: ApiAgentInvocation;
  onClose: () => void;
}

function InvocationDetailDrawer({ invocation, onClose }: InvocationDetailDrawerProps) {
  const colors = agentColors[invocation.agent_type] || agentColors.attack_observer;
  const Icon = agentIcons[invocation.agent_type] || Bot;
  const statusStyle = invocationStatusStyles[invocation.status] || invocationStatusStyles.pending;

  const formatDateTime = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex justify-end z-50">
      {/* Backdrop click to close */}
      <div className="absolute inset-0" onClick={onClose} />
      
      {/* Drawer */}
      <div className="relative w-full max-w-2xl bg-slate-900 border-l border-slate-700 shadow-2xl flex flex-col animate-slide-in-right">
        {/* Header */}
        <div className={`px-6 py-4 ${colors.bg} border-b ${colors.border} shrink-0`}>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className={`w-10 h-10 rounded-lg ${colors.bg} border ${colors.border} flex items-center justify-center`}>
                <Icon className={`w-5 h-5 ${colors.text}`} />
              </div>
              <div>
                <h3 className="font-semibold text-white">{invocation.agent_name}</h3>
                <div className="flex items-center gap-2 text-xs text-slate-400">
                  <div className={`flex items-center gap-1.5 px-2 py-0.5 rounded-full ${statusStyle.bg}`}>
                    <div className={`w-1.5 h-1.5 rounded-full ${statusStyle.dot}`} />
                    <span className={`capitalize ${statusStyle.text}`}>{invocation.status}</span>
                  </div>
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
          {/* Output Summary */}
          <div className="p-4 bg-slate-800/50 rounded-lg border border-slate-700/50">
            <div className="flex items-center gap-2 mb-2">
              <Sparkles className="w-4 h-4 text-azure-400" />
              <span className="text-sm font-medium text-white">Output Summary</span>
            </div>
            <p className="text-sm text-slate-300 leading-relaxed">
              {invocation.output_summary || 'No summary available'}
            </p>
          </div>

          {/* IDs & Metadata */}
          <div className="grid grid-cols-1 gap-3">
            {/* Invocation ID */}
            <div className="p-3 bg-slate-800/30 rounded-lg border border-slate-700/30">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Fingerprint className="w-4 h-4 text-slate-500" />
                  <span className="text-xs text-slate-500">Invocation ID</span>
                </div>
                <div className="flex items-center gap-2">
                  <code className="text-xs text-slate-300 font-mono">{invocation.invocation_id}</code>
                  <button
                    onClick={() => copyToClipboard(invocation.invocation_id)}
                    className="text-slate-500 hover:text-azure-400 transition-colors"
                  >
                    <Copy className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            </div>

            {/* Correlation ID */}
            <div className="p-3 bg-slate-800/30 rounded-lg border border-slate-700/30">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Link2 className="w-4 h-4 text-slate-500" />
                  <span className="text-xs text-slate-500">Correlation ID</span>
                </div>
                <div className="flex items-center gap-2">
                  <code className="text-xs text-azure-300 font-mono">{invocation.correlation_id}</code>
                  <button
                    onClick={() => copyToClipboard(invocation.correlation_id)}
                    className="text-slate-500 hover:text-azure-400 transition-colors"
                  >
                    <Copy className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            </div>

            {/* Linked Run ID */}
            {invocation.linked_run_id && (
              <div className="p-3 bg-cyan-500/10 rounded-lg border border-cyan-500/30">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <ExternalLink className="w-4 h-4 text-cyan-500" />
                    <span className="text-xs text-cyan-400">Linked Run ID</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <code className="text-xs text-cyan-300 font-mono">{invocation.linked_run_id}</code>
                    <button
                      onClick={() => copyToClipboard(invocation.linked_run_id!)}
                      className="text-cyan-500 hover:text-cyan-400 transition-colors"
                    >
                      <Copy className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* Linked Campaign ID */}
            {invocation.linked_campaign_id && (
              <div className="p-3 bg-amber-500/10 rounded-lg border border-amber-500/30">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <ExternalLink className="w-4 h-4 text-amber-500" />
                    <span className="text-xs text-amber-400">Linked Campaign ID</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <code className="text-xs text-amber-300 font-mono">{invocation.linked_campaign_id}</code>
                    <button
                      onClick={() => copyToClipboard(invocation.linked_campaign_id!)}
                      className="text-amber-500 hover:text-amber-400 transition-colors"
                    >
                      <Copy className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* Timestamp */}
            <div className="p-3 bg-slate-800/30 rounded-lg border border-slate-700/30">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Clock className="w-4 h-4 text-slate-500" />
                  <span className="text-xs text-slate-500">Timestamp</span>
                </div>
                <span className="text-xs text-slate-300">{formatDateTime(invocation.timestamp)}</span>
              </div>
            </div>

            {/* Latency */}
            <div className="p-3 bg-slate-800/30 rounded-lg border border-slate-700/30">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Zap className="w-4 h-4 text-slate-500" />
                  <span className="text-xs text-slate-500">Latency</span>
                </div>
                <span className="text-xs text-white font-medium">{invocation.latency_ms}ms</span>
              </div>
            </div>
          </div>

          {/* Raw Output */}
          <div>
            <div className="flex items-center gap-2 mb-2">
              <FileText className="w-4 h-4 text-slate-400" />
              <span className="text-sm font-medium text-slate-300">Raw Output</span>
            </div>
            <div className="bg-slate-950 rounded-lg p-4 overflow-x-auto max-h-[300px] overflow-y-auto">
              <pre className="text-xs text-slate-400 font-mono whitespace-pre-wrap">
                {invocation.raw_output || JSON.stringify(invocation.structured_output, null, 2)}
              </pre>
            </div>
          </div>

          {/* Error Details (if failed) */}
          {invocation.status === 'failed' && invocation.error_details && (
            <div className="p-4 bg-danger-500/10 rounded-lg border border-danger-500/30">
              <div className="flex items-center gap-2 mb-2">
                <AlertCircle className="w-4 h-4 text-danger-400" />
                <span className="text-sm font-medium text-danger-300">Error Details</span>
              </div>
              <p className="text-sm text-danger-300">{invocation.error_details}</p>
              {invocation.error_code && (
                <p className="text-xs text-danger-400 mt-1">Code: {invocation.error_code}</p>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-slate-700 bg-slate-900/80 shrink-0">
          <button onClick={onClose} className="btn-primary w-full">
            Close
          </button>
        </div>
      </div>
    </div>
  );
}

// Invocation History Row Component
interface InvocationRowProps {
  invocation: ApiAgentInvocation;
  onClick: () => void;
}

function InvocationRow({ invocation, onClick }: InvocationRowProps) {
  const colors = agentColors[invocation.agent_type] || agentColors.attack_observer;
  const Icon = agentIcons[invocation.agent_type] || Bot;
  const statusStyle = invocationStatusStyles[invocation.status] || invocationStatusStyles.pending;

  const formatTime = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  return (
    <button
      onClick={onClick}
      className="w-full text-left p-4 bg-slate-800/30 hover:bg-slate-800/50 border border-slate-700/50 hover:border-slate-600 rounded-lg transition-all duration-200 group"
    >
      <div className="flex items-start gap-4">
        {/* Agent Icon */}
        <div className={`w-10 h-10 rounded-lg ${colors.bg} border ${colors.border} flex items-center justify-center shrink-0`}>
          <Icon className={`w-5 h-5 ${colors.text}`} />
        </div>

        {/* Content */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center justify-between mb-1">
            <div className="flex items-center gap-2">
              <span className="font-medium text-white">{invocation.agent_name}</span>
              <div className={`flex items-center gap-1 px-2 py-0.5 rounded-full ${statusStyle.bg}`}>
                <div className={`w-1.5 h-1.5 rounded-full ${statusStyle.dot}`} />
                <span className={`text-xs capitalize ${statusStyle.text}`}>{invocation.status}</span>
              </div>
            </div>
            <ChevronRight className="w-4 h-4 text-slate-600 group-hover:text-azure-400 transition-colors" />
          </div>

          {/* Output Summary */}
          <p className="text-sm text-slate-400 line-clamp-1 mb-2">
            {invocation.output_summary || 'No summary available'}
          </p>

          {/* Metadata Row */}
          <div className="flex items-center gap-4 text-xs text-slate-500">
            <div className="flex items-center gap-1">
              <Fingerprint className="w-3 h-3" />
              <span className="font-mono">{invocation.invocation_id.slice(0, 8)}...</span>
            </div>
            {invocation.linked_run_id && (
              <div className="flex items-center gap-1 text-cyan-400">
                <Link2 className="w-3 h-3" />
                <span>Run</span>
              </div>
            )}
            {invocation.linked_campaign_id && (
              <div className="flex items-center gap-1 text-amber-400">
                <Link2 className="w-3 h-3" />
                <span>Campaign</span>
              </div>
            )}
            <div className="flex items-center gap-1">
              <Clock className="w-3 h-3" />
              <span>{formatTime(invocation.timestamp)}</span>
            </div>
            <div className="flex items-center gap-1">
              <Zap className="w-3 h-3" />
              <span>{invocation.latency_ms}ms</span>
            </div>
          </div>
        </div>
      </div>
    </button>
  );
}

export default function Agents() {
  const [agents, setAgents] = useState<ApiAgentDefinition[]>([]);
  const [summary, setSummary] = useState<ApiInvocationSummary | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  
  // Tab state
  const [activeTab, setActiveTab] = useState<'catalog' | 'history'>('catalog');
  
  // Invocation history state
  const [invocations, setInvocations] = useState<ApiAgentInvocation[]>([]);
  const [invocationsLoading, setInvocationsLoading] = useState(false);
  const [selectedInvocation, setSelectedInvocation] = useState<ApiAgentInvocation | null>(null);
  
  // Modal state
  const [selectedAgent, setSelectedAgent] = useState<ApiAgentDefinition | null>(null);
  const [isInvoking, setIsInvoking] = useState(false);
  const [invokeResult, setInvokeResult] = useState<ApiInvokeAgentResponse | null>(null);
  const [invokingAgentId, setInvokingAgentId] = useState<string | null>(null);

  useEffect(() => {
    fetchData();
  }, []);

  // Fetch invocations when switching to history tab
  useEffect(() => {
    if (activeTab === 'history' && invocations.length === 0) {
      fetchInvocations();
    }
  }, [activeTab]);

  const fetchData = async () => {
    setIsLoading(true);
    setError(null);

    try {
      const [agentsResponse, summaryResponse] = await Promise.all([
        getAgents(),
        getInvocationSummary(),
      ]);

      setAgents(agentsResponse.agents);
      setSummary(summaryResponse);
    } catch (err) {
      console.error('Failed to fetch agents:', err);
      if (err instanceof ApiError) {
        setError(`Failed to load agents: ${err.status} ${err.statusText}`);
      } else {
        setError('Failed to load agents. Please try again.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  const fetchInvocations = async () => {
    setInvocationsLoading(true);
    try {
      const response = await getInvocations();
      setInvocations(response.invocations);
    } catch (err) {
      console.error('Failed to fetch invocations:', err);
      if (err instanceof ApiError) {
        setError(`Failed to load invocations: ${err.status} ${err.statusText}`);
      }
    } finally {
      setInvocationsLoading(false);
    }
  };

  const handleInvoke = async (runId?: string, campaignId?: string) => {
    if (!selectedAgent) return;
    
    setIsInvoking(true);
    setInvokingAgentId(selectedAgent.agent_id);

    try {
      const result = await invokeAgent(selectedAgent.agent_id, {
        linked_run_id: runId,
        linked_campaign_id: campaignId,
      });

      setInvokeResult(result);
      setSelectedAgent(null);
      
      // Refresh summary to update counts
      const newSummary = await getInvocationSummary();
      setSummary(newSummary);
      
      // Add to invocations list at the front
      setInvocations(prev => [result.invocation, ...prev]);
    } catch (err) {
      console.error('Failed to invoke agent:', err);
      if (err instanceof ApiError) {
        setError(`Invocation failed: ${err.message}`);
      } else {
        setError('Failed to invoke agent. Please try again.');
      }
    } finally {
      setIsInvoking(false);
      setInvokingAgentId(null);
    }
  };

  const getInvocationCount = (agentId: string): number => {
    return summary?.by_agent[agentId] || 0;
  };

  // For demo, we don't have last invocation per agent from the summary
  // This would require additional API or tracking
  const getLastInvocation = (_agentId: string): string | null => {
    return null;
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="flex flex-col items-center gap-4">
          <Loader2 className="w-8 h-8 text-azure-500 animate-spin" />
          <p className="text-slate-400">Loading agents...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <Bot className="w-7 h-7 text-azure-500" />
            AI Agents
          </h1>
          <p className="text-slate-400 mt-1">
            Invoke analysis agents to explain red team results during demos
          </p>
        </div>
        
        <button
          onClick={() => {
            fetchData();
            if (activeTab === 'history') fetchInvocations();
          }}
          className="btn-secondary flex items-center gap-2"
        >
          <RefreshCw className="w-4 h-4" />
          Refresh
        </button>
      </div>

      {/* Error Display */}
      {error && (
        <div className="flex items-center gap-3 p-4 bg-danger-500/10 border border-danger-500/30 rounded-lg">
          <AlertCircle className="w-5 h-5 text-danger-400" />
          <p className="text-sm text-danger-300">{error}</p>
          <button
            onClick={() => setError(null)}
            className="ml-auto text-danger-400 hover:text-danger-300"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Tab Navigation */}
      <div className="flex items-center gap-1 p-1 bg-slate-800/50 rounded-lg border border-slate-700/50 w-fit">
        <button
          onClick={() => setActiveTab('catalog')}
          className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-all duration-200 ${
            activeTab === 'catalog'
              ? 'bg-azure-500 text-white shadow-lg shadow-azure-500/20'
              : 'text-slate-400 hover:text-white hover:bg-slate-700/50'
          }`}
        >
          <Bot className="w-4 h-4" />
          Agent Catalog
        </button>
        <button
          onClick={() => setActiveTab('history')}
          className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-all duration-200 ${
            activeTab === 'history'
              ? 'bg-azure-500 text-white shadow-lg shadow-azure-500/20'
              : 'text-slate-400 hover:text-white hover:bg-slate-700/50'
          }`}
        >
          <History className="w-4 h-4" />
          Invocation History
          {summary && summary.total_invocations > 0 && (
            <span className={`ml-1 px-1.5 py-0.5 text-xs rounded-full ${
              activeTab === 'history'
                ? 'bg-white/20 text-white'
                : 'bg-slate-600 text-slate-300'
            }`}>
              {summary.total_invocations}
            </span>
          )}
        </button>
      </div>

      {/* Summary Stats */}
      {summary && (
        <div className="grid grid-cols-4 gap-4">
          <Panel className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-slate-500 uppercase tracking-wide">Total Agents</p>
                <p className="text-2xl font-bold text-white mt-1">{agents.length}</p>
              </div>
              <div className="w-10 h-10 rounded-lg bg-azure-500/20 flex items-center justify-center">
                <Bot className="w-5 h-5 text-azure-400" />
              </div>
            </div>
          </Panel>

          <Panel className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-slate-500 uppercase tracking-wide">Total Invocations</p>
                <p className="text-2xl font-bold text-white mt-1">{summary.total_invocations}</p>
              </div>
              <div className="w-10 h-10 rounded-lg bg-emerald-500/20 flex items-center justify-center">
                <Zap className="w-5 h-5 text-emerald-400" />
              </div>
            </div>
          </Panel>

          <Panel className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-slate-500 uppercase tracking-wide">Completed</p>
                <p className="text-2xl font-bold text-success-400 mt-1">{summary.completed_count}</p>
              </div>
              <div className="w-10 h-10 rounded-lg bg-success-500/20 flex items-center justify-center">
                <CheckCircle className="w-5 h-5 text-success-400" />
              </div>
            </div>
          </Panel>

          <Panel className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-slate-500 uppercase tracking-wide">Avg Latency</p>
                <p className="text-2xl font-bold text-white mt-1">{summary.average_latency_ms}ms</p>
              </div>
              <div className="w-10 h-10 rounded-lg bg-violet-500/20 flex items-center justify-center">
                <Activity className="w-5 h-5 text-violet-400" />
              </div>
            </div>
          </Panel>
        </div>
      )}

      {/* Tab Content */}
      {activeTab === 'catalog' ? (
        <>
          {/* Agent Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            {agents.map((agent) => (
              <AgentCard
                key={agent.agent_id}
                agent={agent}
                invocationCount={getInvocationCount(agent.agent_id)}
                lastInvocation={getLastInvocation(agent.agent_id)}
                onInvoke={() => setSelectedAgent(agent)}
                isInvoking={invokingAgentId === agent.agent_id}
              />
            ))}
          </div>

          {/* Empty State */}
          {agents.length === 0 && !isLoading && (
            <div className="flex flex-col items-center justify-center py-16 text-center">
              <div className="w-16 h-16 rounded-full bg-slate-800 flex items-center justify-center mb-4">
                <Bot className="w-8 h-8 text-slate-500" />
              </div>
              <h3 className="text-lg font-medium text-white mb-2">No Agents Available</h3>
              <p className="text-sm text-slate-400 max-w-sm">
                Agents will appear here once configured. Check the backend configuration.
              </p>
            </div>
          )}
        </>
      ) : (
        /* Invocation History Tab */
        <div className="space-y-4">
          {invocationsLoading ? (
            <div className="flex items-center justify-center py-16">
              <div className="flex flex-col items-center gap-4">
                <Loader2 className="w-8 h-8 text-azure-500 animate-spin" />
                <p className="text-slate-400">Loading invocation history...</p>
              </div>
            </div>
          ) : invocations.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-center">
              <div className="w-16 h-16 rounded-full bg-slate-800 flex items-center justify-center mb-4">
                <History className="w-8 h-8 text-slate-500" />
              </div>
              <h3 className="text-lg font-medium text-white mb-2">No Invocations Yet</h3>
              <p className="text-sm text-slate-400 max-w-sm">
                Agent invocations will appear here once you run an analysis.
                Switch to the Agent Catalog to invoke an agent.
              </p>
              <button
                onClick={() => setActiveTab('catalog')}
                className="btn-primary mt-4"
              >
                Go to Agent Catalog
              </button>
            </div>
          ) : (
            <div className="space-y-3">
              {invocations.map((inv) => (
                <InvocationRow
                  key={inv.invocation_id}
                  invocation={inv}
                  onClick={() => setSelectedInvocation(inv)}
                />
              ))}
            </div>
          )}
        </div>
      )}

      {/* Invoke Modal */}
      {selectedAgent && !invokeResult && (
        <InvokeModal
          agent={selectedAgent}
          onClose={() => setSelectedAgent(null)}
          onInvoke={handleInvoke}
          isLoading={isInvoking}
        />
      )}

      {/* Result Modal */}
      {invokeResult && (
        <ResultModal
          result={invokeResult}
          onClose={() => setInvokeResult(null)}
        />
      )}

      {/* Invocation Detail Drawer */}
      {selectedInvocation && (
        <InvocationDetailDrawer
          invocation={selectedInvocation}
          onClose={() => setSelectedInvocation(null)}
        />
      )}
    </div>
  );
}
