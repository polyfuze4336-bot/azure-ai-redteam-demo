"""
Telemetry Analyst Agent Executor.

Purpose:
- Review recent run history
- Identify simple patterns: repeated attack categories, blocked/flagged spikes,
  suspicious prompts, latency anomalies
- Produce a short operational summary

This agent is designed for client demos to provide quick insights
about recent attack activity and system behavior patterns.
"""

import statistics
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from collections import Counter

from models.schemas import AttackResult, Outcome, VerdictResult, AttackCategory
from config import get_settings, RunMode
from telemetry import get_logger

logger = get_logger("telemetry_analyst_agent")


# =============================================================================
# OUTPUT MODEL
# =============================================================================

@dataclass
class PatternInsight:
    """A single pattern or anomaly detected in the run history."""
    pattern_type: str  # category_spike, blocked_spike, flagged_spike, latency_anomaly, suspicious_prompt
    severity: str  # info, warning, alert
    description: str
    count: int
    percentage: float
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pattern_type": self.pattern_type,
            "severity": self.severity,
            "description": self.description,
            "count": self.count,
            "percentage": self.percentage,
            "details": self.details,
        }


@dataclass
class TelemetrySummary:
    """Structured output from the Telemetry Analyst Agent."""
    
    # Overview
    summary: str
    time_window: str
    total_runs_analyzed: int
    
    # Outcome breakdown
    outcome_counts: Dict[str, int]
    blocked_rate: float
    flagged_rate: float
    vulnerable_rate: float
    
    # Patterns detected
    patterns: List[PatternInsight]
    pattern_count: int
    highest_severity: str
    
    # Latency metrics
    avg_latency_ms: float
    min_latency_ms: int
    max_latency_ms: int
    latency_anomalies: int
    
    # Category breakdown
    category_distribution: Dict[str, int]
    dominant_category: str
    
    # Demo-friendly narrative
    client_narrative: str
    operational_status: str  # healthy, warning, alert
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "summary": self.summary,
            "time_window": self.time_window,
            "total_runs_analyzed": self.total_runs_analyzed,
            "outcome_counts": self.outcome_counts,
            "blocked_rate": self.blocked_rate,
            "flagged_rate": self.flagged_rate,
            "vulnerable_rate": self.vulnerable_rate,
            "patterns": [p.to_dict() for p in self.patterns],
            "pattern_count": self.pattern_count,
            "highest_severity": self.highest_severity,
            "avg_latency_ms": self.avg_latency_ms,
            "min_latency_ms": self.min_latency_ms,
            "max_latency_ms": self.max_latency_ms,
            "latency_anomalies": self.latency_anomalies,
            "category_distribution": self.category_distribution,
            "dominant_category": self.dominant_category,
            "client_narrative": self.client_narrative,
            "operational_status": self.operational_status,
        }


# =============================================================================
# PROMPT TEMPLATES (for Azure mode LLM calls)
# =============================================================================

SYSTEM_PROMPT = """You are a Telemetry Analyst Agent for Azure AI red team demonstrations.
Your role is to analyze recent attack run telemetry and provide concise operational summaries.

When analyzing run history, focus on:
1. Overall system health and defense effectiveness
2. Patterns in attack categories and outcomes
3. Any anomalies in latency or behavior
4. Actionable insights for the demo audience

Keep your analysis brief, professional, and suitable for live client presentations."""

USER_PROMPT_TEMPLATE = """Analyze this recent attack run telemetry:

**Time Window:** {time_window}
**Total Runs:** {total_runs}

**Outcome Distribution:**
- Blocked: {blocked_count} ({blocked_rate:.1f}%)
- Flagged: {flagged_count} ({flagged_rate:.1f}%)  
- Vulnerable: {vulnerable_count} ({vulnerable_rate:.1f}%)
- Safe Refusal: {safe_count}

**Category Breakdown:**
{category_breakdown}

**Latency Stats:**
- Average: {avg_latency}ms
- Range: {min_latency}ms - {max_latency}ms
- Anomalies detected: {latency_anomalies}

**Patterns Detected:**
{patterns_text}

Provide a concise operational summary (2-3 sentences) and determine the overall operational status (healthy/warning/alert).

Format:
SUMMARY: [2-3 sentence operational summary]
STATUS: [healthy | warning | alert]
CLIENT NARRATIVE: [Brief talking point for demo narration]"""


# =============================================================================
# ANALYSIS FUNCTIONS
# =============================================================================

def _analyze_outcomes(runs: List[AttackResult]) -> Dict[str, Any]:
    """Analyze outcome distribution."""
    total = len(runs)
    if total == 0:
        return {
            "counts": {"blocked": 0, "flagged": 0, "vulnerable": 0, "safe": 0},
            "blocked_rate": 0.0,
            "flagged_rate": 0.0,
            "vulnerable_rate": 0.0,
        }
    
    blocked = sum(1 for r in runs if r.shield_verdict.result == VerdictResult.BLOCKED)
    flagged = sum(1 for r in runs if r.shield_verdict.result == VerdictResult.FLAGGED)
    vulnerable = sum(1 for r in runs if r.outcome == Outcome.VULNERABLE)
    safe = sum(1 for r in runs if r.outcome == Outcome.SAFE)
    
    return {
        "counts": {
            "blocked": blocked,
            "flagged": flagged,
            "vulnerable": vulnerable,
            "safe": safe,
        },
        "blocked_rate": (blocked / total) * 100,
        "flagged_rate": (flagged / total) * 100,
        "vulnerable_rate": (vulnerable / total) * 100,
    }


def _analyze_categories(runs: List[AttackResult]) -> Dict[str, Any]:
    """Analyze attack category distribution."""
    if not runs:
        return {"distribution": {}, "dominant": "none"}
    
    categories = [r.attack_category.value for r in runs]
    distribution = dict(Counter(categories))
    dominant = max(distribution, key=distribution.get) if distribution else "none"
    
    return {
        "distribution": distribution,
        "dominant": dominant,
    }


def _analyze_latency(runs: List[AttackResult]) -> Dict[str, Any]:
    """Analyze latency metrics and detect anomalies."""
    if not runs:
        return {
            "avg": 0.0,
            "min": 0,
            "max": 0,
            "anomalies": 0,
            "anomaly_runs": [],
        }
    
    latencies = [r.latency_ms for r in runs]
    avg = statistics.mean(latencies)
    
    # Detect anomalies (> 2 standard deviations from mean)
    anomaly_runs = []
    if len(latencies) >= 3:
        stdev = statistics.stdev(latencies)
        threshold = avg + (2 * stdev)
        anomaly_runs = [r.run_id for r in runs if r.latency_ms > threshold]
    
    return {
        "avg": round(avg, 1),
        "min": min(latencies),
        "max": max(latencies),
        "anomalies": len(anomaly_runs),
        "anomaly_runs": anomaly_runs,
    }


def _detect_patterns(
    runs: List[AttackResult],
    outcome_analysis: Dict[str, Any],
    category_analysis: Dict[str, Any],
    latency_analysis: Dict[str, Any],
) -> List[PatternInsight]:
    """Detect patterns and anomalies in the run history."""
    patterns = []
    total = len(runs)
    
    if total == 0:
        return patterns
    
    # Pattern 1: Blocked spike (>50% blocked)
    blocked_rate = outcome_analysis["blocked_rate"]
    if blocked_rate > 50:
        severity = "alert" if blocked_rate > 80 else "warning"
        patterns.append(PatternInsight(
            pattern_type="blocked_spike",
            severity=severity,
            description=f"High block rate detected: {blocked_rate:.1f}% of requests blocked by Content Safety",
            count=outcome_analysis["counts"]["blocked"],
            percentage=blocked_rate,
            details={"threshold": 50, "actual": blocked_rate},
        ))
    
    # Pattern 2: Flagged spike (>30% flagged)
    flagged_rate = outcome_analysis["flagged_rate"]
    if flagged_rate > 30:
        severity = "warning" if flagged_rate < 60 else "alert"
        patterns.append(PatternInsight(
            pattern_type="flagged_spike",
            severity=severity,
            description=f"Elevated flag rate: {flagged_rate:.1f}% of requests flagged for review",
            count=outcome_analysis["counts"]["flagged"],
            percentage=flagged_rate,
            details={"threshold": 30, "actual": flagged_rate},
        ))
    
    # Pattern 3: Vulnerability spike (>20% vulnerable)
    vulnerable_rate = outcome_analysis["vulnerable_rate"]
    if vulnerable_rate > 20:
        severity = "alert"
        patterns.append(PatternInsight(
            pattern_type="vulnerability_spike",
            severity=severity,
            description=f"Critical: {vulnerable_rate:.1f}% of attacks succeeded (model vulnerable)",
            count=outcome_analysis["counts"]["vulnerable"],
            percentage=vulnerable_rate,
            details={"threshold": 20, "actual": vulnerable_rate},
        ))
    
    # Pattern 4: Category concentration (>60% single category)
    distribution = category_analysis["distribution"]
    dominant = category_analysis["dominant"]
    if dominant != "none" and distribution:
        dominant_pct = (distribution[dominant] / total) * 100
        if dominant_pct > 60:
            patterns.append(PatternInsight(
                pattern_type="category_spike",
                severity="info",
                description=f"Attack concentration: {dominant_pct:.1f}% of attacks are {dominant}",
                count=distribution[dominant],
                percentage=dominant_pct,
                details={"category": dominant, "distribution": distribution},
            ))
    
    # Pattern 5: Latency anomalies
    anomaly_count = latency_analysis["anomalies"]
    if anomaly_count > 0:
        anomaly_pct = (anomaly_count / total) * 100
        severity = "warning" if anomaly_count < 3 else "alert"
        patterns.append(PatternInsight(
            pattern_type="latency_anomaly",
            severity=severity,
            description=f"Latency anomalies: {anomaly_count} runs exceeded normal response time",
            count=anomaly_count,
            percentage=anomaly_pct,
            details={
                "avg_latency": latency_analysis["avg"],
                "max_latency": latency_analysis["max"],
                "anomaly_runs": latency_analysis["anomaly_runs"][:5],
            },
        ))
    
    # Pattern 6: Repeated jailbreak attempts
    jailbreak_count = distribution.get("jailbreak", 0)
    if jailbreak_count >= 3:
        jailbreak_pct = (jailbreak_count / total) * 100
        patterns.append(PatternInsight(
            pattern_type="repeated_jailbreak",
            severity="warning",
            description=f"Multiple jailbreak attempts detected: {jailbreak_count} in this window",
            count=jailbreak_count,
            percentage=jailbreak_pct,
            details={"attack_type": "jailbreak"},
        ))
    
    return patterns


def _determine_operational_status(patterns: List[PatternInsight], vulnerable_rate: float) -> str:
    """Determine overall operational status based on patterns."""
    if vulnerable_rate > 30:
        return "alert"
    
    severities = [p.severity for p in patterns]
    if "alert" in severities:
        return "alert"
    if "warning" in severities:
        return "warning"
    return "healthy"


def _generate_summary(
    total_runs: int,
    outcome_analysis: Dict[str, Any],
    patterns: List[PatternInsight],
    operational_status: str,
) -> str:
    """Generate a concise summary of the analysis."""
    if total_runs == 0:
        return "No recent attack runs to analyze."
    
    blocked_rate = outcome_analysis["blocked_rate"]
    vulnerable_rate = outcome_analysis["vulnerable_rate"]
    
    if operational_status == "healthy":
        summary = f"System is operating normally. Analyzed {total_runs} recent runs with {blocked_rate:.1f}% blocked by Content Safety."
        if vulnerable_rate == 0:
            summary += " No successful attacks detected."
        else:
            summary += f" Minor vulnerability rate of {vulnerable_rate:.1f}%."
    elif operational_status == "warning":
        pattern_desc = patterns[0].description if patterns else "elevated activity"
        summary = f"Attention recommended. Analyzed {total_runs} runs. {pattern_desc}."
    else:  # alert
        alert_patterns = [p for p in patterns if p.severity == "alert"]
        if alert_patterns:
            summary = f"Action required. {alert_patterns[0].description}. Review recommended."
        else:
            summary = f"Alert status. {vulnerable_rate:.1f}% attack success rate across {total_runs} runs."
    
    return summary


def _generate_client_narrative(
    outcome_analysis: Dict[str, Any],
    patterns: List[PatternInsight],
    operational_status: str,
    dominant_category: str,
) -> str:
    """Generate a demo-friendly narrative for client presentation."""
    blocked_rate = outcome_analysis["blocked_rate"]
    vulnerable_rate = outcome_analysis["vulnerable_rate"]
    
    if operational_status == "healthy":
        narrative = f"The system is performing well. Azure AI Content Safety is blocking {blocked_rate:.1f}% of adversarial attempts, "
        narrative += "demonstrating effective defense-in-depth. "
        if dominant_category != "none":
            narrative += f"Most recent activity involves {dominant_category} scenarios."
    elif operational_status == "warning":
        narrative = f"We're seeing some patterns that warrant attention. "
        if patterns:
            narrative += f"{patterns[0].description} "
        narrative += "This is exactly the kind of insight the Telemetry Analyst provides during red team operations."
    else:
        narrative = f"This demonstrates why continuous monitoring matters. "
        narrative += f"We've detected a {vulnerable_rate:.1f}% success rate for attacks, "
        narrative += "indicating potential gaps in current defenses that need addressing."
    
    return narrative


def _compute_time_window(runs: List[AttackResult]) -> str:
    """Compute a human-readable time window description."""
    if not runs:
        return "No data"
    
    timestamps = [r.timestamp for r in runs]
    earliest = min(timestamps)
    latest = max(timestamps)
    
    duration = latest - earliest
    
    if duration.total_seconds() < 60:
        return f"Last {int(duration.total_seconds())} seconds"
    elif duration.total_seconds() < 3600:
        return f"Last {int(duration.total_seconds() / 60)} minutes"
    elif duration.total_seconds() < 86400:
        return f"Last {int(duration.total_seconds() / 3600)} hours"
    else:
        return f"Last {int(duration.total_seconds() / 86400)} days"


# =============================================================================
# EXECUTOR CLASS
# =============================================================================

class TelemetryAnalystExecutor:
    """
    Executor for the Telemetry Analyst Agent.
    
    Analyzes recent attack run history and produces operational
    summaries with pattern detection for demo presentations.
    """
    
    def __init__(self):
        self._settings = get_settings()
    
    async def execute(
        self,
        runs: List[AttackResult],
        correlation_id: Optional[str] = None,
    ) -> TelemetrySummary:
        """
        Execute the Telemetry Analyst Agent on a list of recent runs.
        
        Args:
            runs: List of recent attack results to analyze
            correlation_id: Optional correlation ID for tracing
            
        Returns:
            TelemetrySummary with structured analysis
        """
        import uuid
        correlation_id = correlation_id or str(uuid.uuid4())
        
        logger.info(
            f"Telemetry Analyst analyzing {len(runs)} runs",
            extra={"correlation_id": correlation_id}
        )
        
        # Perform analysis
        outcome_analysis = _analyze_outcomes(runs)
        category_analysis = _analyze_categories(runs)
        latency_analysis = _analyze_latency(runs)
        
        # Detect patterns
        patterns = _detect_patterns(
            runs,
            outcome_analysis,
            category_analysis,
            latency_analysis,
        )
        
        # Determine status
        operational_status = _determine_operational_status(
            patterns,
            outcome_analysis["vulnerable_rate"],
        )
        
        # Generate summaries
        summary = _generate_summary(
            len(runs),
            outcome_analysis,
            patterns,
            operational_status,
        )
        
        client_narrative = _generate_client_narrative(
            outcome_analysis,
            patterns,
            operational_status,
            category_analysis["dominant"],
        )
        
        # Determine highest severity
        highest_severity = "info"
        if patterns:
            if any(p.severity == "alert" for p in patterns):
                highest_severity = "alert"
            elif any(p.severity == "warning" for p in patterns):
                highest_severity = "warning"
        
        time_window = _compute_time_window(runs)
        
        result = TelemetrySummary(
            summary=summary,
            time_window=time_window,
            total_runs_analyzed=len(runs),
            outcome_counts=outcome_analysis["counts"],
            blocked_rate=outcome_analysis["blocked_rate"],
            flagged_rate=outcome_analysis["flagged_rate"],
            vulnerable_rate=outcome_analysis["vulnerable_rate"],
            patterns=patterns,
            pattern_count=len(patterns),
            highest_severity=highest_severity,
            avg_latency_ms=latency_analysis["avg"],
            min_latency_ms=latency_analysis["min"],
            max_latency_ms=latency_analysis["max"],
            latency_anomalies=latency_analysis["anomalies"],
            category_distribution=category_analysis["distribution"],
            dominant_category=category_analysis["dominant"],
            client_narrative=client_narrative,
            operational_status=operational_status,
        )
        
        logger.info(
            f"Telemetry Analyst completed: status={operational_status}, patterns={len(patterns)}",
            extra={"correlation_id": correlation_id}
        )
        
        return result


# =============================================================================
# SINGLETON ACCESS
# =============================================================================

_executor_instance: Optional[TelemetryAnalystExecutor] = None


def get_telemetry_analyst_executor() -> TelemetryAnalystExecutor:
    """Get the singleton Telemetry Analyst executor instance."""
    global _executor_instance
    if _executor_instance is None:
        _executor_instance = TelemetryAnalystExecutor()
    return _executor_instance
