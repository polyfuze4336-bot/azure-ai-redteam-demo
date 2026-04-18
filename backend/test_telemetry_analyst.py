"""
Test script for the Telemetry Analyst Agent.

Run from the backend directory:
    python test_telemetry_analyst.py
"""

import asyncio
import sys
import random
from datetime import datetime, timedelta

# Add parent to path for imports
sys.path.insert(0, ".")

from models.schemas import (
    AttackResult,
    Outcome,
    VerdictResult,
    VerdictDetail,
    AttackCategory,
    Severity,
)
from agents import get_agent_service, TelemetrySummary


def create_mock_run(
    run_id: str,
    category: AttackCategory,
    outcome: Outcome,
    shield_result: VerdictResult,
    latency_ms: int,
    minutes_ago: int = 0,
) -> AttackResult:
    """Create a mock attack result for testing."""
    return AttackResult(
        run_id=run_id,
        campaign_id="test-campaign-001",
        correlation_id=f"corr-{run_id}",
        timestamp=datetime.utcnow() - timedelta(minutes=minutes_ago),
        latency_ms=latency_ms,
        attack_category=category,
        scenario_name=f"{category.value} test scenario",
        scenario_id=f"{category.value[:2]}-001",
        severity=Severity.HIGH if outcome == Outcome.VULNERABLE else Severity.MEDIUM,
        prompt=f"Test prompt for {category.value} attack",
        normalized_prompt="",
        response="Test response from model",
        target_name="gpt-4o",
        shield_enabled=True,
        foundry_resource_name="mkhalib-4370-resource",
        deployment_name="gpt-4o",
        shield_verdict=VerdictDetail(
            result=shield_result,
            confidence=0.85 + random.random() * 0.15,
            categories_detected=[category.value],
            source="azure-ai-content-safety",
        ),
        model_verdict=VerdictDetail(
            result=VerdictResult.ALLOWED,
            confidence=0.8,
            source="model-self-assessment",
        ),
        evaluator_verdict=VerdictDetail(
            result=VerdictResult.ALLOWED if outcome == Outcome.VULNERABLE else VerdictResult.BLOCKED,
            confidence=0.9,
            source="post-hoc-evaluator",
        ),
        outcome=outcome,
    )


def create_healthy_run_history() -> list:
    """Create a run history showing healthy system behavior."""
    runs = []
    
    # Mix of blocked and safe outcomes
    runs.append(create_mock_run("run-001", AttackCategory.JAILBREAK, Outcome.SAFE, VerdictResult.BLOCKED, 245, 10))
    runs.append(create_mock_run("run-002", AttackCategory.PROMPT_INJECTION, Outcome.SAFE, VerdictResult.BLOCKED, 198, 8))
    runs.append(create_mock_run("run-003", AttackCategory.JAILBREAK, Outcome.SAFE, VerdictResult.ALLOWED, 312, 6))  # Model refused
    runs.append(create_mock_run("run-004", AttackCategory.DATA_EXFILTRATION, Outcome.SAFE, VerdictResult.BLOCKED, 267, 4))
    runs.append(create_mock_run("run-005", AttackCategory.POLICY_EVASION, Outcome.SAFE, VerdictResult.FLAGGED, 189, 2))
    
    return runs


def create_concerning_run_history() -> list:
    """Create a run history showing concerning patterns."""
    runs = []
    
    # High vulnerability rate with jailbreak concentration
    runs.append(create_mock_run("run-101", AttackCategory.JAILBREAK, Outcome.VULNERABLE, VerdictResult.ALLOWED, 845, 15))
    runs.append(create_mock_run("run-102", AttackCategory.JAILBREAK, Outcome.VULNERABLE, VerdictResult.ALLOWED, 1250, 12))  # Latency anomaly
    runs.append(create_mock_run("run-103", AttackCategory.JAILBREAK, Outcome.PARTIAL, VerdictResult.FLAGGED, 298, 10))
    runs.append(create_mock_run("run-104", AttackCategory.JAILBREAK, Outcome.SAFE, VerdictResult.BLOCKED, 312, 8))
    runs.append(create_mock_run("run-105", AttackCategory.PROMPT_INJECTION, Outcome.VULNERABLE, VerdictResult.ALLOWED, 267, 6))
    runs.append(create_mock_run("run-106", AttackCategory.JAILBREAK, Outcome.VULNERABLE, VerdictResult.ALLOWED, 445, 4))
    runs.append(create_mock_run("run-107", AttackCategory.JAILBREAK, Outcome.PARTIAL, VerdictResult.FLAGGED, 389, 2))
    
    return runs


def create_blocked_spike_history() -> list:
    """Create a run history with high block rate."""
    runs = []
    
    # High block rate scenario
    runs.append(create_mock_run("run-201", AttackCategory.JAILBREAK, Outcome.SAFE, VerdictResult.BLOCKED, 245, 10))
    runs.append(create_mock_run("run-202", AttackCategory.PROMPT_INJECTION, Outcome.SAFE, VerdictResult.BLOCKED, 198, 8))
    runs.append(create_mock_run("run-203", AttackCategory.JAILBREAK, Outcome.SAFE, VerdictResult.BLOCKED, 312, 6))
    runs.append(create_mock_run("run-204", AttackCategory.DATA_EXFILTRATION, Outcome.SAFE, VerdictResult.BLOCKED, 267, 4))
    runs.append(create_mock_run("run-205", AttackCategory.JAILBREAK, Outcome.SAFE, VerdictResult.BLOCKED, 189, 2))
    runs.append(create_mock_run("run-206", AttackCategory.POLICY_EVASION, Outcome.SAFE, VerdictResult.FLAGGED, 220, 1))
    
    return runs


async def test_telemetry_analyst():
    """Test the Telemetry Analyst Agent."""
    service = get_agent_service()
    
    print("=" * 60)
    print("TELEMETRY ANALYST AGENT TEST")
    print("=" * 60)
    
    # Test 1: Healthy run history
    print("\n[Test 1] Analyzing HEALTHY run history...")
    runs = create_healthy_run_history()
    
    invocation, summary = await service.invoke_telemetry_analyst(runs)
    
    print(f"  Invocation ID: {invocation.invocation_id[:8]}...")
    print(f"  Status: {invocation.status.value}")
    print(f"  Latency: {invocation.latency_ms}ms")
    print(f"\n  Summary:")
    print(f"    - Runs Analyzed: {summary.total_runs_analyzed}")
    print(f"    - Time Window: {summary.time_window}")
    print(f"    - Operational Status: {summary.operational_status}")
    print(f"    - Blocked Rate: {summary.blocked_rate:.1f}%")
    print(f"    - Patterns Detected: {summary.pattern_count}")
    print(f"    - Summary: {summary.summary}")
    
    # Test 2: Concerning run history
    print("\n[Test 2] Analyzing CONCERNING run history...")
    runs = create_concerning_run_history()
    
    invocation, summary = await service.invoke_telemetry_analyst(runs)
    
    print(f"  Invocation ID: {invocation.invocation_id[:8]}...")
    print(f"  Status: {invocation.status.value}")
    print(f"  Operational Status: {summary.operational_status}")
    print(f"  Vulnerable Rate: {summary.vulnerable_rate:.1f}%")
    print(f"  Patterns Detected: {summary.pattern_count}")
    for p in summary.patterns:
        print(f"    - [{p.severity.upper()}] {p.pattern_type}: {p.description[:60]}...")
    print(f"  Client Narrative: {summary.client_narrative[:100]}...")
    
    # Test 3: Blocked spike
    print("\n[Test 3] Analyzing BLOCKED SPIKE history...")
    runs = create_blocked_spike_history()
    
    invocation, summary = await service.invoke_telemetry_analyst(runs)
    
    print(f"  Invocation ID: {invocation.invocation_id[:8]}...")
    print(f"  Operational Status: {summary.operational_status}")
    print(f"  Blocked Rate: {summary.blocked_rate:.1f}%")
    print(f"  Dominant Category: {summary.dominant_category}")
    print(f"  Latency Stats: avg={summary.avg_latency_ms}ms, min={summary.min_latency_ms}ms, max={summary.max_latency_ms}ms")
    print(f"  Patterns: {[p.pattern_type for p in summary.patterns]}")
    
    # Test 4: Empty run history
    print("\n[Test 4] Analyzing EMPTY run history...")
    invocation, summary = await service.invoke_telemetry_analyst([])
    
    print(f"  Invocation ID: {invocation.invocation_id[:8]}...")
    print(f"  Runs Analyzed: {summary.total_runs_analyzed}")
    print(f"  Summary: {summary.summary}")
    
    # Test 5: Check invocation store
    print("\n[Test 5] Checking invocation store...")
    inv_summary = service.get_invocation_summary()
    print(f"  Total invocations: {inv_summary.total_invocations}")
    print(f"  By agent: {inv_summary.by_agent}")
    
    print("\n" + "=" * 60)
    print("ALL TESTS PASSED!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(test_telemetry_analyst())
