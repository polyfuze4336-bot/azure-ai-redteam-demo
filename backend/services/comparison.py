"""
Comparison service for running side-by-side attacks against baseline and guarded targets.

Supports:
- Same resource, different deployments (e.g., gpt-4o vs gpt-4o with shield)
- Different environments (separate endpoints)
"""

import uuid
from datetime import datetime
from typing import Optional, Dict, Any

from models.schemas import (
    AttackRequest,
    AttackResult,
    ComparisonRequest,
    ComparisonResult,
    ComparisonTargetResult,
    ComparisonTargetType,
    ComparisonConfigResponse,
    VerdictDetail,
    VerdictResult,
    Outcome,
)
from services.attack_runner import get_attack_runner
from services.scenarios import get_scenario_service
from config import get_settings
from telemetry import get_logger

logger = get_logger("comparison")


class ComparisonService:
    """
    Service for running side-by-side comparison attacks.
    
    Executes the same attack against two targets:
    - Baseline: Typically without shield protection
    - Guarded: Typically with shield protection
    
    Both can use the same Foundry resource (different deployments) or 
    completely different endpoints.
    """
    
    def __init__(self):
        self._settings = get_settings()
        self._attack_runner = get_attack_runner()
        self._scenario_service = get_scenario_service()
    
    def get_config(self) -> ComparisonConfigResponse:
        """Get current comparison mode configuration."""
        settings = self._settings
        
        baseline_deployment = settings.get_deployment_for_target("baseline") or settings.azure_openai_deployment_name or "gpt-4o"
        guarded_deployment = settings.get_deployment_for_target("guarded") or settings.azure_openai_deployment_name or "gpt-4o"
        
        is_same_resource = settings.is_same_resource_comparison
        
        if is_same_resource:
            comparison_type = "same_resource_different_deployments"
        else:
            comparison_type = "different_environments"
        
        return ComparisonConfigResponse(
            enabled=settings.comparison_mode_configured,
            is_same_resource=is_same_resource,
            comparison_type=comparison_type,
            foundry_resource_name=settings.foundry_resource_name or "mkhalib-4370-resource",
            baseline={
                "deployment_name": baseline_deployment,
                "shield_enabled": settings.baseline_shield_enabled,
                "endpoint": self._mask_endpoint(settings.get_endpoint_for_target("baseline")),
            },
            guarded={
                "deployment_name": guarded_deployment,
                "shield_enabled": settings.guarded_shield_enabled,
                "endpoint": self._mask_endpoint(settings.get_endpoint_for_target("guarded")),
            },
        )
    
    def _mask_endpoint(self, endpoint: Optional[str]) -> str:
        """Mask endpoint URL for display."""
        if not endpoint:
            return "default"
        # Show just the resource name portion
        if "openai.azure.com" in endpoint:
            parts = endpoint.split("//")
            if len(parts) > 1:
                resource = parts[1].split(".")[0]
                return f"https://{resource}.openai.azure.com/..."
        return endpoint[:30] + "..." if len(endpoint) > 30 else endpoint
    
    async def run_comparison(self, request: ComparisonRequest) -> ComparisonResult:
        """
        Run a side-by-side comparison attack.
        
        Args:
            request: Comparison request with scenario and optional overrides
            
        Returns:
            ComparisonResult with results from both targets
        """
        comparison_id = str(uuid.uuid4())
        timestamp = datetime.utcnow()
        
        # Get scenario details
        scenario = self._scenario_service.get_scenario(request.scenario_id)
        if not scenario:
            raise ValueError(f"Scenario not found: {request.scenario_id}")
        
        prompt = request.custom_prompt or scenario.prompt
        
        # Determine deployment and shield settings
        settings = self._settings
        
        baseline_deployment = request.baseline_deployment or \
            settings.get_deployment_for_target("baseline") or \
            settings.azure_openai_deployment_name or "gpt-4o"
        
        guarded_deployment = request.guarded_deployment or \
            settings.get_deployment_for_target("guarded") or \
            settings.azure_openai_deployment_name or "gpt-4o"
        
        baseline_shield = request.baseline_shield_enabled if request.baseline_shield_enabled is not None \
            else settings.baseline_shield_enabled
        
        guarded_shield = request.guarded_shield_enabled if request.guarded_shield_enabled is not None \
            else settings.guarded_shield_enabled
        
        logger.info(
            f"Running comparison: {scenario.name} | "
            f"Baseline: {baseline_deployment} (shield={baseline_shield}) | "
            f"Guarded: {guarded_deployment} (shield={guarded_shield})"
        )
        
        # Run baseline attack
        baseline_request = AttackRequest(
            scenario_id=request.scenario_id,
            target_model=baseline_deployment,
            shield_enabled=baseline_shield,
            custom_prompt=request.custom_prompt,
            metadata={"comparison_id": comparison_id, "target_type": "baseline"},
        )
        baseline_result = await self._attack_runner.run_attack(baseline_request)
        
        # Run guarded attack
        guarded_request = AttackRequest(
            scenario_id=request.scenario_id,
            target_model=guarded_deployment,
            shield_enabled=guarded_shield,
            custom_prompt=request.custom_prompt,
            metadata={"comparison_id": comparison_id, "target_type": "guarded"},
        )
        guarded_result = await self._attack_runner.run_attack(guarded_request)
        
        # Determine comparison type
        is_same_resource = settings.is_same_resource_comparison
        comparison_type = "same_resource_different_deployments" if is_same_resource else "different_environments"
        
        # Build target results
        baseline_target = self._build_target_result(
            baseline_result, 
            ComparisonTargetType.BASELINE,
            settings.foundry_resource_name or "mkhalib-4370-resource",
        )
        
        guarded_target = self._build_target_result(
            guarded_result,
            ComparisonTargetType.GUARDED,
            settings.foundry_resource_name or "mkhalib-4370-resource",
        )
        
        # Calculate comparison metrics
        latency_diff = guarded_result.latency_ms - baseline_result.latency_ms
        baseline_success = baseline_result.outcome == Outcome.VULNERABLE
        guarded_success = guarded_result.outcome == Outcome.VULNERABLE
        
        # Determine shield effectiveness
        if baseline_success and not guarded_success:
            shield_effectiveness = "Shield successfully blocked the attack that bypassed baseline"
        elif not baseline_success and not guarded_success:
            shield_effectiveness = "Both targets blocked the attack"
        elif baseline_success and guarded_success:
            shield_effectiveness = "Attack succeeded on both targets - additional protections may be needed"
        else:
            shield_effectiveness = "Baseline blocked but guarded allowed - unexpected result"
        
        return ComparisonResult(
            comparison_id=comparison_id,
            timestamp=timestamp,
            scenario_id=request.scenario_id,
            scenario_name=scenario.name,
            attack_category=scenario.category,
            severity=scenario.severity,
            prompt=prompt,
            expected_defense=scenario.expected_defense,
            is_same_resource=is_same_resource,
            comparison_type=comparison_type,
            baseline=baseline_target,
            guarded=guarded_target,
            latency_difference_ms=latency_diff,
            baseline_attack_success=baseline_success,
            guarded_attack_success=guarded_success,
            shield_effectiveness=shield_effectiveness,
        )
    
    def _build_target_result(
        self,
        result: AttackResult,
        target_type: ComparisonTargetType,
        foundry_resource: str,
    ) -> ComparisonTargetResult:
        """Build a ComparisonTargetResult from an AttackResult."""
        return ComparisonTargetResult(
            target_type=target_type,
            deployment_name=result.deployment_name or result.target_name,
            foundry_resource_name=result.foundry_resource_name or foundry_resource,
            endpoint_url=self._mask_endpoint(self._settings.get_endpoint_for_target(target_type.value)),
            shield_enabled=result.shield_enabled,
            response=result.response,
            latency_ms=result.latency_ms,
            tokens_used=result.tokens_used,
            shield_verdict=result.shield_verdict,
            model_verdict=result.model_verdict,
            evaluator_verdict=result.evaluator_verdict,
            outcome=result.outcome,
            correlation_id=result.correlation_id,
        )


# Singleton instance
_comparison_service: Optional[ComparisonService] = None


def get_comparison_service() -> ComparisonService:
    """Get the comparison service singleton."""
    global _comparison_service
    if _comparison_service is None:
        _comparison_service = ComparisonService()
    return _comparison_service
