"""
Scenario service for managing attack scenarios.
Uses curated attack packs for organized scenario management.
"""

from typing import List, Optional, Dict, Any
from models.schemas import AttackScenario, AttackCategory
from .attack_packs import (
    get_all_scenarios,
    get_scenarios_by_category as get_pack_scenarios,
    get_scenario_by_id,
    get_pack_info,
    ALL_ATTACK_PACKS,
)


class ScenarioService:
    """
    Service for managing attack scenarios.
    Provides access to curated attack packs with organized scenarios.
    """
    
    def __init__(self):
        self._scenarios: Dict[str, AttackScenario] = {}
        self._load_curated_scenarios()
    
    def _load_curated_scenarios(self) -> None:
        """Load all curated attack scenarios from attack packs."""
        for scenario in get_all_scenarios():
            self._scenarios[scenario.id] = scenario
    
    def get_scenario(self, scenario_id: str) -> Optional[AttackScenario]:
        """Get a scenario by ID."""
        return self._scenarios.get(scenario_id)
    
    def get_all_scenarios(self) -> List[AttackScenario]:
        """Get all scenarios."""
        return list(self._scenarios.values())
    
    def get_scenarios_by_category(self, category: AttackCategory) -> List[AttackScenario]:
        """Get all scenarios for a specific category."""
        return [s for s in self._scenarios.values() if s.category == category]
    
    def get_categories(self) -> List[Dict[str, Any]]:
        """Get all categories with counts and metadata."""
        return get_pack_info()
    
    def get_category_names(self) -> List[str]:
        """Get list of all category names."""
        return [cat.value for cat in ALL_ATTACK_PACKS.keys()]
    
    def count_scenarios(self) -> int:
        """Get total scenario count."""
        return len(self._scenarios)
    
    def count_scenarios_by_category(self, category: AttackCategory) -> int:
        """Get scenario count for a specific category."""
        return len(self.get_scenarios_by_category(category))


# Singleton instance
_scenario_service: Optional[ScenarioService] = None


def get_scenario_service() -> ScenarioService:
    """Get the singleton scenario service."""
    global _scenario_service
    if _scenario_service is None:
        _scenario_service = ScenarioService()
    return _scenario_service

