"""
NetDecoy - Explainable Risk Scoring Engine
Module: intelligence/risk_engine.py

Calculates bounded (0-100), deterministic risk scores with clear breakdowns.
Risk assessment is explainable and idempotent: reading risk scores never compounds them.
"""

from typing import Any, Dict, List, Optional


class RiskEngine:
    """
    Evaluates observed attack detections and calculates an explainable risk score (0-100).
    """

    DEFAULT_WEIGHTS: Dict[str, int] = {
        "BRUTE_FORCE": 20,
        "SCANNING": 20,
        "SQL_INJECTION": 30,
        "PATH_TRAVERSAL": 30,
        "SENSITIVE_ACCESS": 20,
        "REPEATED_SUSPICIOUS": 10,
    }

    def __init__(self, weights: Optional[Dict[str, int]] = None):
        self.weights = dict(self.DEFAULT_WEIGHTS)
        if weights:
            self.weights.update(weights)

    def calculate_level(self, score: int) -> str:
        """Categorizes numeric risk into standard severity bands."""
        if score < 30:
            return "LOW"
        elif score < 60:
            return "MEDIUM"
        elif score < 80:
            return "HIGH"
        else:
            return "CRITICAL"

    def calculate_risk(
        self,
        detections: List[Any],
        session_id: Optional[str] = None,
        event_count: int = 0
    ) -> Dict[str, Any]:
        """
        Calculates the risk score from a collection of AttackDetection objects or dicts.

        Ensures score is bounded within [0, 100].
        Produces detailed breakdown and supporting signals for complete explainability.
        """
        raw_score = 0
        breakdown: Dict[str, int] = {}
        signals: List[Dict[str, Any]] = []

        seen_attack_types = set()

        for det in detections:
            # Handle both AttackDetection objects and raw dicts
            if hasattr(det, "attack_type"):
                attack_type = det.attack_type
                evidence = det.evidence
                severity = det.severity
            elif isinstance(det, dict):
                attack_type = det.get("attack_type", "")
                evidence = det.get("evidence", [])
                severity = det.get("severity", "MEDIUM")
            else:
                continue

            if not attack_type or attack_type in seen_attack_types:
                continue

            seen_attack_types.add(attack_type)
            points = self.weights.get(attack_type, 15)
            key_name = attack_type.lower()

            breakdown[key_name] = points
            raw_score += points

            signals.append({
                "signal": attack_type.replace("_", " ").title(),
                "attack_type": attack_type,
                "points": points,
                "severity": severity,
                "evidence": evidence,
            })

        # Add velocity / volume signal if many events are present without specific detections
        if event_count > 10 and "REPEATED_SUSPICIOUS" not in seen_attack_types:
            volume_points = min(10, (event_count - 10) * 2)
            if volume_points > 0:
                raw_score += volume_points
                breakdown["high_event_volume"] = volume_points
                signals.append({
                    "signal": "High Event Velocity",
                    "attack_type": "HIGH_EVENT_VOLUME",
                    "points": volume_points,
                    "severity": "LOW",
                    "evidence": [f"Session generated {event_count} total interactions"],
                })

        final_score = min(max(raw_score, 0), 100)
        level = self.calculate_level(final_score)

        result: Dict[str, Any] = {
            "score": final_score,
            "level": level,
            "breakdown": breakdown,
            "signals": signals,
        }

        if session_id:
            result["session_id"] = session_id

        return result
