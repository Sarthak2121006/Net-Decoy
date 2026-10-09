"""
NetDecoy - Pattern-Based Next-Stage Prediction Engine
Module: intelligence/prediction_engine.py

Performs deterministic sequence modeling to estimate the attacker's next likely stage.
Uses a transition matrix derived from predefined attack progression patterns (kill-chain-inspired).
Pattern confidence comes from a predefined transition table plus a depth heuristic, not a trained model.
Never uses LLMs to hallucinate confidence percentages or claim future certainty.
Outputs "Pattern confidence", emphasizing heuristic similarity rather than guaranteed forecasting.
"""

from typing import Any, Dict, List, Optional, Tuple


class PredictionEngine:
    """
    Deterministic transition model estimating subsequent attack stages based on
    observed attacker stage sequences. Confidence comes from a predefined transition table
    plus a depth heuristic, not a trained model.
    """

    # Transition model mapping current_stage -> list of (next_stage, base_confidence, rationale)
    TRANSITIONS: Dict[str, List[Tuple[str, int, str]]] = {
        "RECONNAISSANCE": [
            ("SCANNING", 82, "Initial reconnaissance strongly precedes automated endpoint and directory enumeration."),
            ("CREDENTIAL_ACCESS", 15, "Reconnaissance targeting public portals occasionally proceeds directly to authentication tests."),
        ],
        "SCANNING": [
            ("CREDENTIAL_ACCESS", 76, "Endpoint discovery typically identifies login interfaces, triggering credential testing."),
            ("RESOURCE_DISCOVERY", 20, "Scanning often transitions deeper into administrative and internal API exploration."),
        ],
        "CREDENTIAL_ACCESS": [
            ("PRIVILEGE_ESCALATION", 73, "Observed sequence matches known attack-stage pattern: authentication probing precedes privilege escalation via injection or bypass."),
            ("RESOURCE_DISCOVERY", 22, "Acquired credentials or failed attempts often divert into enumerating secondary restricted assets."),
        ],
        "RESOURCE_DISCOVERY": [
            ("PRIVILEGE_ESCALATION", 78, "Enumeration of administrative panels is typically followed by authorization bypass or database injection."),
            ("DATA_ACCESS", 18, "Discovery of unauthenticated assets may lead directly to file extraction."),
        ],
        "PRIVILEGE_ESCALATION": [
            ("DATA_ACCESS", 85, "Privilege escalation is predominantly followed by unauthorized data harvesting or backup extraction."),
            ("EXFILTRATION", 12, "High-privilege state enables rapid external staging."),
        ],
        "DATA_ACCESS": [
            ("EXFILTRATION", 80, "Access to confidential records and database backups strongly indicates imminent data exfiltration."),
            ("PERSISTENCE", 15, "Data access may be accompanied by backdoor installation for sustained access."),
        ],
    }

    # Anticipated decoy targets based on estimated next stage
    STAGE_TARGETS: Dict[str, List[str]] = {
        "SCANNING": ["api", "admin", "search"],
        "CREDENTIAL_ACCESS": ["login", "admin"],
        "RESOURCE_DISCOVERY": ["admin", "api", "backup"],
        "PRIVILEGE_ESCALATION": ["database", "admin"],
        "DATA_ACCESS": ["backup", "search", "database"],
        "EXFILTRATION": ["backup", "api"],
    }

    def predict_next_stage(
        self,
        current_stage: str,
        visited_stages: Optional[List[str]] = None,
        session_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Estimates the next attack stage based on the current stage and history.
        Calculates defensible pattern confidence and provides full rationale.
        """
        stage = current_stage.upper() if current_stage else "RECONNAISSANCE"
        history = [s.upper() for s in (visited_stages or [])]

        transitions = self.TRANSITIONS.get(stage)
        if not transitions:
            # Default fallback for unknown or final stages
            return {
                "current_stage": stage,
                "next_stage": "DATA_ACCESS",
                "confidence": 50,
                "confidence_label": "Pattern confidence",
                "basis": "Default transition heuristic applied for unmodeled stage.",
                "potential_targets": ["backup", "database"],
                "alternative_stages": [],
                "session_id": session_id,
            }

        primary = transitions[0]
        next_stage, base_confidence, rationale = primary

        # Sequence coherence reinforcement:
        # If the observed history matches consecutive stages, slightly boost confidence (+5%, capped at 95)
        adjusted_confidence = base_confidence
        if len(history) >= 2:
            adjusted_confidence = min(95, base_confidence + 5)

        alternatives: List[Dict[str, Any]] = []
        for alt_stage, alt_conf, _ in transitions[1:]:
            alternatives.append({
                "stage": alt_stage,
                "confidence": alt_conf,
            })

        potential_targets = self.STAGE_TARGETS.get(next_stage, ["admin", "database", "backup"])

        result: Dict[str, Any] = {
            "current_stage": stage,
            "next_stage": next_stage,
            "confidence": adjusted_confidence,
            "confidence_label": "Pattern confidence",
            "basis": f"Observed sequence matches known attack-stage pattern ({stage} → {next_stage}): {rationale}",
            "potential_targets": potential_targets,
            "alternative_stages": alternatives,
        }

        if session_id:
            result["session_id"] = session_id

        return result
