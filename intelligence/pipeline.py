"""
NetDecoy - Unified Intelligence Pipeline Coordinator
Module: intelligence/pipeline.py

Orchestrates the complete behavior-to-intelligence pipeline:
Raw Events -> Normalize -> Detect -> Risk -> Attack Stage -> Journey -> AI Explanation -> Next-stage Prediction
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from intelligence.threat_engine import ThreatEngine, AttackDetection
from intelligence.risk_engine import RiskEngine
from intelligence.journey_engine import JourneyEngine
from intelligence.prediction_engine import PredictionEngine
from intelligence.ai_engine import AIEngine


class IntelligencePipeline:
    """
    End-to-end coordinator transforming raw decoy interactions into actionable threat intelligence.
    """

    def __init__(self, ai_api_key: Optional[str] = None):
        self.threat_engine = ThreatEngine()
        self.risk_engine = RiskEngine()
        self.journey_engine = JourneyEngine()
        self.prediction_engine = PredictionEngine()
        self.ai_engine = AIEngine(api_key=ai_api_key)

    def normalize_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Ensures incoming event has required fields and sanitized types."""
        normalized = dict(event)
        if "event_id" not in normalized:
            normalized["event_id"] = f"evt_{int(datetime.now(timezone.utc).timestamp() * 1000)}"
        if "session_id" not in normalized:
            normalized["session_id"] = "default_session"
        if "timestamp" not in normalized:
            normalized["timestamp"] = datetime.now(timezone.utc).isoformat()
        if "source_ip" not in normalized:
            normalized["source_ip"] = "127.0.0.1"
        if "page" not in normalized:
            normalized["page"] = "login"
        if "action" not in normalized:
            normalized["action"] = "interaction"
        if "event_type" not in normalized:
            normalized["event_type"] = "navigation"
        if "payload" not in normalized or not isinstance(normalized["payload"], dict):
            normalized["payload"] = {}

        return normalized

    def process_session(
        self,
        session_id: str,
        events: List[Dict[str, Any]],
        include_ai: bool = True
    ) -> Dict[str, Any]:
        """
        Executes the full intelligence pipeline on all events for a given session.
        """
        # 1. Normalize
        normalized_events = [self.normalize_event(ev) for ev in events]

        # 2. Detect
        detections = self.threat_engine.evaluate_session(normalized_events)
        detections_dict = [d.to_dict() for d in detections]
        detected_types = [d.attack_type for d in detections]

        # Extract all specific evidence strings
        evidence_list: List[str] = []
        for d in detections:
            evidence_list.extend(d.evidence)

        # 3. Risk
        risk_profile = self.risk_engine.calculate_risk(
            detections=detections,
            session_id=session_id,
            event_count=len(normalized_events)
        )

        # 4. Attack Journey & Stage Mapping
        journey_profile = self.journey_engine.build_journey(
            events=normalized_events,
            detections=detections,
            session_id=session_id
        )
        current_stage = journey_profile.get("current_stage", "RECONNAISSANCE")
        visited_stages = journey_profile.get("stages_visited", [])

        # 5. Next-Stage Prediction
        prediction_profile = self.prediction_engine.predict_next_stage(
            current_stage=current_stage,
            visited_stages=visited_stages,
            session_id=session_id
        )

        # 6. AI Explanation (with deterministic fallback)
        ai_profile = {}
        if include_ai:
            ai_profile = self.ai_engine.explain(
                session_id=session_id,
                risk_score=risk_profile["score"],
                risk_level=risk_profile["level"],
                detected_attacks=detected_types,
                evidence_list=evidence_list,
                events_summary=normalized_events
            )

        return {
            "session_id": session_id,
            "event_count": len(normalized_events),
            "detections": detections_dict,
            "detected_attack_types": detected_types,
            "risk": risk_profile,
            "journey": journey_profile,
            "prediction": prediction_profile,
            "ai_analysis": ai_profile,
            "processed_at": datetime.now(timezone.utc).isoformat(),
        }
