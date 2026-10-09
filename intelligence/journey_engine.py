"""
NetDecoy - Attacker Journey & Stage Progression Engine
Module: intelligence/journey_engine.py

Maps observed decoy interactions and detections into chronological attack progression stages.
Stages are based strictly on evidence, without assuming unobserved steps.
"""

from typing import Any, Dict, List, Optional, Set


class JourneyEngine:
    """
    Constructs an attacker journey timeline and tracks progression across MITRE-aligned deception stages:
    RECONNAISSANCE -> SCANNING -> CREDENTIAL_ACCESS -> RESOURCE_DISCOVERY -> PRIVILEGE_ESCALATION -> DATA_ACCESS
    """

    STAGES_ORDER = [
        "RECONNAISSANCE",
        "SCANNING",
        "CREDENTIAL_ACCESS",
        "RESOURCE_DISCOVERY",
        "PRIVILEGE_ESCALATION",
        "DATA_ACCESS",
    ]

    def __init__(self):
        pass

    def map_event_to_stage(self, event: Dict[str, Any], detections: List[Any]) -> str:
        """
        Determines the most accurate attack stage for a specific event based on
        its associated detections, target page, and interaction action.
        """
        # 1. Prioritize direct attack detections
        detection_types = set()
        for det in detections:
            if hasattr(det, "attack_type"):
                detection_types.add(det.attack_type)
            elif isinstance(det, dict):
                detection_types.add(det.get("attack_type"))

        if "SENSITIVE_ACCESS" in detection_types or "PATH_TRAVERSAL" in detection_types:
            return "DATA_ACCESS"
        if "SQL_INJECTION" in detection_types:
            return "PRIVILEGE_ESCALATION"
        if "BRUTE_FORCE" in detection_types:
            return "CREDENTIAL_ACCESS"
        if "SCANNING" in detection_types:
            return "SCANNING"

        # 2. Evaluate resource page and action context
        page = str(event.get("page", "")).lower()
        action = str(event.get("action", "")).lower()
        event_type = str(event.get("event_type", "")).lower()

        if page == "backup" or "download" in action or "export" in action:
            return "DATA_ACCESS"

        if page == "database" or "sql" in action:
            return "PRIVILEGE_ESCALATION"

        if page == "admin" or page == "api" or "probe" in action:
            return "RESOURCE_DISCOVERY"

        if page == "login" and ("auth" in event_type or "login" in action):
            return "CREDENTIAL_ACCESS"

        if action in ("endpoint_probe", "port_scan", "url_scan") or page in ("api", "admin"):
            return "SCANNING"

        # Default fallback for initial passive interactions
        return "RECONNAISSANCE"

    def build_journey(
        self,
        events: List[Dict[str, Any]],
        detections: Optional[List[Any]] = None,
        session_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Processes a sequence of session events and generates a chronological timeline
        with stage mappings and progression analysis.
        """
        timeline: List[Dict[str, Any]] = []
        stages_visited_set: Set[str] = set()
        stages_visited_ordered: List[str] = []

        all_detections = detections or []

        for index, event in enumerate(events, start=1):
            event_id = event.get("event_id")

            # Find matching detections for this event if applicable
            event_detections = [
                d for d in all_detections
                if (hasattr(d, "event_id") and d.event_id == event_id) or
                   (isinstance(d, dict) and d.get("event_id") == event_id)
            ]

            stage = self.map_event_to_stage(event, event_detections)

            if stage not in stages_visited_set:
                stages_visited_set.add(stage)
                stages_visited_ordered.append(stage)

            # Generate descriptive human-readable detail
            page = event.get("page", "unknown")
            action = event.get("action", "interaction")
            payload = event.get("payload", {})
            detail = self._generate_detail(page, action, payload, stage, event_detections)

            timeline_entry: Dict[str, Any] = {
                "step": index,
                "event_id": event_id,
                "timestamp": event.get("timestamp"),
                "page": page,
                "action": action,
                "stage": stage,
                "detail": detail,
            }

            if event_detections:
                first_det = event_detections[0]
                att_name = first_det.attack_type if hasattr(first_det, "attack_type") else first_det.get("attack_type")
                timeline_entry["detection"] = att_name

            timeline.append(timeline_entry)

        current_stage = stages_visited_ordered[-1] if stages_visited_ordered else "RECONNAISSANCE"

        # Sort stages_visited according to canonical sequence order
        canonical_stages = [s for s in self.STAGES_ORDER if s in stages_visited_set]

        result: Dict[str, Any] = {
            "current_stage": current_stage,
            "stages_visited": canonical_stages,
            "stage_count": len(canonical_stages),
            "timeline": timeline,
            "total_steps": len(timeline),
        }

        if session_id:
            result["session_id"] = session_id

        return result

    def _generate_detail(
        self,
        page: str,
        action: str,
        payload: Any,
        stage: str,
        detections: List[Any]
    ) -> str:
        """Constructs concise narrative descriptions for timeline steps."""
        if not isinstance(payload, dict):
            payload = {}

        if detections:
            first_det = detections[0]
            att_name = first_det.attack_type if hasattr(first_det, "attack_type") else first_det.get("attack_type")
            return f"Detected {att_name} on /{page} (Action: {action})"

        if page == "login":
            user = payload.get("username", "unspecified")
            return f"Authentication attempt on login decoy (Username: {user})"

        if page == "database":
            query = payload.get("query") or payload.get("sql") or "input submitted"
            return f"Database console interaction: \"{str(query)[:40]}\""

        if page == "backup":
            target = payload.get("file") or payload.get("filename") or "backup resource"
            return f"Decoy backup portal interaction targeting {target}"

        if page == "admin":
            return f"Enumeration of restricted admin dashboard features ({action})"

        if page == "search":
            q = payload.get("search") or payload.get("query") or payload.get("path") or ""
            return f"Search portal query submission: \"{str(q)[:40]}\""

        if page == "api":
            ep = payload.get("endpoint") or payload.get("path") or "endpoint"
            return f"Explored simulated internal API endpoint: {ep}"

        return f"Interaction with /{page} decoy resource ({action})"
