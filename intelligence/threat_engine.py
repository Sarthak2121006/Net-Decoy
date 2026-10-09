"""
NetDecoy - Deterministic Threat & Attack Detection Engine
Module: intelligence/threat_engine.py

Responsible for applying rule-based detection algorithms on observed decoy interactions.
Detection is strictly deterministic and explainable. No LLM or unverified ML is used
for security-critical detection decisions. Malicious payloads are never executed.
"""

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple


class AttackDetection:
    """Represents a standardized attack detection result."""

    def __init__(
        self,
        attack_type: str,
        detected: bool,
        severity: str,
        evidence: List[str],
        timestamp: Optional[str] = None,
        event_id: Optional[str] = None,
    ):
        self.attack_type = attack_type
        self.detected = detected
        self.severity = severity.upper()
        self.evidence = evidence
        self.timestamp = timestamp or datetime.now(timezone.utc).isoformat()
        self.event_id = event_id

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "attack_type": self.attack_type,
            "detected": self.detected,
            "severity": self.severity,
            "evidence": self.evidence,
            "timestamp": self.timestamp,
        }
        if self.event_id:
            data["event_id"] = self.event_id
        return data


class BruteForceDetector:
    """
    Detects brute force authentication attacks against login decoys.
    Triggers when repeated failed login events occur within a session or time window.
    """

    def __init__(self, failure_threshold: int = 3, window_seconds: int = 120):
        self.failure_threshold = failure_threshold
        self.window_seconds = window_seconds

    def evaluate_session(self, events: List[Dict[str, Any]]) -> Optional[AttackDetection]:
        failed_logins: List[Dict[str, Any]] = []
        targeted_usernames: Set[str] = set()

        for event in events:
            action = str(event.get("action", "")).lower()
            page = str(event.get("page", "")).lower()
            event_type = str(event.get("event_type", "")).lower()

            if action == "failed_login" or (page == "login" and event_type == "authentication" and "fail" in action):
                failed_logins.append(event)
                payload = event.get("payload", {})
                if isinstance(payload, dict):
                    username = payload.get("username")
                    if username:
                        targeted_usernames.add(str(username))

        count = len(failed_logins)
        if count >= self.failure_threshold:
            severity = "HIGH" if count >= 5 else "MEDIUM"
            evidence = [
                f"{count} failed login attempts observed in session (threshold: {self.failure_threshold})",
            ]
            if targeted_usernames:
                evidence.append(f"Targeted usernames: {', '.join(sorted(targeted_usernames))}")

            latest_event = failed_logins[-1]
            return AttackDetection(
                attack_type="BRUTE_FORCE",
                detected=True,
                severity=severity,
                evidence=evidence,
                timestamp=latest_event.get("timestamp"),
                event_id=latest_event.get("event_id"),
            )
        return None


class ScanningDetector:
    """
    Detects endpoint enumeration and rapid multi-page reconnaissance.
    Triggers when a session probes multiple distinct endpoints rapidly.
    """

    def __init__(self, distinct_endpoint_threshold: int = 3):
        self.distinct_endpoint_threshold = distinct_endpoint_threshold
        self.monitored_pages = {"login", "admin", "api", "backup", "database", "search"}

    def evaluate_session(self, events: List[Dict[str, Any]]) -> Optional[AttackDetection]:
        observed_pages: Set[str] = set()
        probed_paths: Set[str] = set()

        for event in events:
            page = str(event.get("page", "")).lower()
            if page in self.monitored_pages:
                observed_pages.add(page)

            payload = event.get("payload", {})
            if isinstance(payload, dict):
                path = payload.get("endpoint") or payload.get("path") or payload.get("url")
                if path:
                    probed_paths.add(str(path))

        distinct_count = len(observed_pages)
        if distinct_count >= self.distinct_endpoint_threshold or len(probed_paths) >= 4:
            severity = "HIGH" if distinct_count >= 5 else "MEDIUM"
            evidence = [
                f"Probed {distinct_count} distinct decoy resource pages: {', '.join(sorted(observed_pages))}",
            ]
            if probed_paths:
                evidence.append(f"Endpoints enumerated: {', '.join(sorted(list(probed_paths)[:5]))}")

            latest_event = events[-1] if events else {}
            return AttackDetection(
                attack_type="SCANNING",
                detected=True,
                severity=severity,
                evidence=evidence,
                timestamp=latest_event.get("timestamp"),
                event_id=latest_event.get("event_id"),
            )
        return None


class SQLInjectionDetector:
    """
    Detects controlled suspicious query patterns in inputs submitted to database or search traps.
    Never executes malicious queries; static syntactic analysis only.
    """

    # Comprehensive SQL injection patterns
    PATTERNS: List[Tuple[str, str]] = [
        (r"(?i)\bunion\s+(all\s+)?select\b", "UNION-based data extraction pattern"),
        (r"(?i)'\s*or\s*['\"]?\d+['\"]?\s*=\s*['\"]?\d+", "OR-based boolean authentication bypass pattern"),
        (r"(?i)\bor\s+1\s*=\s*1\b", "Classic 'OR 1=1' tautology bypass"),
        (r"(?i)'\s*or\s*'[^']*'\s*=\s*'[^']*'", "String equality tautology pattern"),
        (r"(?i)(--|#|/\*|\*/)", "SQL comment syntax truncation pattern"),
        (r"(?i)\b(sleep|benchmark)\s*\(", "Time-based blind SQL injection pattern"),
        (r"(?i)\bexec(\s*|\+)+(sp_|xp_)", "Stored procedure execution invocation"),
        (r"(?i)\bdrop\s+table\b", "Destructive DDL DROP TABLE pattern"),
        (r"(?i)\bselect\s+.*\s+from\s+information_schema", "Metadata schema extraction pattern"),
    ]

    def evaluate_event(self, event: Dict[str, Any]) -> Optional[AttackDetection]:
        payload = event.get("payload", {})
        if not isinstance(payload, dict):
            return None

        # Inspect query fields, search inputs, or username/password strings
        inspected_fields = ["query", "input", "sql", "search", "username", "filter"]
        detected_evidences: List[str] = []

        for field in inspected_fields:
            value = str(payload.get(field, "") or "")
            if not value:
                continue

            for pattern, description in self.PATTERNS:
                if re.search(pattern, value):
                    detected_evidences.append(f"{description} found in payload field '{field}': \"{value[:80]}\"")

        if detected_evidences:
            return AttackDetection(
                attack_type="SQL_INJECTION",
                detected=True,
                severity="HIGH",
                evidence=list(dict.fromkeys(detected_evidences)),  # deduplicate
                timestamp=event.get("timestamp"),
                event_id=event.get("event_id"),
            )
        return None


class PathTraversalDetector:
    """
    Detects directory path traversal indicators in search/file decoys.
    Never resolves paths against the host filesystem.
    """

    PATTERNS: List[Tuple[str, str]] = [
        (r"\.\./|\.\.\\", "Directory step-up sequence ('../' or '..\\')"),
        (r"(%2e|%2E){2}(%2f|%2F|%5c|%5C)", "URL-encoded directory traversal sequence"),
        (r"\.\.%2f|\.\.%5c", "Partially encoded traversal pattern"),
        (r"%00|\x00", "Null byte termination injection"),
        (r"(?i)/etc/(passwd|shadow|hosts)", "Targeting Unix sensitive system file"),
        (r"(?i)(c:|c:\\|windows\\system32|win\.ini|boot\.ini)", "Targeting Windows system files"),
    ]

    def evaluate_event(self, event: Dict[str, Any]) -> Optional[AttackDetection]:
        payload = event.get("payload", {})
        if not isinstance(payload, dict):
            return None

        inspected_fields = ["path", "file", "filename", "search", "query", "url"]
        detected_evidences: List[str] = []

        for field in inspected_fields:
            value = str(payload.get(field, "") or "")
            if not value:
                continue

            for pattern, description in self.PATTERNS:
                if re.search(pattern, value):
                    detected_evidences.append(f"{description} found in payload field '{field}': \"{value[:80]}\"")

        if detected_evidences:
            return AttackDetection(
                attack_type="PATH_TRAVERSAL",
                detected=True,
                severity="HIGH",
                evidence=list(dict.fromkeys(detected_evidences)),
                timestamp=event.get("timestamp"),
                event_id=event.get("event_id"),
            )
        return None


class SensitiveAccessDetector:
    """
    Detects interactions with decoy confidential assets such as backup dumps,
    customer databases, configuration files, or admin portals.
    """

    SENSITIVE_TARGETS: List[Tuple[str, str]] = [
        (r"(?i)\.sql(\.gz)?$", "Attempt to access synthetic SQL database dump"),
        (r"(?i)\.bak$", "Attempt to access synthetic backup archive"),
        (r"(?i)(customer|client|user|credit_card|payroll)", "Targeting simulated confidential enterprise records"),
        (r"(?i)(config|\.env|secrets|credentials|passwords?\.txt)", "Targeting synthetic credentials or configuration file"),
    ]

    def evaluate_event(self, event: Dict[str, Any]) -> Optional[AttackDetection]:
        page = str(event.get("page", "")).lower()
        action = str(event.get("action", "")).lower()
        payload = event.get("payload", {})
        if not isinstance(payload, dict):
            payload = {}

        evidence: List[str] = []
        is_sensitive = False

        if page == "backup":
            is_sensitive = True
            evidence.append("Direct interaction with decoy backup portal")
            if "download" in action:
                evidence.append(f"Decoy backup file download initiated (action: {action})")

        # Inspect target filenames or resources
        resource_name = str(payload.get("file") or payload.get("filename") or payload.get("path") or payload.get("resource") or "")
        if resource_name:
            for pattern, desc in self.SENSITIVE_TARGETS:
                if re.search(pattern, resource_name):
                    is_sensitive = True
                    evidence.append(f"{desc}: \"{resource_name}\"")

        if is_sensitive and evidence:
            return AttackDetection(
                attack_type="SENSITIVE_ACCESS",
                detected=True,
                severity="HIGH",
                evidence=list(dict.fromkeys(evidence)),
                timestamp=event.get("timestamp"),
                event_id=event.get("event_id"),
            )
        return None


class ThreatEngine:
    """
    Master Detection Engine orchestrating rule-based detection modules.
    Evaluates both individual incoming events and accumulated session events.
    """

    def __init__(self):
        self.brute_force_detector = BruteForceDetector()
        self.scanning_detector = ScanningDetector()
        self.sqli_detector = SQLInjectionDetector()
        self.traversal_detector = PathTraversalDetector()
        self.sensitive_detector = SensitiveAccessDetector()

    def evaluate_event(self, event: Dict[str, Any]) -> List[AttackDetection]:
        """Runs single-event rule detectors."""
        detections: List[AttackDetection] = []

        # SQL Injection
        sqli = self.sqli_detector.evaluate_event(event)
        if sqli:
            detections.append(sqli)

        # Path Traversal
        trav = self.traversal_detector.evaluate_event(event)
        if trav:
            detections.append(trav)

        # Sensitive Resource Access
        sens = self.sensitive_detector.evaluate_event(event)
        if sens:
            detections.append(sens)

        return detections

    def evaluate_session(self, events: List[Dict[str, Any]]) -> List[AttackDetection]:
        """
        Runs comprehensive evaluation over an entire session's events,
        combining single-event detectors and multi-event correlation detectors.
        """
        if not events:
            return []

        all_detections: List[AttackDetection] = []
        seen_types: Set[str] = set()

        # 1. Multi-event detectors
        bf = self.brute_force_detector.evaluate_session(events)
        if bf:
            all_detections.append(bf)
            seen_types.add(bf.attack_type)

        scan = self.scanning_detector.evaluate_session(events)
        if scan:
            all_detections.append(scan)
            seen_types.add(scan.attack_type)

        # 2. Per-event detectors across history
        for ev in events:
            event_detections = self.evaluate_event(ev)
            for det in event_detections:
                # Group or keep unique per attack_type with merged evidence
                existing = next((d for d in all_detections if d.attack_type == det.attack_type), None)
                if existing:
                    for ev_item in det.evidence:
                        if ev_item not in existing.evidence:
                            existing.evidence.append(ev_item)
                else:
                    all_detections.append(det)
                    seen_types.add(det.attack_type)

        # 3. Repeated suspicious behavior rule
        if len(seen_types) >= 3 or len(events) >= 8 and len(seen_types) >= 2:
            repeated_det = AttackDetection(
                attack_type="REPEATED_SUSPICIOUS",
                detected=True,
                severity="HIGH",
                evidence=[
                    f"Session exhibited multiple suspicious attack patterns ({', '.join(sorted(seen_types))}) across {len(events)} interactions"
                ],
                timestamp=events[-1].get("timestamp"),
                event_id=events[-1].get("event_id"),
            )
            all_detections.append(repeated_det)

        return all_detections
