"""
NetDecoy - Deterministic Threat & Attack Detection Engine
Module: intelligence/threat_engine.py

Responsible for applying rule-based detection algorithms on observed decoy interactions.
Detection is strictly deterministic and explainable. No LLM or unverified ML is used
for security-critical detection decisions. Malicious payloads are never executed.

Hardened with:
- Out-of-order timestamp sorting and event deduplication by event_id
- Time-window sliding evaluation for brute force (per session and per source_ip)
- Obfuscation resilience (mixed case, inline /**/ comments, double URL-encoding)
- False positive resistance for benign texts containing apostrophes, 'select', or '../'
- Comprehensive rule_id, threshold, and matched pattern attribution in evidence
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
        rule_id: Optional[str] = None,
        threshold: Optional[str] = None,
        matched_pattern: Optional[str] = None,
    ):
        self.attack_type = attack_type
        self.detected = detected
        self.severity = severity.upper()
        self.evidence = evidence
        self.timestamp = timestamp or datetime.now(timezone.utc).isoformat()
        self.event_id = event_id
        self.rule_id = rule_id or f"RULE_{attack_type}"
        self.threshold = threshold or "Configured rule threshold"
        self.matched_pattern = matched_pattern or (evidence[0] if evidence else "")

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "attack_type": self.attack_type,
            "detected": self.detected,
            "severity": self.severity,
            "evidence": self.evidence,
            "timestamp": self.timestamp,
            "rule_id": self.rule_id,
            "threshold": self.threshold,
            "matched_pattern": self.matched_pattern,
        }
        if self.event_id:
            data["event_id"] = self.event_id
        return data


def parse_timestamp(ts: Any) -> Optional[float]:
    """Helper to safely parse ISO timestamps into epoch floats."""
    if not ts or not isinstance(ts, str):
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
    except Exception:
        return None


class BruteForceDetector:
    """
    Detects brute force authentication attacks against login decoys.
    Uses sliding time windows and evaluates counts both per session and per source_ip.
    """

    def __init__(self, failure_threshold: int = 3, window_seconds: int = 120):
        self.failure_threshold = failure_threshold
        self.window_seconds = window_seconds
        self.rule_id = "RULE_BRUTE_FORCE_01"

    def evaluate_session(self, events: List[Dict[str, Any]]) -> Optional[AttackDetection]:
        if not events:
            return None

        failed_by_session: Dict[str, List[Dict[str, Any]]] = {}
        failed_by_ip: Dict[str, List[Dict[str, Any]]] = {}
        all_failed_events: List[Dict[str, Any]] = []
        targeted_usernames: Set[str] = set()

        for event in events:
            if not isinstance(event, dict):
                continue
            action = str(event.get("action") or "").lower()
            page = str(event.get("page") or "").lower()
            event_type = str(event.get("event_type") or "").lower()

            if action == "failed_login" or (page == "login" and event_type == "authentication" and "fail" in action):
                all_failed_events.append(event)
                sess = str(event.get("session_id") or "default_session")
                ip = str(event.get("source_ip") or "unknown_ip")

                failed_by_session.setdefault(sess, []).append(event)
                failed_by_ip.setdefault(ip, []).append(event)

                payload = event.get("payload")
                if isinstance(payload, dict):
                    username = payload.get("username")
                    if username:
                        targeted_usernames.add(str(username))

        def check_window(event_list: List[Dict[str, Any]]) -> Tuple[bool, int]:
            if len(event_list) < self.failure_threshold:
                return False, len(event_list)

            timed_events = []
            for ev in event_list:
                t = parse_timestamp(ev.get("timestamp"))
                if t is not None:
                    timed_events.append(t)

            if timed_events:
                timed_events.sort()
                max_in_window = 0
                for start_idx in range(len(timed_events)):
                    start_t = timed_events[start_idx]
                    count_in_w = sum(1 for t in timed_events[start_idx:] if t - start_t <= self.window_seconds)
                    if count_in_w > max_in_window:
                        max_in_window = count_in_w
                if max_in_window >= self.failure_threshold:
                    return True, max_in_window
                return False, max_in_window

            # Fallback only if events completely lack timestamps
            if len(event_list) >= self.failure_threshold:
                return True, len(event_list)

            return False, len(event_list)

        triggered = False
        highest_count = 0

        for sess_id, ev_list in failed_by_session.items():
            hit, count = check_window(ev_list)
            if hit:
                triggered = True
                if count > highest_count:
                    highest_count = count

        for ip_addr, ev_list in failed_by_ip.items():
            hit, count = check_window(ev_list)
            if hit:
                triggered = True
                if count > highest_count:
                    highest_count = count

        if triggered:
            count = highest_count or len(all_failed_events)
            severity = "HIGH" if count >= 5 else "MEDIUM"
            thresh_str = f"{self.failure_threshold} failed attempts in {self.window_seconds}s"
            matched_pat = f"Repeated failed authentication ({count} attempts)"

            evidence = [
                f"[rule_id: {self.rule_id} | threshold: {thresh_str}] {count} failed login attempts observed in session (threshold: {self.failure_threshold}) (matched pattern: {matched_pat})"
            ]
            if targeted_usernames:
                evidence.append(f"Targeted usernames: {', '.join(sorted(targeted_usernames))}")

            latest_event = all_failed_events[-1] if all_failed_events else {}
            return AttackDetection(
                attack_type="BRUTE_FORCE",
                detected=True,
                severity=severity,
                evidence=evidence,
                timestamp=latest_event.get("timestamp"),
                event_id=latest_event.get("event_id"),
                rule_id=self.rule_id,
                threshold=thresh_str,
                matched_pattern=matched_pat,
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
        self.rule_id = "RULE_SCANNING_01"

    def evaluate_session(self, events: List[Dict[str, Any]]) -> Optional[AttackDetection]:
        if not events:
            return None

        observed_pages: Set[str] = set()
        probed_paths: Set[str] = set()

        for event in events:
            if not isinstance(event, dict):
                continue
            page = str(event.get("page") or "").lower()
            if page in self.monitored_pages:
                observed_pages.add(page)

            payload = event.get("payload")
            if isinstance(payload, dict):
                path = payload.get("endpoint") or payload.get("path") or payload.get("url")
                if path:
                    probed_paths.add(str(path))

        distinct_count = len(observed_pages)
        if distinct_count >= self.distinct_endpoint_threshold or len(probed_paths) >= 4:
            severity = "HIGH" if distinct_count >= 5 else "MEDIUM"
            thresh_str = f"{self.distinct_endpoint_threshold} distinct decoy pages"
            matched_pat = f"Multi-endpoint enumeration ({distinct_count} distinct pages)"

            evidence = [
                f"[rule_id: {self.rule_id} | threshold: {thresh_str}] Probed {distinct_count} distinct decoy resource pages: {', '.join(sorted(observed_pages))} (matched pattern: {matched_pat})"
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
                rule_id=self.rule_id,
                threshold=thresh_str,
                matched_pattern=matched_pat,
            )

        return None


class SQLInjectionDetector:
    """
    Detects controlled suspicious query patterns in inputs submitted to database or search traps.
    Hardened against inline comments and mixed-case obfuscation.
    Never executes malicious queries; static syntactic analysis only.
    """

    def __init__(self):
        self.rule_id = "RULE_SQLI_01"
        self.threshold_desc = "SQL injection syntax signature match"

    # Robust patterns supporting inline comments (/**/) and mixed-case
    PATTERNS: List[Tuple[str, str]] = [
        (r"(?i)\bunion(?:\s+|/\*.*?\*/)+(?:all(?:\s+|/\*.*?\*/)+)?select\b", "UNION-based data extraction pattern"),
        (r"(?i)'?\s*or(?:\s+|/\*.*?\*/)+['\"]?\d+['\"]?\s*=\s*['\"]?\d+", "OR-based boolean authentication bypass pattern"),
        (r"(?i)(?:'|\")?\s*or(?:\s+|/\*.*?\*/)+1\s*=\s*1\b", "Classic 'OR 1=1' tautology bypass"),
        (r"(?i)'\s*or(?:\s+|/\*.*?\*/)+'[^']*'\s*=\s*'[^']*'", "String equality tautology pattern"),
        (r"(?i)'\s*(--|#|/\*)", "SQL comment syntax truncation pattern"),
        (r"(?i)\b(sleep|benchmark)(?:\s+|/\*.*?\*/)*\(", "Time-based blind SQL injection pattern"),
        (r"(?i)\bexec(?:\s+|/\*.*?\*/|\+)+(sp_|xp_)", "Stored procedure execution invocation"),
        (r"(?i)\bdrop(?:\s+|/\*.*?\*/)+table\b", "Destructive DDL DROP TABLE pattern"),
        (r"(?i)\bselect(?:\s+|/\*.*?\*/)+.*?\bfrom(?:\s+|/\*.*?\*/)+information_schema\b", "Metadata schema extraction pattern"),
    ]

    def evaluate_event(self, event: Dict[str, Any]) -> Optional[AttackDetection]:
        if not isinstance(event, dict):
            return None

        payload = event.get("payload")
        if not isinstance(payload, dict):
            return None

        inspected_fields = ["query", "input", "sql", "search", "username", "filter"]
        detected_evidences: List[str] = []
        matched_patterns: List[str] = []

        for field in inspected_fields:
            value = str(payload.get(field) or "")
            if not value:
                continue

            for pattern, description in self.PATTERNS:
                if re.search(pattern, value):
                    detected_evidences.append(
                        f"[rule_id: {self.rule_id} | threshold: {self.threshold_desc}] {description} found in payload field '{field}': \"{value[:80]}\" (matched pattern: {pattern})"
                    )
                    matched_patterns.append(description)

        if detected_evidences:
            return AttackDetection(
                attack_type="SQL_INJECTION",
                detected=True,
                severity="HIGH",
                evidence=list(dict.fromkeys(detected_evidences)),
                timestamp=event.get("timestamp"),
                event_id=event.get("event_id"),
                rule_id=self.rule_id,
                threshold=self.threshold_desc,
                matched_pattern="; ".join(dict.fromkeys(matched_patterns)),
            )

        return None


class PathTraversalDetector:
    """
    Detects directory path traversal indicators in search/file decoys.
    Resistant to double URL-encoding and avoids false positives on harmless text.
    Never resolves paths against the host filesystem.
    """

    def __init__(self):
        self.rule_id = "RULE_PATH_TRAVERSAL_01"
        self.threshold_desc = "Directory traversal signature match"

    # Supports step-up sequences, single & double URL encoding (%252e%252e%252f), null bytes, and sensitive files
    PATTERNS: List[Tuple[str, str]] = [
        (r"(?:\.\.[/\\]){2,}", "Directory step-up sequence ('../' or '..\\')"),
        (r"\.\.[/\\][a-zA-Z0-9_\-\.]+", "Directory step-up sequence ('../' or '..\\')"),
        (r"(?i)(%252e|%2e){2}(%252f|%2f|%255c|%5c)", "URL-encoded directory traversal sequence"),
        (r"(?i)\.\.(%252f|%2f|%255c|%5c)", "Partially encoded traversal pattern"),
        (r"%00|\x00", "Null byte termination injection"),
        (r"(?i)/etc/(passwd|shadow|hosts)", "Targeting Unix sensitive system file"),
        (r"(?i)(c:|c:\\|windows\\system32|win\.ini|boot\.ini)", "Targeting Windows system files"),
    ]

    def evaluate_event(self, event: Dict[str, Any]) -> Optional[AttackDetection]:
        if not isinstance(event, dict):
            return None

        payload = event.get("payload")
        if not isinstance(payload, dict):
            return None

        inspected_fields = ["path", "file", "filename", "search", "query", "url"]
        detected_evidences: List[str] = []
        matched_patterns: List[str] = []

        for field in inspected_fields:
            value = str(payload.get(field) or "")
            if not value:
                continue

            for pattern, description in self.PATTERNS:
                if re.search(pattern, value):
                    detected_evidences.append(
                        f"[rule_id: {self.rule_id} | threshold: {self.threshold_desc}] {description} found in payload field '{field}': \"{value[:80]}\" (matched pattern: {pattern})"
                    )
                    matched_patterns.append(description)

        if detected_evidences:
            return AttackDetection(
                attack_type="PATH_TRAVERSAL",
                detected=True,
                severity="HIGH",
                evidence=list(dict.fromkeys(detected_evidences)),
                timestamp=event.get("timestamp"),
                event_id=event.get("event_id"),
                rule_id=self.rule_id,
                threshold=self.threshold_desc,
                matched_pattern="; ".join(dict.fromkeys(matched_patterns)),
            )

        return None


class SensitiveAccessDetector:
    """
    Detects interactions with decoy confidential assets such as backup dumps,
    customer databases, configuration files, or admin portals.
    """

    def __init__(self):
        self.rule_id = "RULE_SENSITIVE_ACCESS_01"
        self.threshold_desc = "Decoy confidential asset access match"

    SENSITIVE_TARGETS: List[Tuple[str, str]] = [
        (r"(?i)\.sql(\.gz)?$", "Attempt to access synthetic SQL database dump"),
        (r"(?i)\.bak$", "Attempt to access synthetic backup archive"),
        (r"(?i)(customer|client|user|credit_card|payroll)", "Targeting simulated confidential enterprise records"),
        (r"(?i)(config|\.env|secrets|credentials|passwords?\.txt)", "Targeting synthetic credentials or configuration file"),
    ]

    def evaluate_event(self, event: Dict[str, Any]) -> Optional[AttackDetection]:
        if not isinstance(event, dict):
            return None

        page = str(event.get("page") or "").lower()
        action = str(event.get("action") or "").lower()
        payload = event.get("payload")
        if not isinstance(payload, dict):
            payload = {}

        evidence: List[str] = []
        is_sensitive = False

        if page == "backup":
            is_sensitive = True
            evidence.append(f"[rule_id: {self.rule_id} | threshold: {self.threshold_desc}] Direct interaction with decoy backup portal (matched pattern: decoy backup endpoint)")
            if "download" in action:
                evidence.append(f"Decoy backup file download initiated (action: {action})")

        resource_name = str(payload.get("file") or payload.get("filename") or payload.get("path") or payload.get("resource") or "")
        if resource_name:
            for pattern, desc in self.SENSITIVE_TARGETS:
                if re.search(pattern, resource_name):
                    is_sensitive = True
                    evidence.append(f"[rule_id: {self.rule_id} | threshold: {self.threshold_desc}] {desc}: \"{resource_name}\" (matched pattern: {pattern})")

        if is_sensitive and evidence:
            return AttackDetection(
                attack_type="SENSITIVE_ACCESS",
                detected=True,
                severity="HIGH",
                evidence=list(dict.fromkeys(evidence)),
                timestamp=event.get("timestamp"),
                event_id=event.get("event_id"),
                rule_id=self.rule_id,
                threshold=self.threshold_desc,
                matched_pattern="Sensitive backup/credential decoy access",
            )

        return None


class ThreatEngine:
    """
    Master Detection Engine orchestrating rule-based detection modules.
    Evaluates both individual incoming events and accumulated session events.
    Robust against out-of-order timestamps, duplicate event_ids, and missing fields.
    """

    def __init__(self):
        self.brute_force_detector = BruteForceDetector()
        self.scanning_detector = ScanningDetector()
        self.sqli_detector = SQLInjectionDetector()
        self.traversal_detector = PathTraversalDetector()
        self.sensitive_detector = SensitiveAccessDetector()

    def evaluate_event(self, event: Dict[str, Any]) -> List[AttackDetection]:
        """Runs single-event rule detectors."""
        if not event or not isinstance(event, dict):
            return []

        detections: List[AttackDetection] = []

        sqli = self.sqli_detector.evaluate_event(event)
        if sqli:
            detections.append(sqli)

        trav = self.traversal_detector.evaluate_event(event)
        if trav:
            detections.append(trav)

        sens = self.sensitive_detector.evaluate_event(event)
        if sens:
            detections.append(sens)

        return detections

    def evaluate_session(self, events: List[Dict[str, Any]]) -> List[AttackDetection]:
        """
        Runs comprehensive evaluation over an entire session's events.
        Handles deduplication by event_id, sorting out-of-order timestamps,
        and empty lists without raising exceptions.
        """
        if not events:
            return []

        # 1. Deduplicate by event_id
        seen_ids: Set[str] = set()
        deduped: List[Dict[str, Any]] = []
        for ev in events:
            if not isinstance(ev, dict):
                continue
            ev_id = ev.get("event_id")
            if ev_id:
                if ev_id in seen_ids:
                    continue
                seen_ids.add(ev_id)
            deduped.append(ev)

        if not deduped:
            return []

        # 2. Sort out-of-order timestamps while preserving order of untimed events
        def get_ts_key(e: Dict[str, Any]) -> float:
            parsed = parse_timestamp(e.get("timestamp"))
            return parsed if parsed is not None else 0.0

        sorted_events = sorted(deduped, key=get_ts_key)

        all_detections: List[AttackDetection] = []
        seen_types: Set[str] = set()

        # Multi-event correlation detectors
        bf = self.brute_force_detector.evaluate_session(sorted_events)
        if bf:
            all_detections.append(bf)
            seen_types.add(bf.attack_type)

        scan = self.scanning_detector.evaluate_session(sorted_events)
        if scan:
            all_detections.append(scan)
            seen_types.add(scan.attack_type)

        # Per-event detectors across history
        for ev in sorted_events:
            event_detections = self.evaluate_event(ev)
            for det in event_detections:
                existing = next((d for d in all_detections if d.attack_type == det.attack_type), None)
                if existing:
                    for ev_item in det.evidence:
                        if ev_item not in existing.evidence:
                            existing.evidence.append(ev_item)
                else:
                    all_detections.append(det)
                    seen_types.add(det.attack_type)

        # Repeated suspicious behavior rule
        if len(seen_types) >= 3 or (len(sorted_events) >= 8 and len(seen_types) >= 2):
            rule_id = "RULE_REPEATED_SUSPICIOUS_01"
            thresh_str = ">=3 distinct attack types or >=8 events with >=2 types"
            matched_pat = f"Multi-vector activity ({', '.join(sorted(seen_types))})"

            repeated_det = AttackDetection(
                attack_type="REPEATED_SUSPICIOUS",
                detected=True,
                severity="HIGH",
                evidence=[
                    f"[rule_id: {rule_id} | threshold: {thresh_str}] Session exhibited multiple suspicious attack patterns ({', '.join(sorted(seen_types))}) across {len(sorted_events)} interactions (matched pattern: {matched_pat})"
                ],
                timestamp=sorted_events[-1].get("timestamp"),
                event_id=sorted_events[-1].get("event_id"),
                rule_id=rule_id,
                threshold=thresh_str,
                matched_pattern=matched_pat,
            )
            all_detections.append(repeated_det)

        return all_detections
