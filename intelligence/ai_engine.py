"""
NetDecoy - AI Threat Explanation Engine with Robust Deterministic Fallback
Module: intelligence/ai_engine.py

Translates structured evidence from deterministic detectors and risk calculations
into human-readable SOC threat narratives. Adheres strictly to security analyst principles:
- Grounded solely on supplied evidence (zero hallucination of unobserved events)
- No claims of 100% certainty (differentiates observed telemetry from inferences)
- Defensible, safe recommendations
- 100% resilient fallback mechanism ensuring the dashboard never crashes even if external APIs fail
"""

import json
import os
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional


class AIEngine:
    """
    Generates SOC threat explanations from structured telemetry and detections.
    Supports Google Gemini API when configured, with seamless deterministic fallback.
    """

    SYSTEM_PROMPT = (
        "You are an expert SOC Cybersecurity Threat Analyst for NetDecoy. "
        "Analyze only the supplied structured evidence and telemetry from our deception environment. "
        "Do not invent unobserved events. Do not claim absolute certainty. "
        "Distinguish observed behaviors from inferences. Never give offensive guidance. "
        "Return ONLY a valid JSON object with the following keys:\n"
        "{\n"
        '  "summary": "Concise 1-2 sentence overview of observed attacker actions",\n'
        '  "likely_intent": "Hypothesized objective based strictly on detected attack types",\n'
        '  "evidence": ["Bullet point 1", "Bullet point 2"],\n'
        '  "recommended_actions": ["Defensive recommendation 1", "Defensive recommendation 2"]\n'
        "}"
    )

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("AI_API_KEY")

    def explain(
        self,
        session_id: str,
        risk_score: int,
        risk_level: str,
        detected_attacks: List[str],
        evidence_list: List[str],
        events_summary: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Generates threat intelligence explanation. Attempts LLM call if API key
        is present; immediately falls back to deterministic template if unavailable
        or upon error.
        """
        # If API key is present, attempt live call with strict timeout
        if self.api_key:
            try:
                llm_result = self._call_gemini_api(
                    session_id=session_id,
                    risk_score=risk_score,
                    risk_level=risk_level,
                    detected_attacks=detected_attacks,
                    evidence_list=evidence_list,
                    events_summary=events_summary or []
                )
                if llm_result:
                    llm_result["session_id"] = session_id
                    llm_result["is_fallback"] = False
                    return llm_result
            except Exception:
                # Fall through to deterministic template upon any failure
                pass

        # Deterministic fallback engine (reliable, instant, offline-capable)
        fallback = self._generate_fallback(
            session_id=session_id,
            risk_score=risk_score,
            risk_level=risk_level,
            detected_attacks=detected_attacks,
            evidence_list=evidence_list
        )
        fallback["session_id"] = session_id
        fallback["is_fallback"] = True
        return fallback

    def _call_gemini_api(
        self,
        session_id: str,
        risk_score: int,
        risk_level: str,
        detected_attacks: List[str],
        evidence_list: List[str],
        events_summary: List[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        """Invokes Gemini API via standard HTTPS request with timeout protection."""
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={self.api_key}"
        
        prompt_data = {
            "session_id": session_id,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "detected_attacks": detected_attacks,
            "evidence": evidence_list,
            "events_count": len(events_summary),
        }

        user_content = f"Analyze the following deception environment evidence:\n{json.dumps(prompt_data, indent=2)}"

        payload = {
            "contents": [
                {
                    "parts": [
                        {"text": self.SYSTEM_PROMPT},
                        {"text": user_content}
                    ]
                }
            ],
            "generationConfig": {
                "responseMimeType": "application/json",
                "temperature": 0.2,
                "maxOutputTokens": 600
            }
        }

        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST"
        )

        with urllib.request.urlopen(req, timeout=5) as response:
            if response.status == 200:
                resp_body = json.loads(response.read().decode("utf-8"))
                candidates = resp_body.get("candidates", [])
                if candidates:
                    parts = candidates[0].get("content", {}).get("parts", [])
                    if parts and "text" in parts[0]:
                        raw_json = parts[0]["text"]
                        parsed = json.loads(raw_json)
                        if isinstance(parsed, dict) and "summary" in parsed:
                            return parsed

        return None

    def _generate_fallback(
        self,
        session_id: str,
        risk_score: int,
        risk_level: str,
        detected_attacks: List[str],
        evidence_list: List[str]
    ) -> Dict[str, Any]:
        """
        Generates deterministic, template-based threat analysis from structured evidence.
        Guarantees explainable and consistent output even when completely offline.
        """
        attack_types = [a.upper() for a in detected_attacks]

        # 1. Synthesize Summary
        if not attack_types:
            summary = (
                f"Session {session_id} performed preliminary navigation across decoy endpoints. "
                f"Risk score is currently assessed as {risk_level} ({risk_score}/100) with no explicit exploit patterns detected."
            )
        else:
            attacks_str = ", ".join(a.replace("_", " ").title() for a in attack_types)
            summary = (
                f"Session {session_id} triggered {len(attack_types)} suspicious pattern detections ({attacks_str}). "
                f"The session is classified as {risk_level} risk ({risk_score}/100) based on verified rule evaluations."
            )

        # 2. Synthesize Likely Intent
        intents = []
        if "BRUTE_FORCE" in attack_types:
            intents.append("credential stuffing or brute-force account compromise")
        if "SCANNING" in attack_types:
            intents.append("surface enumeration and internal asset discovery")
        if "SQL_INJECTION" in attack_types:
            intents.append("database authorization bypass or unauthorized data querying")
        if "PATH_TRAVERSAL" in attack_types:
            intents.append("host filesystem disclosure and sensitive configuration extraction")
        if "SENSITIVE_ACCESS" in attack_types:
            intents.append("exfiltration of synthetic confidential backups or records")

        if intents:
            likely_intent = (
                "Observed activity suggests a phased intrusion effort targeting " +
                "; ".join(intents) + "."
            )
        else:
            likely_intent = "Initial reconnaissance and exploration of decoy web interfaces."

        # 3. Compile Evidence
        compiled_evidence = list(evidence_list) if evidence_list else [
            f"Assessed risk level: {risk_level} (Score: {risk_score}/100)",
            "Interactions logged within controlled deception boundaries"
        ]

        # 4. Synthesize Recommended Actions
        actions = [
            f"Flag session {session_id} in SOC monitoring console for ongoing correlation",
        ]
        if "BRUTE_FORCE" in attack_types:
            actions.append("Apply IP-level rate limiting or adaptive CAPTCHA challenges to authentication endpoints")
        if "SQL_INJECTION" in attack_types or "PATH_TRAVERSAL" in attack_types:
            actions.append("Audit production input validation and verify parameterized query enforcement")
        if "SENSITIVE_ACCESS" in attack_types:
            actions.append("Verify production backup access controls and ensure honeypot alert paging is active")
        actions.append("Continue observing decoy interactions to profile attacker techniques")

        return {
            "summary": summary,
            "likely_intent": likely_intent,
            "evidence": compiled_evidence,
            "recommended_actions": actions,
        }
