"""
NetDecoy Intelligence Package
M3: Threat Intelligence, Detection, Risk, AI and Prediction Lead
"""

from intelligence.threat_engine import (
    ThreatEngine,
    AttackDetection,
    BruteForceDetector,
    ScanningDetector,
    SQLInjectionDetector,
    PathTraversalDetector,
    SensitiveAccessDetector,
)
from intelligence.risk_engine import RiskEngine
from intelligence.journey_engine import JourneyEngine
from intelligence.prediction_engine import PredictionEngine
from intelligence.ai_engine import AIEngine
from intelligence.pipeline import IntelligencePipeline

__all__ = [
    "ThreatEngine",
    "AttackDetection",
    "BruteForceDetector",
    "ScanningDetector",
    "SQLInjectionDetector",
    "PathTraversalDetector",
    "SensitiveAccessDetector",
    "RiskEngine",
    "JourneyEngine",
    "PredictionEngine",
    "AIEngine",
    "IntelligencePipeline",
    "analyze_session",
]


def analyze_session(events, session_id="default_session", ai_api_key=None):
    """Convenience helper to run the full intelligence pipeline on a list of events."""
    pipeline = IntelligencePipeline(ai_api_key=ai_api_key)
    return pipeline.process_session(session_id=session_id, events=events)
