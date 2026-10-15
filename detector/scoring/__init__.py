"""Scoring strategies used by the phishing detector."""
from .risk import DIMENSION_CAPS, evaluate_hard_rules, score_result

__all__ = [
    'DIMENSION_CAPS',
    'evaluate_hard_rules',
    'score_result',
]
