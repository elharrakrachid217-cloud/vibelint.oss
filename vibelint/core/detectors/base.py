"""
core/detectors/base.py
======================
Base class for all detectors.
Every detector inherits from this and implements detect().
"""

from abc import ABC, abstractmethod


class BaseDetector(ABC):

    @abstractmethod
    def detect(self, code: str, language: str, filename: str = "") -> list[dict]:
        """
        Scan the code and return a list of violations.
        Each violation is a dict with keys:
            - type: str
            - severity: 'critical' | 'high' | 'medium' | 'low'
            - line: int
            - description: str
            - offending_line: str
            - fix_hint: str
        """
        pass
