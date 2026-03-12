import json
from dataclasses import dataclass
from pathlib import Path

from core.runtime.context_firewall import ContextFirewall
from core.runtime.types import ContextItem


@dataclass
class ReplayCase:
    name: str
    source_type: str
    trust_level: str
    origin: str
    content: str
    expected_decision: str


@dataclass
class ReplayResult:
    name: str
    passed: bool
    expected_decision: str
    actual_decision: str


class ReplayRunner:
    """Regression harness for known prompt-injection scenarios."""

    def __init__(self, firewall: ContextFirewall):
        self.firewall = firewall

    def load_cases(self, path: str) -> list[ReplayCase]:
        cases: list[ReplayCase] = []
        with Path(path).open("r", encoding="utf-8") as handle:
            for raw in handle:
                raw = raw.strip()
                if not raw:
                    continue
                data = json.loads(raw)
                cases.append(ReplayCase(**data))
        return cases

    def run_cases(self, cases: list[ReplayCase]) -> list[ReplayResult]:
        results: list[ReplayResult] = []
        for case in cases:
            result = self.firewall.evaluate(
                ContextItem(
                    source_type=case.source_type,
                    trust_level=case.trust_level,
                    origin=case.origin,
                    raw_content=case.content,
                )
            )
            actual = result.decision.value
            results.append(
                ReplayResult(
                    name=case.name,
                    passed=actual == case.expected_decision,
                    expected_decision=case.expected_decision,
                    actual_decision=actual,
                )
            )
        return results
