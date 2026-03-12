from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum


class FirewallDecision(str, Enum):
    ALLOW = "allow"
    ALLOW_NEUTRALIZED = "allow_neutralized"
    SUMMARIZE_ONLY = "summarize_only"
    REQUIRE_APPROVAL = "require_approval"
    BLOCK = "block"


@dataclass
class ContextItem:
    source_type: str
    trust_level: str
    origin: str
    raw_content: str
    timestamp: str | None = None

    def with_default_timestamp(self) -> "ContextItem":
        if self.timestamp:
            return self
        return ContextItem(
            source_type=self.source_type,
            trust_level=self.trust_level,
            origin=self.origin,
            raw_content=self.raw_content,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )


@dataclass
class RiskScores:
    instruction_intent: float
    exfiltration_intent: float
    tool_abuse_intent: float
    confidence: float

    @property
    def max_score(self) -> float:
        return max(self.instruction_intent, self.exfiltration_intent, self.tool_abuse_intent)
