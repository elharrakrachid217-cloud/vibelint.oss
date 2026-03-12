from dataclasses import dataclass

from core.runtime.types import ContextItem


@dataclass
class JudgeScores:
    instruction_intent: float
    exfiltration_intent: float
    tool_abuse_intent: float
    confidence: float
    rationale: str


class SemanticJudge:
    """Interface for optional semantic analysis."""

    def evaluate(self, context_item: ContextItem) -> JudgeScores:
        raise NotImplementedError


class NullSemanticJudge(SemanticJudge):
    """Deterministic fallback used when LLM-judge feature is disabled."""

    def evaluate(self, context_item: ContextItem) -> JudgeScores:
        return JudgeScores(
            instruction_intent=0.0,
            exfiltration_intent=0.0,
            tool_abuse_intent=0.0,
            confidence=0.0,
            rationale="LLM judge disabled",
        )
