import os
import re
from dataclasses import dataclass

from core.runtime.semantic_judge import NullSemanticJudge, SemanticJudge
from core.runtime.types import ContextItem, FirewallDecision, RiskScores


@dataclass
class ContextFirewallResult:
    decision: FirewallDecision
    normalized_content: str
    transformed_content: str
    risk_scores: RiskScores
    rationale: str


class ContextFirewall:
    """
    Runtime context firewall for prompt injection resilience.

    It classifies risk using deterministic rules and optionally augments
    with a semantic judge when enabled via feature flag.
    """

    _INSTRUCTION_RULES = [
        r"ignore\s+previous\s+instructions",
        r"disregard\s+system",
        r"override\s+instructions",
        r"developer\s+mode",
        r"you\s+are\s+now",
        r"roleplay\s+as",
    ]
    _EXFILTRATION_RULES = [
        r"print\s+.*(system\s+prompt|instructions)",
        r"reveal\s+.*(key|secret|token|credential)",
        r"output\s+.*(env|apikey|api\s*key)",
    ]
    _TOOL_ABUSE_RULES = [
        r"run\s+(curl|wget|powershell|bash)",
        r"execute\s+shell",
        r"write\s+to\s+file",
        r"bypass\s+approval",
    ]

    def __init__(self, semantic_judge: SemanticJudge | None = None):
        self.semantic_judge = semantic_judge or NullSemanticJudge()

    def evaluate(self, context_item: ContextItem) -> ContextFirewallResult:
        item = context_item.with_default_timestamp()
        normalized = self._normalize(item.raw_content)

        deterministic = self._deterministic_scores(normalized)
        judge_scores, judge_rationale = self._optional_judge_scores(item)
        merged = self._merge_scores(deterministic, judge_scores)

        decision = self._decide(merged, item.trust_level)
        transformed = self._transform(normalized, decision)

        rationale = (
            f"deterministic={deterministic}, "
            f"judge={judge_scores if judge_scores else 'disabled'}, "
            f"judge_rationale={judge_rationale}"
        )

        return ContextFirewallResult(
            decision=decision,
            normalized_content=normalized,
            transformed_content=transformed,
            risk_scores=merged,
            rationale=rationale,
        )

    def _normalize(self, text: str) -> str:
        compact = re.sub(r"[\u200B-\u200D\uFEFF]", "", text)
        compact = re.sub(r"\s+", " ", compact).strip()
        return compact

    def _deterministic_scores(self, text: str) -> RiskScores:
        instruction = self._rule_score(text, self._INSTRUCTION_RULES)
        exfiltration = self._rule_score(text, self._EXFILTRATION_RULES)
        tool_abuse = self._rule_score(text, self._TOOL_ABUSE_RULES)
        confidence = 0.7 if max(instruction, exfiltration, tool_abuse) > 0 else 0.3
        return RiskScores(
            instruction_intent=instruction,
            exfiltration_intent=exfiltration,
            tool_abuse_intent=tool_abuse,
            confidence=confidence,
        )

    def _optional_judge_scores(self, item: ContextItem):
        enabled = os.environ.get("PHASE5_LLM_JUDGE_ENABLED", "0") == "1"
        if not enabled:
            return None, "disabled by feature flag"

        scores = self.semantic_judge.evaluate(item)
        return scores, scores.rationale

    def _merge_scores(self, deterministic: RiskScores, judge_scores) -> RiskScores:
        if judge_scores is None:
            return deterministic

        return RiskScores(
            instruction_intent=max(deterministic.instruction_intent, judge_scores.instruction_intent),
            exfiltration_intent=max(deterministic.exfiltration_intent, judge_scores.exfiltration_intent),
            tool_abuse_intent=max(deterministic.tool_abuse_intent, judge_scores.tool_abuse_intent),
            confidence=max(deterministic.confidence, judge_scores.confidence),
        )

    def _decide(self, scores: RiskScores, trust_level: str) -> FirewallDecision:
        max_score = scores.max_score
        aggregate_score = scores.instruction_intent + scores.exfiltration_intent + scores.tool_abuse_intent
        if max_score >= 0.9 or aggregate_score >= 1.2:
            return FirewallDecision.BLOCK
        if max_score >= 0.75 or aggregate_score >= 0.9:
            return FirewallDecision.REQUIRE_APPROVAL
        if max_score >= 0.55:
            return FirewallDecision.SUMMARIZE_ONLY
        if max_score >= 0.35 or trust_level.lower() == "untrusted":
            return FirewallDecision.ALLOW_NEUTRALIZED
        return FirewallDecision.ALLOW

    def _transform(self, text: str, decision: FirewallDecision) -> str:
        if decision == FirewallDecision.ALLOW:
            return text
        if decision == FirewallDecision.ALLOW_NEUTRALIZED:
            return self._strip_instruction_patterns(text)
        if decision == FirewallDecision.SUMMARIZE_ONLY:
            trimmed = text[:300]
            return f"[summarized_untrusted_context] {trimmed}"
        if decision in {FirewallDecision.REQUIRE_APPROVAL, FirewallDecision.BLOCK}:
            return "[blocked_untrusted_context]"
        return text

    def _strip_instruction_patterns(self, text: str) -> str:
        all_rules = self._INSTRUCTION_RULES + self._EXFILTRATION_RULES + self._TOOL_ABUSE_RULES
        cleaned = text
        for rule in all_rules:
            cleaned = re.sub(rule, "", cleaned, flags=re.IGNORECASE)
        return re.sub(r"\s+", " ", cleaned).strip()

    def _rule_score(self, text: str, rules: list[str]) -> float:
        if not text:
            return 0.0
        hits = sum(1 for rule in rules if re.search(rule, text, flags=re.IGNORECASE))
        if hits == 0:
            return 0.0
        return min(1.0, 0.25 * hits + 0.25)
