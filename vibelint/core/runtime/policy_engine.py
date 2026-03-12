from dataclasses import dataclass

from core.runtime.types import FirewallDecision, RiskScores


@dataclass
class ActionPolicyDecision:
    decision: FirewallDecision
    rationale: str


class ActionPolicyEngine:
    """Capability gate for runtime actions after context evaluation."""

    SENSITIVE_ACTIONS = {
        "file_write",
        "command_exec",
        "network_request",
        "secret_access",
        "tool_invoke",
    }

    def evaluate_action(
        self,
        action_type: str,
        risk_scores: RiskScores,
        requested_by_trusted_actor: bool = False,
    ) -> ActionPolicyDecision:
        score = risk_scores.max_score
        sensitive = action_type in self.SENSITIVE_ACTIONS

        if score >= 0.9:
            return ActionPolicyDecision(FirewallDecision.BLOCK, "critical risk score")

        if sensitive and score >= 0.6:
            return ActionPolicyDecision(FirewallDecision.REQUIRE_APPROVAL, "sensitive action at elevated risk")

        if sensitive and not requested_by_trusted_actor and score >= 0.35:
            return ActionPolicyDecision(FirewallDecision.REQUIRE_APPROVAL, "untrusted actor requesting sensitive action")

        if score >= 0.55:
            return ActionPolicyDecision(FirewallDecision.SUMMARIZE_ONLY, "context needs constrained handling")

        if score >= 0.35:
            return ActionPolicyDecision(FirewallDecision.ALLOW_NEUTRALIZED, "allow with neutralization")

        return ActionPolicyDecision(FirewallDecision.ALLOW, "low risk")
