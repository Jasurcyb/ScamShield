import os
import sys
import asyncio
from typing import Optional, Dict, Any

# Ensure project root is on sys.path
_ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT_DIR not in sys.path:
    sys.path.insert(0, _ROOT_DIR)

from tools.stego_tool import stego_security_tool
from tools.vision_tool import vision_fraud_tool
from tools.text_url_tool import text_url_fraud_tool
from tools.llm_provider import call_text_llm, best_remote_text_provider, summary_language_instruction
from app import scoring

class HybridRouter:
    def __init__(self):
        pass

    def _get_provider_cost(self, provider: str) -> float:
        """Returns a cost estimate in USD for the query based on provider pricing."""
        costs = {
            "fireworks": 0.00015,  # Approx cost for ~150 tokens on Gemma 4 31B IT
            "gemini": 0.000075,    # Approx cost for ~150 tokens on Gemini 2.5 Flash
            "anthropic": 0.003,    # Approx cost for ~150 tokens on Claude Sonnet
        }
        return costs.get(provider, 0.0)

    def _determine_llm_provider(self) -> str:
        """Pick the cloud LLM provider (Anthropic → Gemini → Fireworks).

        Local Ollama inference was removed: every analysis runs on a cloud
        provider, so at least one configured API key is mandatory.
        """
        provider = best_remote_text_provider()
        if provider is None:
            raise RuntimeError(
                "No LLM provider configured. "
                "Set ANTHROPIC_API_KEY, GEMINI_API_KEY or FIREWORKS_API_KEY."
            )
        return provider

    def _calculate_fraud_probability(self, overall_risk: str, n_findings: int = 0) -> int:
        """Calibrated probability (eval-derived), not a hand-written table."""
        return scoring.fraud_probability(overall_risk, n_findings)

    async def _generate_final_summary(self, agent_reports: dict, provider: str, language: str = "en") -> str:
        """Synthesize agent findings into a single final verdict using the chosen provider."""
        summaries = []
        for agent_name, report in agent_reports.items():
            if report and "summary" in report:
                summaries.append(f"{agent_name.capitalize()} Agent Summary: {report['summary']}")

        if not summaries:
            return "Analysis completed, but no detailed summaries were generated."

        combined_summaries = "\n".join(summaries)

        prompt_sections = [
            f"""
You are a senior forensic analyst orchestrator. Review the following summaries \
provided by specialized AI agents evaluating a potentially fraudulent artifact.

{combined_summaries}

Synthesize these findings into a single, cohesive final verdict (2-3 sentences max) \
in professional English. Explain the overall conclusion clearly for a human judge, \
without using overly technical jargon. Do not use formatting like markdown or lists.
""",
            summary_language_instruction(language),
        ]
        prompt = "\n".join(section for section in prompt_sections if section)
        # Save env variables and temporarily override to enforce the routed provider if needed
        # Since call_text_llm automatically selects provider based on env keys,
        # we configure the route.
        try:
            # Run text completion
            summary = await asyncio.to_thread(call_text_llm, prompt, provider)
            return summary.strip()
        except Exception as e:
            return f"Failed to generate unified summary due to LLM error: {e}"

    async def route_decision(
        self,
        file_path: Optional[str] = None,
        text: Optional[str] = None,
        language: str = "en",
    ) -> dict:
        """
        Orchestration router: analyzes size and keywords, routes to appropriate LLMs,
        combines outputs, and calculates cost. `language` sets the verdict language.
        """
        tasks = {}
        agent_reports = {}

        is_image = False
        if file_path and os.path.exists(file_path):
            ext = os.path.splitext(file_path)[1].lower()
            is_image = ext in [".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"]

        if not file_path and not text:
            return {
                "overall_risk": "unknown",
                "fraud_probability": 0,
                "agent_reports": {},
                "final_summary": "No inputs provided for analysis.",
                "router_metadata": {
                    "selected_provider": "none",
                    "tokens_used": 0,
                    "cost_estimate": 0.0
                }
            }

        # ── Determine routed provider ──────────────────────────────────────────
        routed_provider = self._determine_llm_provider()

        if file_path and os.path.exists(file_path):
            tasks["stego"] = stego_security_tool(file_path)
            if is_image:
                tasks["vision"] = vision_fraud_tool(file_path, provider=routed_provider, language=language)
        if text:
            tasks["text"] = text_url_fraud_tool(text, provider=routed_provider, language=language)
        
        # Execute tools concurrently
        results = await asyncio.gather(*tasks.values(), return_exceptions=True)
        
        for agent_name, result in zip(tasks.keys(), results):
            if isinstance(result, Exception):
                agent_reports[agent_name] = {
                    "risk_level": "unknown",
                    "summary": f"Agent tool failed with exception: {result}"
                }
            else:
                agent_reports[agent_name] = result

        # ── Determine overall risk ────────────────────────────────────────────
        risk_hierarchy = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
        max_risk_val = 0
        overall_risk = "unknown"
        
        for report in agent_reports.values():
            r = report.get("risk_level", "unknown")
            r_val = risk_hierarchy.get(r, 0)
            if r_val > max_risk_val:
                max_risk_val = r_val
                overall_risk = r

        if max_risk_val == 0:
            overall_risk = "unknown"

        fraud_probability = self._calculate_fraud_probability(
            overall_risk, scoring.count_findings(agent_reports)
        )
        final_summary = await self._generate_final_summary(agent_reports, routed_provider, language)

        # Metadata metrics
        cost_estimate = self._get_provider_cost(routed_provider)
        tokens_estimate = None

        return {
            "overall_risk": overall_risk,
            "fraud_probability": fraud_probability,
            "agent_reports": agent_reports,
            "final_summary": final_summary,
            "router_metadata": {
                "selected_provider": routed_provider,
                "tokens_used": tokens_estimate,
                "cost_estimate": cost_estimate
            }
        }
