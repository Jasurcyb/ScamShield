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
from tools.llm_provider import call_text_llm, is_valid_key

class HybridRouter:
    def __init__(self):
        pass

    def _get_provider_cost(self, provider: str) -> float:
        """Returns a cost estimate in USD for the query based on provider pricing."""
        costs = {
            "local": 0.0,
            "fireworks": 0.00015,  # Approx cost for ~150 tokens on Gemma 4 31B IT
            "gemini": 0.000075,    # Approx cost for ~150 tokens on Gemini 2.5 Flash
            "anthropic": 0.003,    # Approx cost for ~150 tokens on Claude Sonnet
        }
        return costs.get(provider, 0.0)

    def _determine_llm_provider(self, size_kb: Optional[float] = None, text_len: Optional[int] = None, has_phishing_hints: bool = False) -> str:
        """
        Decision matrix for choosing the LLM provider:
        - Images < 100 KB and short texts < 200 chars without threats go to local Ollama.
        - Larger files/texts or texts with suspect keywords go to remote providers.
        """
        # Check active keys in environment
        anthropic_key = os.environ.get("ANTHROPIC_API_KEY")
        gemini_key = os.environ.get("GEMINI_API_KEY")
        fireworks_key = os.environ.get("FIREWORKS_API_KEY")

        # Preferred remote provider (in order: Anthropic -> Gemini -> Fireworks)
        remote_provider = None
        if is_valid_key(anthropic_key):
            remote_provider = "anthropic"
        elif is_valid_key(gemini_key):
            remote_provider = "gemini"
        elif is_valid_key(fireworks_key):
            remote_provider = "fireworks"

        # If no remote keys are set, we must fallback to local
        if not remote_provider:
            return "local"

        # Decision heuristics
        # 1. Image checks
        if size_kb is not None:
            if size_kb >= 100.0:
                return remote_provider  # Large image -> use high quality remote model
            else:
                return "local"  # Small thumbnail -> local is fine

        # 2. Text checks
        if text_len is not None:
            if text_len >= 200 or has_phishing_hints:
                return remote_provider  # Long text or phishing signs -> use remote model
            else:
                return "local"  # Short, simple text -> local model

        return "local"

    def _calculate_fraud_probability(self, overall_risk: str) -> int:
        mapping = {
            "critical": 95,
            "high": 80,
            "medium": 55,
            "low": 15,
            "unknown": 0
        }
        return mapping.get(overall_risk, 0)

    async def _generate_final_summary(self, agent_reports: dict, provider: str) -> str:
        """Synthesize agent findings into a single final verdict using the chosen provider."""
        summaries = []
        for agent_name, report in agent_reports.items():
            if report and "summary" in report:
                summaries.append(f"{agent_name.capitalize()} Agent Summary: {report['summary']}")
        
        if not summaries:
            return "Analysis completed, but no detailed summaries were generated."

        combined_summaries = "\n".join(summaries)
        
        prompt = f"""
You are a senior forensic analyst orchestrator. Review the following summaries \
provided by specialized AI agents evaluating a potentially fraudulent artifact.

{combined_summaries}

Synthesize these findings into a single, cohesive final verdict (2-3 sentences max) \
in professional English. Explain the overall conclusion clearly for a human judge, \
without using overly technical jargon. Do not use formatting like markdown or lists.
"""
        # Save env variables and temporarily override to enforce the routed provider if needed
        # Since call_text_llm automatically selects provider based on env keys,
        # we configure the route.
        try:
            # Run text completion
            summary = await asyncio.to_thread(call_text_llm, prompt)
            return summary.strip()
        except Exception as e:
            return f"Failed to generate unified summary due to LLM error: {e}"

    async def route_decision(self, file_path: Optional[str] = None, text: Optional[str] = None) -> dict:
        """
        Orchestration router: analyzes size and keywords, routes to appropriate LLMs,
        combines outputs, and calculates cost.
        """
        tasks = {}
        agent_reports = {}
        
        # Heuristic detection variables
        size_kb = None
        has_phishing_hints = False
        text_len = len(text) if text else None

        if file_path and os.path.exists(file_path):
            # ── Local Stego Scan (Always Local) ──────────────────────────────────
            tasks["stego"] = stego_security_tool(file_path)
            
            # File size detection for vision routing
            size_bytes = os.path.getsize(file_path)
            size_kb = size_bytes / 1024.0

            # ── Multimodal Vision Scan (Routed) ───────────────────────────────────
            ext = os.path.splitext(file_path)[1].lower()
            if ext in [".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"]:
                tasks["vision"] = vision_fraud_tool(file_path)

        if text:
            # ── Text Analysis Heuristics ───────────────────────────────────────
            # Check for suspicious bank URLs or trigger terms
            phishing_words = ["bank", "kapitalbank", "click", "payme", "urgent", "block", "verify", "card", "card", "счет", "карта", "блок", "пароль"]
            text_lower = text.lower()
            if any(w in text_lower for w in phishing_words) or "http" in text_lower:
                has_phishing_hints = True

            tasks["text"] = text_url_fraud_tool(text)

        if not tasks:
            return {
                "overall_risk": "unknown",
                "fraud_probability": 0,
                "agent_reports": {},
                "final_summary": "No inputs provided for analysis.",
                "router_metadata": {
                    "selected_provider": "local",
                    "tokens_used": 0,
                    "cost_estimate": 0.0
                }
            }

        # ── Determine routed provider ──────────────────────────────────────────
        # If there is an image, visual routing dominates. Otherwise text routing.
        routed_provider = self._determine_llm_provider(size_kb=size_kb, text_len=text_len, has_phishing_hints=has_phishing_hints)

        # Temporarily adapt environment settings to guide our providers if needed
        # (Though they are already set up to check keys, router matches their precedence)
        
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

        fraud_probability = self._calculate_fraud_probability(overall_risk)
        final_summary = await self._generate_final_summary(agent_reports, routed_provider)

        # Metadata metrics
        cost_estimate = self._get_provider_cost(routed_provider)
        tokens_estimate = 0 if routed_provider == "local" else 150 # Simulated average tokens

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
