"""
orchestrator.py — ScamShield Multi-Agent Orchestrator

Coordinates the execution of Agent 1 (Vision), Agent 2 (Stego), and Agent 3 (Text).
"""

import asyncio
import os
import json
from tools.stego_tool import stego_security_tool
from tools.vision_tool import vision_fraud_tool
from tools.text_url_tool import text_url_fraud_tool
from tools.llm_provider import call_text_llm

class ScamShieldOrchestrator:
    def __init__(self):
        pass

    def _calculate_fraud_probability(self, overall_risk: str) -> int:
        """Calculate a probability score (0-100) based on the highest risk level."""
        mapping = {
            "critical": 95,
            "high": 80,
            "medium": 55,
            "low": 15,
            "unknown": 0
        }
        return mapping.get(overall_risk, 0)

    async def _generate_final_summary(self, agent_reports: dict) -> str:
        """Use the LLM to synthesize a single final summary from all agent summaries."""
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
        try:
            summary = await asyncio.to_thread(call_text_llm, prompt)
            return summary.strip()
        except Exception as e:
            return f"Failed to generate unified summary due to LLM error: {e}"

    async def analyze(self, file_path: str = None, text: str = None) -> dict:
        """
        Main orchestration logic.
        Runs relevant agents concurrently and merges results.
        """
        tasks = {}
        
        if file_path:
            ext = os.path.splitext(file_path)[1].lower()
            is_image = ext in [".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"]
            
            tasks["stego"] = stego_security_tool.ainvoke({"file_path": file_path})
            if is_image:
                tasks["vision"] = vision_fraud_tool.ainvoke({"file_path": file_path})

        if text:
            tasks["text"] = text_url_fraud_tool.ainvoke({"text": text})

        if not tasks:
            return {
                "overall_risk": "unknown",
                "fraud_probability": 0,
                "agent_reports": {},
                "final_summary": "No inputs provided for analysis."
            }

        # Run all selected agents concurrently
        results = await asyncio.gather(*tasks.values(), return_exceptions=True)
        
        agent_reports = {}
        for agent_name, result in zip(tasks.keys(), results):
            if isinstance(result, Exception):
                agent_reports[agent_name] = {
                    "risk_level": "unknown",
                    "summary": f"Agent failed with exception: {result}"
                }
            else:
                agent_reports[agent_name] = result

        # Determine overall risk
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
        final_summary = await self._generate_final_summary(agent_reports)

        return {
            "overall_risk": overall_risk,
            "fraud_probability": fraud_probability,
            "agent_reports": agent_reports,
            "final_summary": final_summary
        }
