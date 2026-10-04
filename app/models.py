from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

# ── Response models for individual tools ──────────────────────────────────────

class VisionResponse(BaseModel):
    risk_level: str = Field(..., description="Risk tier: 'low', 'medium', 'high', 'critical', or 'unknown'")
    visual_findings: List[str] = Field(..., description="List of visual fraud indicators detected")
    summary: str = Field(..., description="Concise professional English verdict summary")


class StegoResponse(BaseModel):
    risk_level: str = Field(..., description="Risk tier: 'low', 'medium', 'high', or 'critical'")
    lsb_findings: Dict[str, Any] = Field(..., description="LSB anomaly, histogram, EOF/trailing, entropy and metadata details")
    ctf_flags: List[str] = Field(..., description="CTF-style flag strings detected in the file data")
    threat_words: List[str] = Field(..., description="Matched threat/trigger keywords")
    macro_analysis: Dict[str, Any] = Field(..., description="VBA macro, PDF script, and archive payload check results")
    summary: str = Field(..., description="Professional English verdict summary of the forensic scan")


class TextResponse(BaseModel):
    risk_level: str = Field(..., description="Risk tier: 'low', 'medium', 'high', or 'critical'")
    text_findings: List[str] = Field(..., description="List of text/URL fraud indicators detected")
    summary: str = Field(..., description="Professional English verdict summary of the text scan")


# ── Response models for the hybrid router ─────────────────────────────────────

class RouterMetadata(BaseModel):
    selected_provider: str = Field(..., description="The model provider chosen: 'fireworks', 'anthropic', 'gemini', or 'none' when nothing was analyzed")
    tokens_used: Optional[int] = Field(None, description="Number of tokens used in LLM processing if available")
    cost_estimate: float = Field(..., description="Estimated cost of the query in USD")


class FullAnalysisResponse(BaseModel):
    overall_risk: str = Field(..., description="The combined risk tier across all analyzed agents")
    fraud_probability: int = Field(..., description="Probability of fraud as a percentage (0-100)")
    agent_reports: Dict[str, Any] = Field(..., description="Individual tool responses (stego, vision, text)")
    final_summary: str = Field(..., description="Unified final summary synthesized from all active agents")
    router_metadata: RouterMetadata = Field(..., description="Metadata from the hybrid provider routing decision")
