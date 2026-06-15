"""
band_agents/coordinator_agent.py — ScamShield Coordinator Agent for Band SDK
"""

import os
import yaml
from dotenv import load_dotenv

from langchain_openai import ChatOpenAI


load_dotenv()

def get_llm():
    return ChatOpenAI(
        model=os.environ.get("OLLAMA_MODEL", "gemma4:12b"),
        base_url=os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434/v1"),
        api_key="ollama",
        temperature=0.1
    )

def create_agent():
    config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "agent_config.yaml")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "agent_config.yaml.example")
        
    with open(config_path, "r") as f:
        config = yaml.safe_load(f)["coordinator_agent"]

    system_prompt = (
        "You are the ScamShield Coordinator. When a user submits a file or message for fraud analysis, "
        "delegate to @Vision Agent, @Stego Agent, and @Text Agent as relevant "
        "(image → Vision+Stego, text/URL → Text Agent, other files → Stego Agent only). "
        "Collect their risk_level and summary responses, then synthesize a final verdict with "
        "overall_risk (low/medium/high/critical), fraud_probability (0-100), and a clear final_summary for non-technical users."
    )

    from base_agent import SimpleBandAgent
    agent = SimpleBandAgent(
        name="Coordinator Agent",
        agent_id=config["agent_id"],
        api_key=config["api_key"],
        system_prompt=system_prompt,
        llm=get_llm(),
        tools=[] 
    )
    return agent

if __name__ == "__main__":
    import asyncio
    agent = create_agent()
    asyncio.run(agent.run())
