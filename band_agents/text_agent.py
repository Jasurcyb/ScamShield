"""
band_agents/text_agent.py — ScamShield Text Agent for Band SDK
"""

import os
import sys
import yaml
from dotenv import load_dotenv

from langchain_openai import ChatOpenAI


# Ensure tools can be imported
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tools.text_url_tool import text_url_fraud_tool

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
        config = yaml.safe_load(f)["text_agent"]

    from base_agent import SimpleBandAgent
    agent = SimpleBandAgent(
        name="Text Agent",
        agent_id=config["agent_id"],
        api_key=config["api_key"],
        system_prompt="You are the Text/URL Fraud specialist in ScamShield. Use text_url_fraud_tool to analyze messages and links for phishing/scam patterns.",
        llm=get_llm(),
        tools=[text_url_fraud_tool]
    )
    return agent

if __name__ == "__main__":
    import asyncio
    agent = create_agent()
    asyncio.run(agent.run())
