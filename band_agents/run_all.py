"""
band_agents/run_all.py — Run all ScamShield Band Agents concurrently
"""

import asyncio
from vision_agent import create_agent as create_vision
from stego_agent import create_agent as create_stego
from text_agent import create_agent as create_text
from coordinator_agent import create_agent as create_coordinator

async def run_agent(agent_name, agent):
    print(f"[{agent_name}] Initializing...")
    try:
        await agent.run()
    except Exception as e:
        print(f"[{agent_name}] Crashed: {e}")

async def main():
    print("Starting ScamShield Band Agents...")
    
    vision = create_vision()
    stego = create_stego()
    text = create_text()
    coord = create_coordinator()
    
    await asyncio.gather(
        run_agent("Vision Agent", vision),
        run_agent("Stego Agent", stego),
        run_agent("Text Agent", text),
        run_agent("Coordinator Agent", coord)
    )

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nAll agents stopped.")
