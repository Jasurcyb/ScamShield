"""Quick test: verify ALL 4 API keys against Band platform."""
import asyncio
import yaml
import os
from thenvoi_rest import AsyncRestClient

BASE_URL = "https://app.band.ai"

async def test_key(name, api_key):
    client = AsyncRestClient(api_key=api_key, base_url=BASE_URL)
    try:
        chats = await client.agent_api_chats.list_agent_chats()
        print(f"[OK] {name}: {len(chats.data)} chat(s)")
    except Exception as e:
        err_short = str(e)[:120]
        print(f"[FAIL] {name}: {err_short}")

async def main():
    config_path = "agent_config.yaml"
    if not os.path.exists(config_path):
        config_path = "agent_config.yaml.example"
    with open(config_path) as f:
        config = yaml.safe_load(f)
    
    for section, data in config.items():
        await test_key(section, data["api_key"])

asyncio.run(main())
