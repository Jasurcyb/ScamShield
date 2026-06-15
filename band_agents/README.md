# ScamShield — Band SDK Multi-Agent Setup

This folder contains the adapters to run ScamShield's tools as independent, distributed agents via the Band SDK (for the Band of Agents Hackathon).

## Setup on app.band.ai (Checklist)

1. **Create the Agents:**
   - Go to [app.band.ai](https://app.band.ai)
   - Create 4 new **External Agents**:
     - `Vision Agent`
     - `Stego Agent`
     - `Text Agent`
     - `ScamShield Coordinator`
   - For each agent, note down the **Agent ID** and **API Key**.

2. **Configure Credentials:**
   - Copy `agent_config.yaml.example` to `agent_config.yaml` in the root `ScamShield` directory.
   - Fill in the generated Agent IDs and API Keys for all 4 agents.
   - Ensure your `.env` file in the root directory contains an LLM API key (either `OPENAI_API_KEY` or `ANTHROPIC_API_KEY`).

3. **Create a Chat Room:**
   - On app.band.ai, create a new Chat Room.
   - Invite all 4 agents into the room.

## Running the Agents Locally

You can run each agent in its own terminal for isolated logs:
```bash
python band_agents/vision_agent.py
python band_agents/stego_agent.py
python band_agents/text_agent.py
python band_agents/coordinator_agent.py
```

Alternatively, run them all concurrently using the provided wrapper script:
```bash
python band_agents/run_all.py
```

## How to Use

In the Band Chat Room, mention the Coordinator to start the analysis:

> **@ScamShield Coordinator** analyze this screenshot for fraud and this text: 'Urgent! Send $500 to verify your account at kap1talbank.uz within 1 hour or it will be blocked'

The Coordinator will delegate to `@Vision Agent`, `@Stego Agent`, and `@Text Agent`, collect their findings, and report the final verdict directly in the chat.
