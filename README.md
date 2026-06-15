# ScamShield - Multimodal Fraud Detection Multi-Agent System

## Problem
In recent years, Central Asia—particularly Uzbekistan—has witnessed an unprecedented surge in financial fraud, phishing attacks, and social engineering across messaging apps like Telegram and WhatsApp. Fraudsters leverage localized social engineering (in Uzbek and Russian), craft sophisticated typo-squatting domains mimicking domestic financial institutions (such as Kapitalbank, Click, Payme), and distribute manipulated transaction screenshots or malware-laced files. The lack of automated, localized, and multi-layered threat intelligence makes it exceptionally easy for ordinary citizens to fall victim to these cyber-scams.

## Solution
**ScamShield** addresses this challenge by deploying a distributed, multi-agent cooperative security system built on top of the **Band SDK**. Rather than relying on a single general-purpose model, ScamShield orchestrates four specialized agents in a chat room setting:
1. **ScamShield Coordinator**: Acts as the orchestrator. When a user requests analysis of a suspicious message or file, the Coordinator parses the request and delegates sub-tasks to the appropriate specialized agents, aggregates their findings, and outputs a structured final verdict.
2. **Vision Agent**: Analyzes images, screenshots, and payment receipts using multimodal LLMs (Claude/Gemini) to inspect them for editing artifacts, mismatched fonts, overlay manipulations, or forged bank templates.
3. **Stego Agent**: Executes a production-grade forensics engine performing **nine concurrent deep checks** (LSB stego detection, histogram analysis, appended data detection, entropy scoring, Word VBA macro extraction, PDF JS check, archive scanning, CTF flag extraction, and threat keyword matching).
4. **Text Agent**: Analyzes conversational context, SMS texts, and URLs using localized LLMs to flag phishing tactics, urgency hooks, punycode attacks, and banking typo-squatting.

## Architecture Diagram
```
                      ┌────────────────────────────────────────┐
                      │            User / Chat Room            │
                      └──────────────────┬─────────────────────┘
                                         │
                                         ▼ (Mentions / Request)
                      ┌────────────────────────────────────────┐
                      │         ScamShield Coordinator         │
                      └────┬─────────────┼───────────────┬─────┘
                           │             │               │
                           │ (Delegates) │ (Delegates)   │ (Delegates)
                           ▼             ▼               ▼
                     ┌───────────┐ ┌───────────┐   ┌───────────┐
                     │  Vision   │ │   Stego   │   │   Text    │
                     │   Agent   │ │   Agent   │   │   Agent   │
                     └─────┬─────┘ └─────┬─────┘   └─────┬─────┘
                           │             │               │
                           │ (Inspects)  │ (Analyzes)    │ (Checks)
                           ▼             ▼               ▼
                     ┌───────────┐ ┌───────────┐   ┌───────────┐
                     │  Vision   │ │ Forensics │   │   Text/URL│
                     │   Tool    │ │  Engine   │   │   Tool    │
                     └─────┬─────┘ └─────┬─────┘   └─────┬─────┘
                           │             │               │
      (Claude/Gemini API) ─┘             │               └─ (Ollama/gemma4)
                                         ▼
                                 [ LSB Stego Check ]
                                 [ Histogram Comb  ]
                                 [ Appended Data   ]
                                 [ File Entropy    ]
                                 [ Macro/VBA Check ]
                                 [ JS/PDF Check    ]
                                 [ Rar/Zip Scan    ]
                                 [ CTF Flags Check ]
                                 [ Threat Keywords ]
```

## Tech Stack
| Component | Technology | Description |
| :--- | :--- | :--- |
| **Multi-Agent Orchestration** | Band SDK | Manages message routing, multi-agent chat room, and background polling. |
| **LLM Orchestration** | LangChain & LangGraph | Connects agent workflows, structured outputs, and tool-calling interfaces. |
| **Local Text & URL Agent** | Ollama (`gemma4:12b`) | Performs privacy-preserving local classification of threat words and social engineering. |
| **Vision Analysis LLM** | Anthropic Claude / Gemini API | Multimodal vision models for advanced graphic manipulation and layout verification. |
| **Forensic Analysis** | Production Stego Engine | Pure Python steganography, comb-effect, macro, and archive forensic tools. |

## Key Innovation
1. **Battle-Tested Forensics Engine**: Adapted from a real-world cybersecurity system (**Stego-Shield Bot**), this engine performs nine parallel forensic checks on files (analyzing pixel distributions, embedded scripts, and zip structural offsets) rather than just metadata checking.
2. **Levenshtein Typo-Squatting Detection**: Specifically fine-tuned to protect users of Uzbek banks (e.g., *Kapitalbank*, *Ipak Yuli Bank*, *Anorbank*, *TBC Bank*, *Click*, *Payme*). It computes edit distances on extracted domains to catch tricky lookalikes (like `kap1talbank.uz` or `anorbank.co`) that visual inspections or standard blacklists miss.

## Setup Instructions

### 1. Install Dependencies
Ensure you have Python 3.11+ installed. Run:
```bash
pip install -r requirements.txt
```

### 2. Configure Environment Variables
Copy the `.env.example` file to `.env`:
```bash
cp .env.example .env
```
Open `.env` and fill in your API keys (e.g. `GEMINI_API_KEY`, `ANTHROPIC_API_KEY`).

### 3. Register Agents on Band.ai
1. Go to [app.band.ai](https://app.band.ai) and sign in.
2. Create **four** new External Agents:
   - `Vision Agent`
   - `Stego Agent`
   - `Text Agent`
   - `ScamShield Coordinator`
3. Copy the generated **Agent ID** and **API Key** for each agent.
4. Copy `agent_config.yaml.example` to `agent_config.yaml`:
   ```bash
   cp agent_config.yaml.example agent_config.yaml
   ```
5. Open `agent_config.yaml` and paste the corresponding IDs and API keys.

### 4. Create Chat Room
1. On app.band.ai, create a new Chat Room.
2. Invite all four agents (`ScamShield Coordinator`, `Vision Agent`, `Stego Agent`, `Text Agent`) into the room.

### 5. Pull Ollama Model
For local text analysis, make sure Ollama is installed and running, then pull the model:
```bash
ollama pull gemma4:12b
```

### 6. Run the System Locally
Run the concurrent runner script to initialize and connect all four agents:
```bash
python band_agents/run_all.py
```

### 7. Interact in the Chat Room
In your Band chat room, mention the Coordinator to initiate a verification:
> **@ScamShield Coordinator** analyze this screenshot for fraud and this text: 'Urgent! Send $500 to verify your account at kap1talbank.uz within 1 hour or it will be blocked'

## Demo
Watch the system in action: [[DEMO VIDEO LINK]](https://github.com/placeholder/ScamShield)

## Team
- **Jasur Mahkamov** - Solo Developer (Fergana Valley, Uzbekistan)

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
