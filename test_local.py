"""
test_local.py — Script to test migrated ScamShield tools locally without FastAPI or LangChain.
"""

import asyncio
import os
import sys

# Ensure project root is on sys.path
_ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
if _ROOT_DIR not in sys.path:
    sys.path.insert(0, _ROOT_DIR)

from tools.vision_tool import vision_fraud_tool
from tools.stego_tool import stego_security_tool
from tools.text_url_tool import text_url_fraud_tool

async def test_tools():
    print("=== Testing Stego / Forensics Tool ===")
    test_file = "fake_screenshot.png"
    if os.path.exists(test_file):
        print(f"Running stego_security_tool on '{test_file}'...")
        stego_res = await stego_security_tool(test_file)
        print("Stego Result:")
        print(f"  Risk Level: {stego_res['risk_level']}")
        print(f"  Summary   : {stego_res['summary']}")
        print(f"  Threats   : {stego_res['threat_words']}")
        print(f"  Flags     : {stego_res['ctf_flags']}")
    else:
        print(f"Warning: test file '{test_file}' not found.")

    print("\n=== Testing Text / URL Phishing Tool ===")
    test_text = "Urgent! Send $500 to verify your account at kap1talbank.uz within 1 hour or it will be blocked"
    print(f"Running text_url_fraud_tool on: '{test_text}'...")
    text_res = await text_url_fraud_tool(test_text)
    print("Text Result:")
    print(f"  Risk Level: {text_res['risk_level']}")
    print(f"  Summary   : {text_res['summary']}")
    print(f"  Findings  : {text_res['text_findings']}")

    print("\n=== Testing Vision Fraud Tool (Requires API Keys / Ollama) ===")
    if os.path.exists(test_file):
        print(f"Running vision_fraud_tool on '{test_file}'...")
        # Note: If no API keys or local Ollama are available, this will return an error dictionary gracefully.
        vision_res = await vision_fraud_tool(test_file)
        print("Vision Result:")
        print(f"  Risk Level: {vision_res['risk_level']}")
        print(f"  Summary   : {vision_res['summary']}")
        print(f"  Findings  : {vision_res['visual_findings']}")
    else:
        print(f"Warning: test file '{test_file}' not found.")

if __name__ == "__main__":
    asyncio.run(test_tools())
