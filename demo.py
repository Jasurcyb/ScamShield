"""
demo.py — CLI interface for ScamShield Orchestrator
"""

import asyncio
import argparse
import sys
from orchestrator import ScamShieldOrchestrator

def print_progress_bar(probability: int):
    """Prints a simple progress bar for the probability."""
    bar_length = 20
    filled_length = int(bar_length * probability // 100)
    bar = '#' * filled_length + '-' * (bar_length - filled_length)
    print(f"[{bar}] {probability}%")

async def main():
    parser = argparse.ArgumentParser(description="ScamShield Full Pipeline Demo")
    parser.add_argument("--file", help="Path to a file (image, document, etc.) to analyze")
    parser.add_argument("--text", help="Text message or URL to analyze")
    
    args = parser.parse_args()
    
    if not args.file and not args.text:
        print("Error: Must provide either --file or --text (or both).")
        parser.print_help()
        sys.exit(1)

    print("\n🚀 Starting ScamShield Analysis Pipeline...\n")
    
    orchestrator = ScamShieldOrchestrator()
    result = await orchestrator.analyze(file_path=args.file, text=args.text)
    
    print("=" * 60)
    print("🎯 SCAMSHIELD FINAL VERDICT")
    print("=" * 60)
    print(f"Overall Risk Level : {result['overall_risk'].upper()}")
    print("Fraud Probability  : ", end="")
    print_progress_bar(result['fraud_probability'])
    print(f"\nFinal Summary:\n  {result['final_summary']}\n")
    
    print("-" * 60)
    print("🤖 INDIVIDUAL AGENT REPORTS")
    print("-" * 60)
    
    for agent_name, report in result['agent_reports'].items():
        print(f"\n[{agent_name.upper()} AGENT]")
        print(f"  Risk Level: {report.get('risk_level', 'unknown').upper()}")
        print(f"  Summary   : {report.get('summary', 'No summary')}")
        
        # Print specific findings if available
        if 'visual_findings' in report and report['visual_findings']:
            print("  Visual Findings:")
            for f in report['visual_findings']: print(f"    - {f}")
        if 'text_findings' in report and report['text_findings']:
            print("  Text Findings:")
            for f in report['text_findings']: print(f"    - {f}")
        if 'ctf_flags' in report and report['ctf_flags']:
            print(f"  CTF Flags : {report['ctf_flags']}")
            
    print("\n" + "=" * 60)

if __name__ == "__main__":
    asyncio.run(main())
