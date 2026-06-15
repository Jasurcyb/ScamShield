"""
band_agents/test_tool_calling.py — Test if the local Ollama model supports LangChain tool calling
"""

import os
import json
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain_core.tools import tool

load_dotenv()

@tool
def get_weather(city: str) -> str:
    """Get the current weather for a specific city."""
    # Dummy implementation for testing
    return f"The weather in {city} is sunny and 25°C."

def test_ollama_tools():
    print("Testing Ollama tool calling via LangChain's OpenAI adapter...")
    
    model_name = os.environ.get("OLLAMA_MODEL", "gemma4:12b")
    base_url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434/v1")
    
    print(f"Model: {model_name}")
    print(f"Base URL: {base_url}\n")
    
    llm = ChatOpenAI(
        model=model_name,
        base_url=base_url,
        api_key="ollama",
        temperature=0.1
    )
    
    # Bind the tool to the model
    llm_with_tools = llm.bind_tools([get_weather])
    
    print("Sending prompt: 'What is the weather like in Tashkent today?'")
    try:
        response = llm_with_tools.invoke("What is the weather like in Tashkent today?")
        
        print("\n--- Response ---")
        print(f"Content: {response.content}")
        
        if hasattr(response, 'tool_calls') and response.tool_calls:
            print("\n✅ Tool calls detected!")
            print(json.dumps(response.tool_calls, indent=2))
            
            # Optionally simulate tool execution
            for tool_call in response.tool_calls:
                if tool_call['name'] == 'get_weather':
                    print(f"\nSimulating execution of {tool_call['name']}...")
                    result = get_weather.invoke(tool_call['args'])
                    print(f"Result: {result}")
        else:
            print("\n❌ No tool calls detected. The model might not support tool calling properly via this adapter.")
            
    except Exception as e:
        print(f"\n❌ Error during model invocation: {e}")

if __name__ == "__main__":
    test_ollama_tools()
