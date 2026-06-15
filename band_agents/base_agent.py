"""
band_agents/base_agent.py — Manual polling-based Band SDK Agent Integration
"""

import asyncio
from langchain_core.messages import SystemMessage, HumanMessage, ToolMessage
from thenvoi_rest import AsyncRestClient

class SimpleBandAgent:
    def __init__(self, name, agent_id, api_key, system_prompt, llm, tools=None):
        self.name = name
        self.agent_id = agent_id
        self.api_key = api_key
        self.system_prompt = system_prompt
        self.llm = llm
        self.tools = tools or []
        self.client = AsyncRestClient(
            api_key=self.api_key,
            base_url="https://app.band.ai"
        )
        
        if self.tools:
            self.llm_with_tools = self.llm.bind_tools(self.tools)
        else:
            self.llm_with_tools = self.llm
            
        self.tool_map = {t.name: t for t in self.tools}

    async def _process_message(self, chat_id, message):
        try:
            # 1. Mark message as processing
            await self.client.agent_api_messages.mark_agent_message_processing(chat_id=chat_id, id=message.id)
            safe_msg = (message.content[:80] + '...') if len(message.content) > 80 else message.content
            print(f"[{self.name}] Processing message: {safe_msg}")
            
            # 2. Prepare LangChain conversation
            messages = [
                SystemMessage(content=self.system_prompt),
                HumanMessage(content=message.content)
            ]
            
            # 3. Call LLM
            response = await self.llm_with_tools.ainvoke(messages)
            
            # 4. Handle tool calls if any
            if response.tool_calls:
                messages.append(response)
                for tc in response.tool_calls:
                    print(f"[{self.name}] Calling tool {tc['name']} with args {tc['args']}")
                    tool = self.tool_map.get(tc['name'])
                    if tool:
                        # Some tools might be synchronous or asynchronous. ainvoke handles both safely.
                        result = await tool.ainvoke(tc['args'])
                        messages.append(ToolMessage(tool_call_id=tc['id'], content=str(result), name=tc['name']))
                    else:
                        error_msg = f"Error: Tool {tc['name']} not found"
                        messages.append(ToolMessage(tool_call_id=tc['id'], content=error_msg, name=tc['name']))
                
                # Second pass to get the final answer from LLM
                response = await self.llm_with_tools.ainvoke(messages)
                
            final_text = response.content
            safe_reply = (final_text[:80] + '...') if len(final_text) > 80 else final_text
            print(f"[{self.name}] Sending reply: {safe_reply}")
            
            # 5. Send message back to the chat room
            # Mention the original sender (required: minItems 1)
            mention = {"id": message.sender_id}
            if message.sender_name:
                mention["name"] = message.sender_name
            await self.client.agent_api_messages.create_agent_chat_message(
                chat_id=chat_id,
                message={"content": final_text, "mentions": [mention]}
            )
            
            # 6. Mark original message as processed
            await self.client.agent_api_messages.mark_agent_message_processed(chat_id=chat_id, id=message.id)
            print(f"[{self.name}] Message marked as processed.")
            
        except Exception as e:
            print(f"[{self.name}] Error processing message: {e}")
            try:
                # Mark as failed so it doesn't block forever
                await self.client.agent_api_messages.mark_agent_message_failed(chat_id=chat_id, id=message.id, error=str(e))
            except Exception as mark_error:
                print(f"[{self.name}] Failed to mark message as failed: {mark_error}")
                
    async def run(self):
        print(f"[{self.name}] Starting polling loop...")
        while True:
            try:
                # Get all chats for this agent
                chats_response = await self.client.agent_api_chats.list_agent_chats()
                if not chats_response.data:
                    print(f"[{self.name}] No chats found, waiting...")
                else:
                    for chat in chats_response.data:
                        try:
                            # Try to get the next pending message
                            next_msg_res = await self.client.agent_api_messages.get_agent_next_message(chat_id=chat.id)
                            # Ensure we actually got a message (depending on API, it might return None or throw 404 if empty)
                            if next_msg_res and getattr(next_msg_res, 'data', None):
                                await self._process_message(chat.id, next_msg_res.data)
                        except Exception as inner_e:
                            err_str = str(inner_e).lower()
                            # 404 / 'not found' typically means no pending message, which is expected
                            # 204 No Content also means no pending message
                            if "404" not in err_str and "not found" not in err_str and "204" not in err_str:
                                print(f"[{self.name}] Error fetching next message for chat {chat.id}: {inner_e}")
            except Exception as e:
                print(f"[{self.name}] Error listing chats: {e}")
            
            await asyncio.sleep(2)
