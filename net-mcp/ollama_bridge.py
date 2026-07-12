#!/usr/bin/env python3
"""Offline chat bridge: connects a local Ollama model to the net-diag MCP server's tools.

Usage:
    .venv/bin/python ollama_bridge.py [--model llama3.2:1b]
"""
import argparse
import asyncio
import sys
from pathlib import Path

import ollama
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

SERVER_SCRIPT = Path(__file__).parent / "net_mcp_server.py"
PYTHON = sys.executable

SYSTEM_PROMPT = (
    "You are an offline network troubleshooting assistant running locally on a Raspberry Pi. "
    "You have tools to check the default gateway, ping/traceroute hosts, resolve DNS, list network "
    "interfaces, ARP-scan the LAN, and scan ports on devices including the router. "
    "You have no internet access yourself beyond what these tools provide — use them rather than "
    "guessing. When a user reports connectivity trouble, start by checking network interfaces and "
    "the default gateway before assuming the WAN/internet is at fault. Be concise and give concrete "
    "next steps."
)


def mcp_tool_to_ollama(tool) -> dict:
    return {
        "type": "function",
        "function": {
            "name": tool.name,
            "description": tool.description or "",
            "parameters": tool.inputSchema,
        },
    }


def tool_result_text(result) -> str:
    parts = []
    for block in result.content:
        text = getattr(block, "text", None)
        if text is not None:
            parts.append(text)
    return "\n".join(parts) if parts else "(no output)"


async def run(model: str) -> None:
    server_params = StdioServerParameters(command=PYTHON, args=[str(SERVER_SCRIPT)])
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            listed = await session.list_tools()
            ollama_tools = [mcp_tool_to_ollama(t) for t in listed.tools]
            print(f"Connected to net-diag MCP server ({len(ollama_tools)} tools). Model: {model}")
            print("Type your network problem, or 'exit' to quit.\n")

            messages = [{"role": "system", "content": SYSTEM_PROMPT}]
            while True:
                try:
                    user_input = input("you> ").strip()
                except (EOFError, KeyboardInterrupt):
                    print()
                    break
                if not user_input:
                    continue
                if user_input.lower() in ("exit", "quit"):
                    break

                messages.append({"role": "user", "content": user_input})

                for _ in range(8):  # cap tool-call rounds per turn
                    response = ollama.chat(model=model, messages=messages, tools=ollama_tools, think=False)
                    msg = response["message"]
                    messages.append(msg)

                    calls = msg.get("tool_calls")
                    if not calls:
                        print(f"assistant> {msg.get('content', '')}\n")
                        break

                    for call in calls:
                        name = call["function"]["name"]
                        args = call["function"]["arguments"] or {}
                        print(f"  [tool] {name}({args})")
                        result = await session.call_tool(name, args)
                        text = tool_result_text(result)
                        messages.append({"role": "tool", "tool_name": name, "content": text})
                else:
                    print("assistant> (stopped after too many tool-call rounds)\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default="llama3.2:1b", help="Ollama model tag to use (default: llama3.2:1b)")
    args = parser.parse_args()
    asyncio.run(run(args.model))


if __name__ == "__main__":
    main()
