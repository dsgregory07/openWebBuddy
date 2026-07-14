#!/usr/bin/env python3
"""Offline chat bridge: connects a local Ollama model to the net-diag MCP server's tools.

Runs the platform-appropriate server automatically (net_mcp_server_win.py on Windows,
net_mcp_server.py elsewhere); override with --server.

Usage (Windows):
    net-mcp\\.venv\\Scripts\\python.exe ollama_bridge.py [--model qwen2.5:7b-instruct]
    net-mcp\\.venv\\Scripts\\python.exe ollama_bridge.py --ask "my internet is down"
Usage (Linux):
    .venv/bin/python ollama_bridge.py [--model qwen3:4b]

The default model comes from the MODEL environment variable or the repo-root .env,
falling back to llama3.2:1b — same precedence as the launcher scripts.
"""
import argparse
import asyncio
import os
import platform
import re
import sys
from pathlib import Path

import ollama
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

_HERE = Path(__file__).parent
_DEFAULT_SERVER = _HERE / ("net_mcp_server_win.py" if platform.system() == "Windows" else "net_mcp_server.py")
PYTHON = sys.executable

SYSTEM_PROMPT = (
    "You are an autonomous network troubleshooting agent running locally on this machine. "
    "You diagnose problems by calling diagnostic tools; never guess when a tool can check.\n"
    "\n"
    "Method:\n"
    "1. Think about which layer most likely explains the symptom: local adapter -> Wi-Fi/link -> "
    "gateway/router -> DNS -> WAN/internet -> specific service.\n"
    "2. Call one tool, read its result, then pick the next tool based on what you learned.\n"
    "3. For 'internet is down' reports, a good chain is: list_network_interfaces, then "
    "check_gateway_reachable, then check_internet, then dns_server_check or traceroute_host "
    "depending on what failed.\n"
    "4. Keep investigating until you can state a diagnosis; most problems need 2-6 tool calls. "
    "Never ask the user for permission to run a tool - just run it.\n"
    "5. If a tool fails or times out, note that and try a different tool instead of repeating "
    "the same call.\n"
    "\n"
    "When you are confident, stop calling tools and answer with exactly three sections:\n"
    "DIAGNOSIS: one or two sentences naming the failing layer/component.\n"
    "EVIDENCE: the key tool results that support it.\n"
    "NEXT STEPS: concrete actions for the user, most likely fix first."
)


def default_model() -> str:
    """MODEL env var, else MODEL= from the repo-root .env, else llama3.2:1b."""
    if os.environ.get("MODEL"):
        return os.environ["MODEL"]
    env_file = _HERE.parent / ".env"
    if env_file.is_file():
        for line in env_file.read_text(encoding="utf-8", errors="replace").splitlines():
            m = re.match(r"\s*MODEL\s*=\s*(\S+)", line)
            if m:
                return m.group(1)
    return "llama3.2:1b"


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


def chat(model: str, messages: list, tools: list, options: dict):
    """ollama.chat with thinking disabled; falls back for servers/models that reject `think`."""
    try:
        return ollama.chat(model=model, messages=messages, tools=tools, options=options, think=False)
    except ollama.ResponseError:
        return ollama.chat(model=model, messages=messages, tools=tools, options=options)


async def answer(session, messages, tools, args) -> None:
    """Run the agentic tool loop for the last user message and print the final answer."""
    for round_no in range(1, args.max_rounds + 1):
        response = chat(args.model, messages, tools, {"num_ctx": args.num_ctx, "temperature": args.temperature})
        msg = response["message"]
        messages.append(msg)

        calls = msg.get("tool_calls")
        if not calls:
            print(f"assistant> {msg.get('content', '')}\n")
            return

        for call in calls:
            name = call["function"]["name"]
            call_args = call["function"]["arguments"] or {}
            print(f"  [round {round_no}] {name}({call_args})")
            try:
                result = await session.call_tool(name, dict(call_args))
                text = tool_result_text(result)
            except Exception as e:  # tool crash should not kill the conversation
                text = f"tool error: {e}"
            preview = text if len(text) <= 300 else text[:300] + " ..."
            print("    -> " + preview.replace("\n", "\n       "))
            messages.append({"role": "tool", "tool_name": name, "content": text})
    print("assistant> (stopped after too many tool-call rounds)\n")


async def run(args) -> None:
    server_params = StdioServerParameters(command=PYTHON, args=[str(args.server)])
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            listed = await session.list_tools()
            ollama_tools = [mcp_tool_to_ollama(t) for t in listed.tools]
            print(f"Connected to net-diag MCP server ({len(ollama_tools)} tools). Model: {args.model}")

            messages = [{"role": "system", "content": SYSTEM_PROMPT}]

            if args.ask:
                print(f"you> {args.ask}")
                messages.append({"role": "user", "content": args.ask})
                await answer(session, messages, ollama_tools, args)
                return

            print("Type your network problem, or 'exit' to quit.\n")
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
                await answer(session, messages, ollama_tools, args)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default=default_model(),
                        help="Ollama model tag (default: MODEL env / .env, else llama3.2:1b)")
    parser.add_argument("--server", default=str(_DEFAULT_SERVER),
                        help="path to the MCP server script (default: the one for this OS)")
    parser.add_argument("--ask", default=None,
                        help="ask a single question non-interactively and exit")
    parser.add_argument("--max-rounds", type=int, default=12,
                        help="max tool-call rounds per question (default: 12)")
    parser.add_argument("--num-ctx", type=int, default=8192,
                        help="context window tokens (default: 8192)")
    parser.add_argument("--temperature", type=float, default=0.2,
                        help="sampling temperature; low keeps tool use deterministic (default: 0.2)")
    args = parser.parse_args()
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
