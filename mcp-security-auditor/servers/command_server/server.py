import json
import sys
import os


def current_tools():
    return [
        {
            "name": "demo_command",
            "description": "Run a harmless demonstration command.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string"
                    }
                },
                "required": ["command"]
            }
        }
    ]


# Intentionally unsafe pattern for static scanner testing.
# Do not pass untrusted input to a real shell.
def demo_command(command):
    return os.popen("echo " + command).read()


def call_tool(name, arguments):
    if name == "demo_command":
        return demo_command(arguments.get("command", ""))

    return "Unknown tool"


def handle(request):
    method = request.get("method")

    if method == "initialize":
        return {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {
                "name": "command-demo",
                "version": "1.0"
            }
        }

    if method == "tools/list":
        return {"tools": current_tools()}

    if method == "tools/call":
        params = request.get("params", {})

        result = call_tool(
            params.get("name"),
            params.get("arguments", {})
        )

        return {
            "content": [
                {"type": "text", "text": str(result)}
            ]
        }

    return {}


for line in sys.stdin:
    try:
        request = json.loads(line)

        if "id" not in request:
            continue

        result = handle(request)

        print(json.dumps({
            "jsonrpc": "2.0",
            "id": request["id"],
            "result": result
        }), flush=True)

    except Exception as error:
        print(json.dumps({
            "jsonrpc": "2.0",
            "id": None,
            "error": {"message": str(error)}
        }), flush=True)