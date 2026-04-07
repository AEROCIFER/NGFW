import json
import sys


def main() -> int:
    try:
        import ollama
    except Exception as e:
        print(json.dumps({"ok": False, "stage": "import", "error": str(e)}))
        return 2

    try:
        client = ollama.Client(host="http://localhost:11434")
        resp = client.chat(
            model="gemma4:latest",
            messages=[
                {"role": "system", "content": "You are a test harness. Reply with JSON only."},
                {"role": "user", "content": 'Return exactly: {"pong": true}'},
            ],
            options={"temperature": 0},
            format="json",
        )
        content = resp["message"]["content"]
        parsed = json.loads(content)
        print(json.dumps({"ok": True, "model": "gemma4:latest", "response": parsed}))
        return 0
    except Exception as e:
        print(json.dumps({"ok": False, "stage": "chat", "error": str(e)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

