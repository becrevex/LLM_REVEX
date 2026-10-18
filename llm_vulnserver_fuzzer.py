import ollama
import socket
import time
import datetime
import json
from typing import List

# ================== CONFIG ==================
TARGET_IP = "127.0.0.1"          # Change if vulnserver is on another machine
TARGET_PORT = 9999
MODEL = "deepseek-coder-v2:lite" # ← best for this task
CRASH_TIMEOUT = 3                # seconds to detect hang/crash
LOG_FILE = "vulnserver_crashes.log"
CRASH_JSON = "crashes.json"

VULN_COMMANDS = ["TRUN", "GMON", "GTER", "HTER", "LTER", "KSTET"]
# ===========================================

def is_server_alive() -> bool:
    """Quick check after each test"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((TARGET_IP, TARGET_PORT))
        s.send(b"HELP\r\n")
        resp = s.recv(1024)
        s.close()
        return b"Valid Commands" in resp or len(resp) > 10
    except:
        return False

def send_payload(payload: str) -> str:
    """Send and return response or crash indicator"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(CRASH_TIMEOUT)
        s.connect((TARGET_IP, TARGET_PORT))
        s.send((payload + "\r\n").encode("utf-8", errors="ignore"))
        resp = s.recv(4096).decode("utf-8", errors="ignore")
        s.close()
        return resp.strip() if resp else "NO_RESPONSE"
    except socket.timeout:
        return "TIMEOUT - POSSIBLE CRASH"
    except Exception as e:
        return f"CRASH_DETECTED: {str(e)}"

def ask_llm(history: List[str], crashes: List[dict]) -> str:
    """LLM decides the next smart payload"""
    crash_summary = "\n".join([f"CRASH #{c['iter']}: {c['payload']}" for c in crashes[-3:]])
    prompt = f"""You are an expert fuzzing AI targeting vulnserver.exe (port 9999).
Vulnerable commands: TRUN, GMON, GTER, HTER, LTER, KSTET (all take one parameter after a space).

Previous 5 interactions:
{'\\n'.join(history[-5:])}

Recent crashes:
{crash_summary or "None yet"}

Generate ONE new test case that is likely to trigger a buffer overflow or crash.
- Choose any command (or a new mutation pattern).
- Use extremely long strings, special chars, format strings, nested delimiters, etc.
- Output **ONLY** the exact string to send (e.g. "TRUN AAAAAAAAAAAAAAAAA..." or "GMON /././...").
No explanations, no markdown, no extra text."""

    try:
        resp = ollama.chat(model=MODEL, messages=[{"role": "user", "content": prompt}])
        return resp["message"]["content"].strip()
    except Exception as e:
        print(f"LLM error: {e}")
        return "TRUN " + "A" * 2000

# ================== MAIN LOOP ==================
print("🚀 LLM-Powered Vulnserver Fuzzer Starting")
print(f"Target: {TARGET_IP}:{TARGET_PORT} | Model: {MODEL}")
print("Run vulnserver.exe in Immunity Debugger first!\n")

history: List[str] = []
crashes: List[dict] = []
iteration = 0

while True:
    iteration += 1
    payload = ask_llm(history, crashes)
    print(f"[{iteration}] Sending: {payload[:80]}{'...' if len(payload)>80 else ''}")

    response = send_payload(payload)
    print(f"    → Response: {response[:120]}{'...' if len(response)>120 else ''}")

    # Record in history
    history.append(f"Sent: {payload} | Resp: {response[:100]}")

    # Crash detection
    if "CRASH" in response.upper() or "TIMEOUT" in response.upper() or not is_server_alive():
        crash_time = datetime.datetime.now().isoformat()
        crash_entry = {
            "iteration": iteration,
            "timestamp": crash_time,
            "payload": payload,
            "response": response
        }
        crashes.append(crash_entry)

        print(f"🚨 CRASH DETECTED on iteration {iteration}! Saving...")

        with open(LOG_FILE, "a") as f:
            f.write(f"[{crash_time}] CRASH #{iteration}\nPayload: {payload}\nResponse: {response}\n\n")
        
        with open(CRASH_JSON, "w") as f:
            json.dump(crashes, f, indent=2)

        print("   → Restart vulnserver.exe in your debugger and press ENTER to continue...")
        input()  # Wait for you to restart the target

    time.sleep(0.1)  # Gentle rate limit
