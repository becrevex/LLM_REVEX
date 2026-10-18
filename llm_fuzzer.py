import ollama
import socket
import time
from scapy.all import *  # or use boofuzz for more structure

TARGET_IP = "127.0.0.1"
TARGET_PORT = 8080
MODEL = "deepseek-coder-v2:16b"  # or qwen2.5-coder:14b

def ask_llm(prompt):
    response = ollama.chat(model=MODEL, messages=[{'role': 'user', 'content': prompt}])
    return response['message']['content'].strip()

def send_packet(data):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((TARGET_IP, TARGET_PORT))
        s.sendall(data.encode() if isinstance(data, str) else data)
        resp = s.recv(4096)
        s.close()
        return resp.decode(errors='ignore')
    except Exception as e:
        return f"CRASH or TIMEOUT: {str(e)}"

# Main loop
print("Starting LLM-driven network fuzzer...")
base_prompt = "You are a network fuzzer. Generate one malformed packet for [YOUR PROTOCOL] that could trigger a vulnerability. Output ONLY the raw bytes/string to send. Previous response: "

seed = "GET / HTTP/1.1\r\nHost: test\r\n"  # starting valid packet

for i in range(500):  # or run forever
    prompt = base_prompt + seed
    if "CRASH" in seed:
        prompt += "\nLast packet crashed the service! Generate similar aggressive mutations."
    
    malformed = ask_llm(prompt)
    print(f"[{i}] Sending: {malformed[:100]}...")
    
    response = send_packet(malformed)
    print(f"Response: {response[:200]}")
    
    # Feed back the actual response so LLM gets smarter
    seed = response or malformed
    
    if "CRASH" in response or "timeout" in response.lower():
        print("🚨 POTENTIAL VULNERABILITY DETECTED! Saving...")
        with open("crashes.log", "a") as f:
            f.write(f"CRASH #{i}: {malformed}\nResponse: {response}\n\n")
        time.sleep(5)  # let service recover
    
    time.sleep(0.1)  # rate limit
