#!/usr/bin/env python3
from boofuzz import *
import sys
import time

def main():
    if len(sys.argv) < 3:
        print("Usage: python boofuzz_vulnserver.py <COMMAND>")
        print("Commands: TRUN, GMON, GTER, HTER, LTER, KSTET")
        print("Example: python boofuzz_vulnserver.py TRUN")
        sys.exit(1)
    
    srv_port = sys.argv[1]
    command = sys.argv[2].upper()
    if command not in ["TRUN", "GMON", "GTER", "HTER", "LTER", "KSTET"]:
        print(f"[-] Unsupported command: {command}")
        sys.exit(1)
    
    print(f"[+] Starting structured fuzzing on {command} command")
    print("[+] Make sure vulnserver.exe is running in Immunity Debugger!")
    print("[+] Press Ctrl+C to stop anytime\n")
    
    session = Session(
        target=Target(
            connection=SocketConnection("127.0.0.1", int(srv_port), proto='tcp')
        ),
        sleep_time=1.0,           # Important for stability (prevents race conditions)
        restart_sleep_time=5,
    )

    s_initialize("Vulnserver")
    s_string(command, fuzzable=False)   # fixed command name
    s_delim(" ", fuzzable=False)
    s_string("A" * 50, name="overflow", fuzzable=True, max_len=10000)

    session.connect(s_get("Vulnserver"))
    session.fuzz()

if __name__ == "__main__":
    main()
