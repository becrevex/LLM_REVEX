You are an expert fuzzing engineer. Write a complete, ready-to-run boofuzz Python script for vulnserver.exe (port 9999).
Command to fuzz: TRUN (or whatever I specify).
Requirements:
- Accept command as sys.argv[1] (TRUN, GMON, GTER, HTER, LTER, KSTET)
- Use Session + SocketConnection("127.0.0.1", 9999, proto='tcp')
- sleep_time=1.0
- s_string(command, fuzzable=False) + s_delim(" ") + s_string("A"*50, name="overflow", fuzzable=True, max_len=10000)
- Clear comments and usage instructions
- Output ONLY the full script, no explanations.



You are an expert network security researcher. Write a complete, ready-to-run Python script using the boofuzz library to fuzz the following network service:

Target: HTTP server on 127.0.0.1:8080 (or describe your protocol)
Protocol spec: [paste any RFC snippet, Wireshark capture summary, or "black-box – discover via traffic"]
Goals: Find buffer overflows, format string bugs, state machine violations, injection points.
Requirements:
- Use Session and Target
- Define blocks for headers, bodies, query strings with primitives (String, Delim, Static, etc.)
- Add intelligent mutations (long strings, special chars, negative numbers, nested structures)
- Include crash detection via connection reset or timeout
- Make it stateful (follow protocol sequence)
- Add logging and save interesting crashes
- Use Python 3.10+ syntax

Output ONLY the full script with comments. No explanations.
