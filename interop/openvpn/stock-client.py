#!/usr/bin/env python3
"""Runs one scenario with the stock openvpn client, to check the bench
itself (CLIENT=openvpn ./run.sh): connects with the given client options,
pings an address through the tunnel, then stops.

    stock-client.py <ip to ping> <openvpn client options...>

Answers come from the management interface (what a GUI does), from the
environment: INTEROP_USERNAME, INTEROP_PASSWORD, INTEROP_OTP; the static
challenge answer is sent as SCRV1:base64(password):base64(code), a CRV1
challenge is answered on the next connection as CRV1::<state>::<code>.
INTEROP_EXPECT_ERROR (a regular expression): give up as soon as a log line
matches it (the client would otherwise retry until the timeout); run.sh
checks the error. INTEROP_DURATION: keep the tunnel up that many
seconds, pinging every second. INTEROP_EXPECT: what the server must have
pushed, separated by commas (full-tunnel, route=<net>, dns=<ip>, domain=<name>).
"""

import base64
import os
import re
import socket
import subprocess
import sys
import threading
import time

TIMEOUT = 30
MANAGEMENT = "/run/openvpn-management.sock"

target, options = sys.argv[1], sys.argv[2:]
env = os.environ.get
expect_error = env("INTEROP_EXPECT_ERROR")
duration = int(env("INTEROP_DURATION") or 0)
lines = []
connected = threading.Event()
failed = threading.Event()


def b64(text):
    return base64.b64encode(text.encode()).decode()


def quote(text):
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def management():
    for _ in range(100):
        try:
            sock = socket.socket(socket.AF_UNIX)
            sock.connect(MANAGEMENT)
            break
        except OSError:
            time.sleep(0.1)
    else:
        lines.append("stock-client: no management interface")
        failed.set()
        return
    send = lambda command: sock.sendall(command.encode() + b"\n")
    send("state on")
    send("hold release")
    challenge = None  # (state, user) of a CRV1 challenge
    for line in sock.makefile(encoding="utf-8", errors="replace"):
        line = line.rstrip("\r\n")
        lines.append("management: " + line)
        if line.startswith(">HOLD:"):
            send("hold release")
        elif line.startswith(">STATE:") and ",CONNECTED," in line:
            connected.set()
        elif line.startswith(">PASSWORD:Verification Failed"):
            match = re.search(r"\['CRV1:[^:]*:([^:]*):([^:]*):", line)
            if match and challenge is None:
                challenge = (match.group(1), base64.b64decode(match.group(2)).decode())
            else:
                lines.append("stock-client: AUTH_FAILED")
                failed.set()
        elif line.startswith(">PASSWORD:Need 'Auth'"):
            user, password = env("INTEROP_USERNAME", ""), env("INTEROP_PASSWORD", "")
            if challenge:
                user, password = challenge[1], f"CRV1::{challenge[0]}::{env('INTEROP_OTP', '')}"
            elif " SC:" in line:
                password = f"SCRV1:{b64(password)}:{b64(env('INTEROP_OTP', ''))}"
            send(f'username "Auth" {quote(user)}')
            send(f'password "Auth" {quote(password)}')


def output(process):
    for line in process.stdout:
        lines.append(line.rstrip("\n"))


def matching(pattern):
    return next((l for l in list(lines) if re.search(pattern, l, re.I)), None)


def ip_routes():
    return subprocess.run(["ip", "route"], capture_output=True, text=True).stdout


def check_expected(expect):
    pushed = matching(r"PUSH_REPLY") or ""
    problems = []
    for item in re.split(r"[ ,]+", expect.strip()):
        if not item:
            continue
        kind, _, value = item.partition("=")
        if kind == "full-tunnel":
            ok = "0.0.0.0/1 " in ip_routes() and "128.0.0.0/1 " in ip_routes()
        elif kind == "route":
            ok = value + " " in ip_routes()
        elif kind == "dns":
            ok = f"dhcp-option DNS {value}" in pushed
        elif kind == "domain":
            ok = f"dhcp-option DOMAIN {value}" in pushed
        else:
            ok = False
        if not ok:
            problems.append(item)
    return problems


def ping():
    if duration:
        result = subprocess.run(["ping", "-i", "1", "-W", "1", "-w", str(duration), target],
                                capture_output=True, text=True)
        stats = re.search(r"(\d+) packets transmitted, (\d+) packets received", result.stdout)
        sent, received = (int(stats.group(1)), int(stats.group(2))) if stats else (0, 0)
        print(f"ping {target} for {duration} s: {received}/{sent} answered")
        # A few losses are allowed while the keys change, not a dead tunnel.
        return sent > 0 and received >= sent * 0.9
    result = subprocess.run(["ping", "-c", "5", "-W", "1", target], capture_output=True, text=True)
    return result.returncode == 0


def main():
    command = ["openvpn", "--client", "--dev", "tun", "--nobind", "--verb", "3",
               "--management", MANAGEMENT, "unix", "--management-hold",
               "--management-query-passwords", "--auth-retry", "interact", *options]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    threading.Thread(target=output, args=(process,), daemon=True).start()
    threading.Thread(target=management, daemon=True).start()
    deadline = time.time() + TIMEOUT
    while time.time() < deadline and not connected.is_set() and process.poll() is None:
        if failed.is_set() or (expect_error and matching(expect_error)):
            break
        time.sleep(0.2)
    ok = False
    if connected.is_set():
        answered = ping()
        problems = check_expected(env("INTEROP_EXPECT", ""))
        ok = answered and not problems
        verdict = f"ping {target} through the tunnel: {'ok' if answered else 'FAILED'}"
        if problems:
            verdict += f", not as expected: {' '.join(problems)}"
    else:
        verdict = "not connected"
    process.terminate()
    try:
        process.wait(5)
    except subprocess.TimeoutExpired:
        process.kill()
    print("\n".join(lines))
    print(verdict)
    return 0 if ok else 1


sys.exit(main())
