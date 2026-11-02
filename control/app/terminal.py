"""Browser terminal: xterm.js <-> websocket <-> `docker exec -it` in the claude container."""
import asyncio
import json
import socket
import threading
import uuid

from fastapi import WebSocket, WebSocketDisconnect

import tclib

from .config import CLAUDE_CONTAINER
from .dockerops import client


# Fixed commands only – the browser picks an id, never sends a command line.
PROFILES = {
    "claude":    {"title": "Claude · /workspace", "cmd": ["cc"], "hint": "Claude Code in /workspace – persistent tmux session claude-workspace"},
    "login":     {"title": "Claude · sign in", "hint": "Sign the sandbox in to your claude.ai account (claude auth login)", "cmd": ["bash", "-lc", "claude auth login; echo; claude auth status --text; echo; read -rp 'Press Enter to close. '"]},
    "rc":        {"title": "Claude · RC", "hint": "The always-running remote-control session (tmux claude-rc)", "cmd": ["bash", "-lc", "tmux has-session -t claude-rc 2>/dev/null && exec tmux attach -t claude-rc || { echo 'No claude-rc session (container just started?).'; sleep 600; }"]},
    "shell":     {"title": "Shell (user claude)", "hint": "bash in the sandbox with Claude's rights – no access to .env or the SSH key", "cmd": ["bash", "-l"]},
    "svc":       {"title": "Shell · svc list", "hint": "Status of all services and Docker hosts (svc list, svc docker), then a shell to try svc commands", "cmd": ["bash", "-lc", "svc list; echo; svc docker; echo; exec bash -l"]},
    "inventory": {"title": "Claude · system inventory", "hint": "Claude scans hosts, stacks and services and drafts your site rules (local/CLAUDE.md) – you approve before anything is written", "cmd": ["tmux", "new-session", "-A", "-s", "claude-inventory", "-c", "/workspace", "claude", "/inventory"]},
}


def onboard_cmd(name):
    """Claude service onboarding (/onboard <name>) in its own persistent tmux session"""
    if not tclib.valid_name(name):
        raise ValueError("invalid service name")
    return ["tmux", "new-session", "-A", "-s", f"claude-onboard-{name}", "-c", "/workspace", "claude", f"/onboard {name}"]


async def bridge(ws: WebSocket, cmd, workdir="/workspace", user="claude"):
    """every terminal runs as the unprivileged user claude – the same view and rights Claude has"""
    api = client().api
    # docker keeps an exec running after its socket closes – a tmux client per lost connection, shrinking the window
    # to the smallest one. The wrapper notes the pid, so closing hangs it up like a closed terminal window.
    term = uuid.uuid4().hex
    cmd = ["sh", "-c", 'echo $$ > "/tmp/.tc-term-$0"; exec "$@"', term, *cmd]
    exec_id = api.exec_create(CLAUDE_CONTAINER, cmd, tty=True, stdin=True, workdir=workdir, user=user,
                              environment={"TERM": "xterm-256color", "COLORTERM": "truecolor", "LANG": "C.UTF-8"})["Id"]
    sock = api.exec_start(exec_id, tty=True, socket=True)
    raw = getattr(sock, "_sock", sock)
    # docker-py gives the socket its 60 s API timeout – a terminal can be silent much longer (reading, thinking)
    raw.settimeout(None)
    loop = asyncio.get_running_loop()
    queue: asyncio.Queue = asyncio.Queue()

    def reader():
        try:
            while True:
                data = raw.recv(65536)
                if not data:
                    break
                loop.call_soon_threadsafe(queue.put_nowait, data)
        except OSError:
            pass
        loop.call_soon_threadsafe(queue.put_nowait, None)

    threading.Thread(target=reader, daemon=True).start()

    async def pump_out():
        while True:
            data = await queue.get()
            if data is None:
                await ws.send_text(json.dumps({"type": "exit"}))
                return
            await ws.send_bytes(data)

    async def pump_in():
        while True:
            msg = json.loads(await ws.receive_text())
            if msg.get("type") == "input":
                raw.sendall(msg["data"].encode())
            elif msg.get("type") == "ping":  # keepalive: the answer is traffic from upstream, so reverse proxies keep the socket open
                await ws.send_text(json.dumps({"type": "pong"}))
            elif msg.get("type") == "resize":
                try:
                    api.exec_resize(exec_id, height=int(msg["rows"]), width=int(msg["cols"]))
                except Exception:  # noqa: BLE001
                    pass

    out_task = asyncio.create_task(pump_out())
    in_task = asyncio.create_task(pump_in())
    try:
        await asyncio.wait({out_task, in_task}, return_when=asyncio.FIRST_COMPLETED)
    except WebSocketDisconnect:
        pass
    finally:
        for t in (out_task, in_task):
            t.cancel()
        try:
            raw.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        raw.close()
        await asyncio.to_thread(hangup, term, user)


def hangup(term, user):
    """SIGHUP to the terminal's process (a tmux client detaches, Claude keeps running; a shell exits)"""
    try:
        api = client().api
        e = api.exec_create(CLAUDE_CONTAINER, ["sh", "-c", 'f="/tmp/.tc-term-$0"; p=$(cat "$f") && rm -f "$f" && kill -HUP "$p"', term], user=user)
        api.exec_start(e["Id"], detach=True)
    except Exception:  # noqa: BLE001
        pass
