#!/usr/bin/env python3
"""Self-check for the Nirva mock provider (no simulator needed).

Speaks the ImpossiBLE socket protocol directly against a headless mock:

  IMPOSSIBLE_MOCK_SOCKET=/tmp/impossible-nirva-test.sock \
      .build/debug/ImpossiBLE-Mock --nirva-headless &
  python3 Tests/nirva-mock-check.py /tmp/impossible-nirva-test.sock

Verifies scan -> connect -> discover -> subscribe -> AUTH echo ->
streaming start (0x0102 DSS packets, rolling counter, L/R tags) -> stop.
"""
import base64
import json
import socket
import struct
import sys
import time

SOCK = sys.argv[1] if len(sys.argv) > 1 else "/tmp/impossible-nirva-test.sock"
CMS_CMD = "A7D42001-5E2B-4C91-9F3A-8B27D6E14A90"
CMS_RSP = "A7D42002-5E2B-4C91-9F3A-8B27D6E14A90"
DSS_DATA = "A7D41001-5E2B-4C91-9F3A-8B27D6E14A90"
DEADLINE = time.time() + 10  # sim-connect assertions must fit in 10s


def pkt(cmd, counter, payload=b""):
    return struct.pack("<HHB", cmd, len(payload), counter) + payload


class Client:
    def __init__(self, path):
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.s.connect(path)
        self.s.settimeout(0.5)
        self.buf = b""

    def send(self, msg):
        self.s.sendall(json.dumps(msg).encode() + b"\n")

    def recv(self, deadline=None):
        while b"\n" not in self.buf:
            if time.time() > (deadline or DEADLINE):
                raise TimeoutError("deadline exceeded")
            try:
                chunk = self.s.recv(65536)
            except socket.timeout:
                continue
            if not chunk:
                raise ConnectionError("socket closed")
            self.buf += chunk
        line, self.buf = self.buf.split(b"\n", 1)
        return json.loads(line)

    def wait_for(self, ty, **match):
        while True:
            msg = self.recv()
            if msg.get("type") == ty and all(msg.get(k) == v for k, v in match.items()):
                return msg


c = Client(SOCK)

c.send({"type": "scan", "services": []})
disc = c.wait_for("didDiscover")
assert disc["name"] == "Nirva Mock", disc
dev = disc["id"]
c.send({"type": "stopScan"})

c.send({"type": "connect", "id": dev})
c.wait_for("didConnect", id=dev)

c.send({"type": "discoverServices", "id": dev, "services": []})
services = {s["uuid"].upper(): s["id"] for s in c.wait_for("didDiscoverServices")["services"]}

chars = {}
for svc_id in services.values():
    c.send({"type": "discoverCharacteristics", "serviceId": svc_id, "characteristics": []})
    for ch in c.wait_for("didDiscoverCharacteristics")["characteristics"]:
        chars[ch["uuid"].upper()] = ch["id"]

for uuid in (CMS_RSP, DSS_DATA):  # subscribe before any CMS write, like the app
    c.send({"type": "setNotify", "characteristicId": chars[uuid], "enabled": True})
    c.wait_for("didUpdateNotification", characteristicId=chars[uuid])


def write_cmd(data):
    c.send({"type": "write", "characteristicId": chars[CMS_CMD],
            "value": base64.b64encode(data).decode(), "writeType": 0})


def rsp_value():
    msg = c.wait_for("didUpdateValue", characteristicId=chars[CMS_RSP])
    return base64.b64decode(msg["value"])


# AUTH 0x0001 -> echo "NIRVA", same counter
write_cmd(pkt(0x0001, 7, b"NIRVA"))
rsp = rsp_value()
assert rsp == pkt(0x0001, 7, b"NIRVA"), rsp.hex()

# STREAMING 0x0010 [01] -> ack [01], then 0x0102 packets on DSS
write_cmd(pkt(0x0010, 8, b"\x01"))
assert rsp_value() == pkt(0x0010, 8, b"\x01")

frames = []
while len(frames) < 20:
    msg = c.wait_for("didUpdateValue", characteristicId=chars[DSS_DATA])
    frames.append(base64.b64decode(msg["value"]))

for i, f in enumerate(frames):
    cmd, length, counter = struct.unpack_from("<HHB", f)
    assert cmd == 0x0102 and length == len(f) - 5, f.hex()
    assert counter == frames[0][4] + i, "counter gap"
    assert f[5] in (0x01, 0x02) and f[5] != frames[i - 1][5] if i else True, "tag"

# STREAMING 0x0010 [00] -> ack, stream stops
write_cmd(pkt(0x0010, 9, b"\x00"))
deadline = time.time() + 1
tail = 0
while time.time() < deadline:
    try:
        msg = c.recv(deadline)
        if msg.get("type") == "didUpdateValue" and msg.get("characteristicId") == chars[DSS_DATA]:
            tail += 1
    except TimeoutError:
        break
assert tail <= 5, f"stream did not stop ({tail} extra frames)"

print(f"OK: auth echo + {len(frames)} DSS frames, counters contiguous, stream stops on disable")
