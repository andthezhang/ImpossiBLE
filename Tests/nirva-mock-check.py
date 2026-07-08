#!/usr/bin/env python3
"""Self-check for the Nirva mock provider (no simulator needed).

Speaks the ImpossiBLE socket protocol directly against a headless mock:

  IMPOSSIBLE_MOCK_SOCKET=/tmp/impossible-nirva-test.sock \
      .build/debug/ImpossiBLE-Mock --nirva-headless &
  python3 Tests/nirva-mock-check.py /tmp/impossible-nirva-test.sock

Verifies scan -> connect -> discover -> subscribe -> AUTH echo ->
unified status/version -> streaming start (0x0102 DSS packets, rolling
counter, L/R tags) -> 0x0202 offline LIST/SEND drain -> stop.
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


def unified_payload(*bits):
    payload = bytearray(110)
    for bit in bits:
        payload[bit // 8] |= 1 << (bit % 8)
    return bytes(payload)


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


def rsp_packet(cmd=None):
    while True:
        raw = rsp_value()
        actual_cmd, length, _counter = struct.unpack_from("<HHB", raw)
        assert length == len(raw) - 5, raw.hex()
        if cmd is None or actual_cmd == cmd:
            return raw


# AUTH 0x0001 -> echo "NIRVA", same counter
write_cmd(pkt(0x0001, 7, b"NIRVA"))
rsp = rsp_value()
assert rsp == pkt(0x0001, 7, b"NIRVA"), rsp.hex()

# QUERY_PARAMS 0x0201 -> full unified payload; QUERY_FW_VER mask -> 0x0202 text.
write_cmd(pkt(0x0201, 10))
status = rsp_packet(0x0201)
assert len(status) == 5 + 110 and status[5 + 88] == 1, status.hex()

write_cmd(pkt(0x0202, 11, unified_payload(23)))
version = rsp_packet(0x0202)
assert b"impossible-mock" in version[5:], version
assert rsp_packet(0x0202) == pkt(0x0202, 11)

# START_LC3 0x0202 mask bit 11 -> empty 0x0202 ack, then 0x0102 packets on DSS.
write_cmd(pkt(0x0202, 8, unified_payload(11)))
assert rsp_packet(0x0202) == pkt(0x0202, 8)

frames = []
while len(frames) < 20:
    msg = c.wait_for("didUpdateValue", characteristicId=chars[DSS_DATA])
    frames.append(base64.b64decode(msg["value"]))

for i, f in enumerate(frames):
    cmd, length, counter = struct.unpack_from("<HHB", f)
    assert cmd == 0x0102 and length == len(f) - 5, f.hex()
    assert counter == frames[0][4] + i, "counter gap"
    assert f[5] in (0x01, 0x02) and f[5] != frames[i - 1][5] if i else True, "tag"

# STOP_LC3 before SEND, matching the app drain sequence.
write_cmd(pkt(0x0202, 9, unified_payload(12)))
assert rsp_packet(0x0202) == pkt(0x0202, 9)
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

# LIST 0x0202 QUERY_LFS_FILES mask bit 9 -> legacy action 0x0093 page.
write_cmd(pkt(0x0202, 20, unified_payload(9)))
page = rsp_packet(0x0093)
assert page[4] == 20, page.hex()
lines = page[5:].decode().strip().split("\n")
files = [tuple(l.split(",")) for l in lines]
assert all(n.startswith("lc3_") and n.endswith(".bin") for n, _ in files), files
assert rsp_packet(0x0202) == pkt(0x0202, 20)

# SEND 0x0202 SEND_LC3_DUMP mask bit 13 -> 0x0202 ack, 0x010F plan,
# then raw DSS frames on DSS char. The unified command carries no filename;
# the mock sends the oldest file it advertised above.
name, size = files[0]
write_cmd(pkt(0x0202, 21, unified_payload(13)))
assert rsp_packet(0x0202)[5:] == b"\x01"
plan = rsp_packet(0x010F)
assert plan[:2] == b"\x0f\x01", plan.hex()
total_size, chunk_count = struct.unpack_from("<II", plan, 5)
assert total_size == int(size) and chunk_count > 2, (total_size, size, chunk_count)


def crc16(data):
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return crc


dss = []
wire_bytes = 0
while len(dss) < chunk_count:
    if not dss:
        msg = c.recv()
        assert msg.get("type") == "didUpdateValue", msg
        assert msg.get("characteristicId") == chars[DSS_DATA], msg
    else:
        msg = c.wait_for("didUpdateValue", characteristicId=chars[DSS_DATA])
    f = base64.b64decode(msg["value"])
    seq, ts, dtype = struct.unpack_from("<HIB", f)
    assert seq == len(dss), (seq, len(dss))                    # contiguous from 0
    assert struct.unpack("<H", f[-2:])[0] == crc16(f[:-2])     # CRC16 valid
    assert dtype == (0x01 if seq == 0 else 0x03 if seq == chunk_count - 1 else 0x02)
    if dtype == 0x02:  # LC3_DATA: [01][lenL][L][02][lenR][R]
        d = f[7:-2]
        assert d[0] == 0x01 and d[2 + d[1]] == 0x02, d.hex()
    dss.append(f)
    wire_bytes += len(f)
assert wire_bytes == total_size, (wire_bytes, total_size)

# Unknown file -> plan [0][0]
write_cmd(pkt(0x000F, 22, b"lc3_9999.bin"))
assert rsp_value() == pkt(0x010F, 22, struct.pack("<II", 0, 0))

print(f"OK: auth echo + {len(frames)} audio pkts + LIST {len(files)} files + "
      f"drain {name} ({chunk_count} DSS frames, {wire_bytes}B, CRC/seq valid), stream stops on disable")
