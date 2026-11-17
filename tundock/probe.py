"""Public probes run from inside the isolated network."""

import concurrent.futures
import http.client
import json
import os
import socket
import ssl
import struct
import sys
import time

from .core import DNS_ADDRESS


def trace_fields(ip):
    with socket.create_connection((ip, 443), timeout=4) as connection:
        with ssl.create_default_context().wrap_socket(connection, server_hostname="one.one.one.one") as tls:
            tls.sendall(b"GET /cdn-cgi/trace HTTP/1.1\r\nHost: one.one.one.one\r\nConnection: close\r\n\r\n")
            response = http.client.HTTPResponse(tls)
            response.begin()
            if response.status != 200:
                raise OSError(f"Probe returned HTTP {response.status}.")
            fields = dict(line.split("=", 1) for line in response.read(4096).decode().splitlines() if "=" in line)
            return {key: fields[key] for key in ("ip", "loc") if key in fields}


def https_trace(ip):
    return trace_fields(ip).get("loc", "")


def dns(address=DNS_ADDRESS, port=53, timeout=5):
    # A wire query cannot be satisfied by /etc/hosts or the host resolver cache.
    transaction = int.from_bytes(os.urandom(2), "big")
    question = b"\x03one\x03one\x03one\x03one\x00\x00\x01\x00\x01"
    request = struct.pack("!6H", transaction, 0x0100, 1, 0, 0, 0) + question
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as conn:
        conn.settimeout(timeout)
        conn.connect((address, port))
        conn.send(request)
        response = conn.recv(4096)
    if len(response) < 12 + len(question) + 12:
        raise OSError("The private resolver did not return an answer.")
    received, flags, questions, answers, _, _ = struct.unpack_from("!6H", response)
    if (received != transaction or (flags & 0x820F) != 0x8000 or questions != 1 or not answers
            or response[12:12 + len(question)] != question):
        raise OSError("The private resolver returned an invalid DNS response.")
    return ""


def udp():
    token = os.urandom(8)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as conn:
        conn.settimeout(3)
        conn.connect(("162.159.200.1", 123))
        conn.send(b"\x23" + bytes(39) + token)
        reply = conn.recv(512)
        if len(reply) < 48 or reply[0] & 7 != 4 or reply[24:32] != token:
            raise OSError("The UDP probe received no valid NTP reply.")
    return ""


def try_probe(callback):
    started = time.monotonic()
    try:
        value = callback()
        return {"ok": True, "ms": round((time.monotonic() - started) * 1000), "value": value}
    except (OSError, ValueError, http.client.HTTPException):
        return {"ok": False, "ms": 0, "value": ""}


if __name__ == "__main__":
    if sys.argv[1:] == ["--exit-ip"]:
        try:
            print(json.dumps(trace_fields("1.1.1.1")))
        except (OSError, ValueError, http.client.HTTPException):
            sys.exit(1)
        sys.exit(0)
    tasks = {"tcp": lambda: https_trace("1.1.1.1"), "dns": dns}
    if "ipv6" in sys.argv[1:]:
        tasks["ipv6"] = lambda: https_trace("2606:4700:4700::1111")
    if "udp" in sys.argv[1:]:
        tasks["udp"] = udp
    with concurrent.futures.ThreadPoolExecutor() as pool:
        pending = {name: pool.submit(try_probe, callback) for name, callback in tasks.items()}
        print(json.dumps({name: result.result() for name, result in pending.items()}))
