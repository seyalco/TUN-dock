"""Measure the actual tunnel, using SOCKS5 negotiation to explain UDP failures."""

from dataclasses import asdict
import json
import subprocess
import sys

from .core import (
    ROOT, IPv6RouteUnavailable, Proxy, Report, Result, Tunnel, TunnelError,
    require_active, run_process, socks_udp_associate,
)


def _udp_negotiation(proxy, stop):
    if proxy.scheme != "socks5":
        return Result("Unavailable", "HTTP CONNECT carries TCP.")
    try:
        result = run_process(
            [sys.executable, "-m", "tundock.diagnostics", "--socks-udp"],
            cwd=ROOT.parent, timeout=5, stop=stop, input_text=json.dumps(asdict(proxy)),
        )
    except subprocess.TimeoutExpired:
        return Result("Unverified", "SOCKS5 UDP negotiation timed out.")
    if result.returncode:
        return Result("Unverified", "Could not complete SOCKS5 UDP negotiation.")
    return Result(**json.loads(result.stdout))


def probe(proxy, options, stop=None):
    require_active(stop)
    udp = (_udp_negotiation(proxy, stop) if options.udp != "Block"
           else Result("Blocked", "Disabled by your policy."))
    use_udp = udp.state == "Accepted"
    use_ipv6 = options.ipv6 != "Block"

    def run_probe(ipv6):
        with Tunnel(proxy, options, udp=use_udp, ipv6=ipv6) as tunnel:
            tunnel.start(stop)
            args = [sys.executable, "-m", "tundock.probe"]
            if use_udp:
                args.append("udp")
            if ipv6:
                args.append("ipv6")
            completed = tunnel.run(args, cwd=ROOT.parent, timeout=12, stop=stop)
            if completed.returncode:
                raise TunnelError(completed.stderr.strip() or "The isolated connectivity test failed.")
            return json.loads(completed.stdout)

    try:
        result = run_probe(use_ipv6)
    except IPv6RouteUnavailable:
        require_active(stop)
        result = run_probe(False)

    def status(name, ok, failed):
        value = result.get(name, {})
        if not value.get("ok"):
            return Result("Unverified", failed)
        country = value.get("value", "")
        suffix = f" · {country}" if country else ""
        return Result("Verified", f"{ok} · {value['ms']} ms{suffix}")

    if use_udp:
        udp = status("udp", "NTP reply through TUN", "SOCKS5 accepted UDP, but the NTP probe did not reply.")
    ipv6 = (status("ipv6", "HTTPS through IPv6", "No verified IPv6 HTTPS response.")
            if use_ipv6 else Result("Blocked", "Disabled by your policy."))
    return Report(
        tun=Result("Verified", "Private namespace and TUN route are ready."),
        tcp=status("tcp", "TLS and HTTPS through TUN", "The HTTPS probe did not respond."),
        dns=status("dns", "DNS packet answered by the private resolver",
                   "The private resolver did not return a verified DoH answer."),
        udp=udp,
        ipv6=ipv6,
    )


if __name__ == "__main__" and sys.argv[1:] == ["--socks-udp"]:
    proxy = Proxy(**json.load(sys.stdin))
    print(json.dumps(asdict(socks_udp_associate(proxy))))
