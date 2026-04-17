"""
pcap_builder.py — Convert a list of SimPacket objects into real .pcap bytes.

Strategy
--------
* TCP packets get a full SYN→SYN-ACK→ACK handshake injected once per unique
  (src_ip, src_port, dst_ip, dst_port) 4-tuple, so Suricata can reassemble
  the stream and evaluate flow:established / flow:to_server rules correctly.
* Sequence numbers are tracked per session so data packets carry consistent
  seq/ack values that follow naturally from the handshake.
* UDP and DNS packets are emitted as plain Ether/IP/UDP datagrams.
* ICMP packets are emitted as proper echo-request frames (type 8, code 0).
* Checksums are intentionally left to scapy defaults; Suricata is invoked
  with -k none so checksum errors never suppress alerts.
"""
from __future__ import annotations

import io
import random
from dataclasses import dataclass, field

from scapy.all import Ether, IP, TCP, UDP, ICMP, Raw
from scapy.utils import PcapWriter

from app.simulation.scenarios import SimPacket


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_pcap(packets: list[SimPacket]) -> bytes:
    """
    Convert *packets* into pcap bytes.

    Returns the complete pcap file as a ``bytes`` object — ready to be
    written to disk (e.g. ``/tmp/sim_xxx/traffic.pcap``) and fed to
    ``suricata -r``.
    """
    scapy_pkts = _build_scapy_packets(packets)
    buf = io.BytesIO()
    writer = PcapWriter(buf, nano=False, sync=True)
    for pkt in scapy_pkts:
        writer.write(pkt)
    writer.flush()
    result = buf.getvalue()
    writer.close()
    return result


# ---------------------------------------------------------------------------
# Session tracking
# ---------------------------------------------------------------------------

@dataclass
class _Session:
    """Per-TCP-session state carried across packets."""
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    client_seq: int = field(default=0)
    server_seq: int = field(default=0)

    @property
    def key(self) -> tuple:
        return (self.client_ip, self.client_port, self.server_ip, self.server_port)


# ---------------------------------------------------------------------------
# Core builder
# ---------------------------------------------------------------------------

def _build_scapy_packets(sim_packets: list[SimPacket]) -> list:
    result: list = []
    sessions: dict[tuple, _Session] = {}

    for sp in sim_packets:
        proto = sp.protocol.lower()

        if proto == "tcp":
            key = (sp.src_ip, sp.src_port, sp.dst_ip, sp.dst_port)
            if key not in sessions:
                sess = _Session(
                    client_ip=sp.src_ip,
                    client_port=sp.src_port,
                    server_ip=sp.dst_ip,
                    server_port=sp.dst_port,
                )
                handshake_pkts, sess = _tcp_handshake(sess)
                result.extend(handshake_pkts)
                sessions[key] = sess

            sess = sessions[key]
            if sp.payload:
                data_pkt, sess = _tcp_data(sess, sp.payload, sp.flags)
                result.append(data_pkt)
                sessions[key] = sess

        elif proto in ("udp", "dns"):
            result.append(_udp_packet(sp.src_ip, sp.src_port, sp.dst_ip, sp.dst_port, sp.payload))

        elif proto in ("icmp", "icmp6"):
            result.append(_icmp_packet(sp.src_ip, sp.dst_ip))

    return result


# ---------------------------------------------------------------------------
# Packet factories
# ---------------------------------------------------------------------------

def _eth_ip(src_ip: str, dst_ip: str):
    """Base Ethernet + IP layer pair."""
    return Ether() / IP(src=src_ip, dst=dst_ip)


def _tcp_handshake(sess: _Session) -> tuple[list, _Session]:
    """
    Emit SYN / SYN-ACK / ACK for *sess*.

    Returns the packet list and an updated session whose ``client_seq`` and
    ``server_seq`` are set to the post-handshake values (ISN + 1, because
    the SYN byte itself consumes one sequence-number slot).
    """
    client_isn = random.randint(1_000_000, 0xFFFF_FF00)
    server_isn = random.randint(1_000_000, 0xFFFF_FF00)

    syn = _eth_ip(sess.client_ip, sess.server_ip) / TCP(
        sport=sess.client_port,
        dport=sess.server_port,
        flags="S",
        seq=client_isn,
        ack=0,
        window=65535,
    )
    syn_ack = _eth_ip(sess.server_ip, sess.client_ip) / TCP(
        sport=sess.server_port,
        dport=sess.client_port,
        flags="SA",
        seq=server_isn,
        ack=client_isn + 1,
        window=65535,
    )
    ack = _eth_ip(sess.client_ip, sess.server_ip) / TCP(
        sport=sess.client_port,
        dport=sess.server_port,
        flags="A",
        seq=client_isn + 1,
        ack=server_isn + 1,
        window=65535,
    )

    sess.client_seq = client_isn + 1
    sess.server_seq = server_isn + 1
    return [syn, syn_ack, ack], sess


def _tcp_data(sess: _Session, payload: str, flags: str) -> tuple[object, _Session]:
    """
    Emit a single PSH-ACK data packet from the client side.

    Uses and advances ``sess.client_seq`` so that subsequent data packets
    in the same session carry monotonically increasing sequence numbers.
    """
    raw = _encode(payload)
    tcp_flags = flags.upper() if flags else "PA"

    pkt = _eth_ip(sess.client_ip, sess.server_ip) / TCP(
        sport=sess.client_port,
        dport=sess.server_port,
        flags=tcp_flags,
        seq=sess.client_seq,
        ack=sess.server_seq,
        window=65535,
    ) / Raw(load=raw)

    sess.client_seq += len(raw)
    return pkt, sess


def _udp_packet(src_ip: str, src_port: int, dst_ip: str, dst_port: int, payload: str) -> object:
    return _eth_ip(src_ip, dst_ip) / UDP(sport=src_port, dport=dst_port) / Raw(load=_encode(payload))


def _icmp_packet(src_ip: str, dst_ip: str) -> object:
    return _eth_ip(src_ip, dst_ip) / ICMP(type=8, code=0) / Raw(load=b"\x08\x00" + b"\x00" * 14)


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _encode(payload: str) -> bytes:
    """Encode a payload string to bytes, replacing un-encodable characters."""
    if isinstance(payload, bytes):
        return payload
    return payload.encode("utf-8", errors="replace")
