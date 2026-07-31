import json
import logging
import random
from asyncio import CancelledError, create_task, sleep
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from typing import Any

from httpx import AsyncClient
from websockets.asyncio.client import connect as ws_connect
from websockets.exceptions import ConnectionClosed

from .messaging import (
    MESSAGE_VALID_SECONDS,
    PLATFORM_DISCORD,
    InputMessage,
    MessageFilter,
    prefix_id,
)

UTC = timezone.utc
logger = logging.getLogger("discord_msg")
logger.setLevel(logging.INFO)

API_BASE = "https://discord.com/api/v10"
GATEWAY_URL = "wss://gateway.discord.gg/?v=10&encoding=json"
REQUEST_TIMEOUT = 30.0
# DIRECT_MESSAGES only — DM content does not need privileged MESSAGE_CONTENT
INTENT_DIRECT_MESSAGES = 1 << 12

OP_DISPATCH = 0
OP_HEARTBEAT = 1
OP_IDENTIFY = 2
OP_HELLO = 10
OP_HEARTBEAT_ACK = 11

InboundHandler = Callable[[tuple[InputMessage, ...]], Awaitable[None]]


def parse_dm_message_create(
    payload: dict[str, Any],
    *,
    bot_user_id: str | None,
) -> InputMessage | None:
    """Map a MESSAGE_CREATE dispatch payload to InputMessage, or None if ignored."""
    if payload.get("guild_id") is not None:
        return None
    author = payload.get("author") or {}
    author_id = author.get("id")
    if not author_id:
        return None
    if bot_user_id is not None and str(author_id) == str(bot_user_id):
        return None
    content = payload.get("content")
    if not content:
        return None
    msg_id = payload.get("id")
    if not msg_id:
        return None
    created = payload.get("timestamp")
    if not created:
        return None
    try:
        timestamp = datetime.fromisoformat(created.replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=UTC)
        else:
            timestamp = timestamp.astimezone(UTC)
    except ValueError:
        logger.warning("Skipping Discord message with bad timestamp: %s", created)
        return None
    return InputMessage(
        id=str(msg_id),
        timestamp=timestamp,
        content=content,
        sender_id=prefix_id(PLATFORM_DISCORD, author_id),
    )


class AlarmDiscordClient:
    """Minimal Discord Gateway + REST client for DM receive/send."""

    def __init__(
        self,
        *,
        on_ready_register: Callable[["AlarmDiscordClient"], Awaitable[None]],
        on_inbound: InboundHandler,
        message_filter: MessageFilter,
    ):
        self._on_ready_register = on_ready_register
        self._on_inbound = on_inbound
        self._message_filter = message_filter
        self._token: str | None = None
        self._bot_user_id: str | None = None
        self._registered = False
        self._closed = False
        self._ws = None
        self._sequence: int | None = None
        self._heartbeat_task = None
        self._dm_channels: dict[str, str] = {}
        self._http: AsyncClient | None = None

    @property
    def prefixed_bot_id(self) -> str | None:
        if self._bot_user_id is None:
            return None
        return prefix_id(PLATFORM_DISCORD, self._bot_user_id)

    def is_closed(self) -> bool:
        return self._closed

    async def start(self, token: str) -> None:
        self._token = token
        self._closed = False
        self._http = AsyncClient(
            base_url=API_BASE,
            timeout=REQUEST_TIMEOUT,
            headers={
                "Authorization": f"Bot {token}",
                "Content-Type": "application/json",
                "User-Agent": "alarm-monitor (thin-discord)",
            },
        )
        try:
            async with ws_connect(GATEWAY_URL) as ws:
                self._ws = ws
                await self._gateway_loop()
        finally:
            await self.close()

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._heartbeat_task is not None:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except CancelledError:
                pass
            self._heartbeat_task = None
        if self._ws is not None:
            try:
                await self._ws.close()
            except Exception:
                logger.exception("Error closing Discord websocket")
            self._ws = None
        if self._http is not None:
            await self._http.aclose()
            self._http = None

    async def send_dm(self, bare_user_id: str, text: str) -> None:
        try:
            int(bare_user_id)
        except ValueError as exc:
            raise ValueError(f"Invalid Discord user id: {bare_user_id!r}") from exc
        if self._http is None:
            raise RuntimeError("Discord client is not connected")

        channel_id = self._dm_channels.get(bare_user_id)
        if channel_id is None:
            channel_id = await self._create_dm_channel(bare_user_id)
            self._dm_channels[bare_user_id] = channel_id

        response = await self._http.post(
            f"/channels/{channel_id}/messages",
            json={"content": text},
        )
        response.raise_for_status()

    async def _create_dm_channel(self, bare_user_id: str) -> str:
        assert self._http is not None
        response = await self._http.post(
            "/users/@me/channels",
            json={"recipient_id": bare_user_id},
        )
        response.raise_for_status()
        channel_id = response.json().get("id")
        if not channel_id:
            raise RuntimeError("Discord create DM response missing channel id")
        return str(channel_id)

    async def _gateway_loop(self) -> None:
        assert self._ws is not None
        try:
            async for raw in self._ws:
                if self._closed:
                    break
                data = json.loads(raw)
                await self._handle_payload(data)
        except ConnectionClosed:
            logger.info("Discord gateway connection closed")

    async def _handle_payload(self, data: dict[str, Any]) -> None:
        op = data.get("op")
        seq = data.get("s")
        if seq is not None:
            self._sequence = seq
        t = data.get("t")
        d = data.get("d")

        if op == OP_HELLO:
            interval_ms = (d or {}).get("heartbeat_interval", 41250)
            await self._start_heartbeat(interval_ms / 1000.0)
            await self._identify()
            return

        if op == OP_HEARTBEAT:
            await self._send_heartbeat()
            return

        if op == OP_HEARTBEAT_ACK:
            return

        if op == OP_DISPATCH:
            if t == "READY":
                user = (d or {}).get("user") or {}
                self._bot_user_id = str(user.get("id")) if user.get("id") else None
                if not self._registered:
                    await self._on_ready_register(self)
                    self._registered = True
                    logger.info("Discord connected as %s", self.prefixed_bot_id)
                return
            if t == "MESSAGE_CREATE":
                await self._on_message_create(d or {})
                return

    async def _identify(self) -> None:
        assert self._ws is not None and self._token is not None
        payload = {
            "op": OP_IDENTIFY,
            "d": {
                "token": self._token,
                "intents": INTENT_DIRECT_MESSAGES,
                "properties": {
                    "os": "linux",
                    "browser": "alarm-monitor",
                    "device": "alarm-monitor",
                },
            },
        }
        await self._ws.send(json.dumps(payload))

    async def _start_heartbeat(self, interval_seconds: float) -> None:
        if self._heartbeat_task is not None:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except CancelledError:
                pass

        async def heartbeat_loop() -> None:
            # Discord recommends jittering the first heartbeat.
            await sleep(interval_seconds * random.random())
            while not self._closed:
                await self._send_heartbeat()
                await sleep(interval_seconds)

        self._heartbeat_task = create_task(heartbeat_loop(), name="discord_heartbeat")

    async def _send_heartbeat(self) -> None:
        if self._ws is None or self._closed:
            return
        await self._ws.send(
            json.dumps({"op": OP_HEARTBEAT, "d": self._sequence})
        )

    async def _on_message_create(self, payload: dict[str, Any]) -> None:
        if not self._registered:
            return
        inbound = parse_dm_message_create(payload, bot_user_id=self._bot_user_id)
        if inbound is None:
            return
        filtered = self._message_filter.filter((inbound,), MESSAGE_VALID_SECONDS)
        self._message_filter.clear_processed()
        if filtered:
            await self._on_inbound(filtered)


def make_discord_client(
    *,
    on_ready_register: Callable[[AlarmDiscordClient], Awaitable[None]],
    on_inbound: InboundHandler,
    message_filter: MessageFilter,
) -> AlarmDiscordClient:
    return AlarmDiscordClient(
        on_ready_register=on_ready_register,
        on_inbound=on_inbound,
        message_filter=message_filter,
    )
