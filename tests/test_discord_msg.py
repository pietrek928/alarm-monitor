from datetime import datetime, timezone

import httpx
import pytest

from alarm_monitor.discord_msg import (
    AlarmDiscordClient,
    parse_dm_message_create,
)
from alarm_monitor.messaging import MessageFilter


UTC = timezone.utc


def test_parse_dm_message_create():
    payload = {
        "id": "111",
        "content": "hej",
        "timestamp": "2026-07-30T10:00:00.000000+00:00",
        "author": {"id": "222", "username": "user"},
        "guild_id": None,
    }
    msg = parse_dm_message_create(payload, bot_user_id="999")
    assert msg is not None
    assert msg.id == "111"
    assert msg.content == "hej"
    assert msg.sender_id == "discord:222"
    assert msg.timestamp == datetime(2026, 7, 30, 10, 0, tzinfo=UTC)


def test_parse_ignores_guild_self_and_empty():
    base = {
        "id": "1",
        "content": "hi",
        "timestamp": "2026-07-30T10:00:00+00:00",
        "author": {"id": "222"},
    }
    assert (
        parse_dm_message_create({**base, "guild_id": "guild"}, bot_user_id="999")
        is None
    )
    assert (
        parse_dm_message_create(
            {**base, "author": {"id": "999"}}, bot_user_id="999"
        )
        is None
    )
    assert (
        parse_dm_message_create({**base, "content": ""}, bot_user_id="999")
        is None
    )


@pytest.mark.asyncio
async def test_send_dm_creates_channel_then_message():
    calls: list[tuple[str, str, dict | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = request.content.decode() if request.content else None
        payload = None
        if body:
            import json

            payload = json.loads(body)
        path = request.url.path
        calls.append((request.method, path, payload))
        if path.endswith("/users/@me/channels"):
            return httpx.Response(200, json={"id": "chan-1"})
        if path.endswith("/channels/chan-1/messages"):
            return httpx.Response(200, json={"id": "msg-1"})
        return httpx.Response(404, json={"message": f"not found: {path}"})

    async def noop_ready(_client):
        return None

    async def noop_inbound(_messages):
        return None

    transport = httpx.MockTransport(handler)
    client = AlarmDiscordClient(
        on_ready_register=noop_ready,
        on_inbound=noop_inbound,
        message_filter=MessageFilter(),
    )
    client._http = httpx.AsyncClient(
        base_url="https://discord.com/api/v10",
        transport=transport,
        headers={"Authorization": "Bot test"},
    )
    try:
        await client.send_dm("123456789012345678", "hello")
        await client.send_dm("123456789012345678", "again")
    finally:
        await client._http.aclose()

    assert calls[0][0] == "POST"
    assert calls[0][1].endswith("/users/@me/channels")
    assert calls[0][2] == {"recipient_id": "123456789012345678"}
    assert calls[1][0] == "POST"
    assert calls[1][1].endswith("/channels/chan-1/messages")
    assert calls[1][2] == {"content": "hello"}
    # Second DM reuses cached channel
    assert calls[2][0] == "POST"
    assert calls[2][1].endswith("/channels/chan-1/messages")
    assert calls[2][2] == {"content": "again"}


@pytest.mark.asyncio
async def test_send_dm_rejects_non_numeric_id():
    async def noop_ready(_client):
        return None

    async def noop_inbound(_messages):
        return None

    client = AlarmDiscordClient(
        on_ready_register=noop_ready,
        on_inbound=noop_inbound,
        message_filter=MessageFilter(),
    )
    with pytest.raises(ValueError, match="Invalid Discord user id"):
        await client.send_dm("not-a-number", "hi")
