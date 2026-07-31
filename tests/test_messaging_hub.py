import pytest

from alarm_monitor.messaging import MessagingHub


class FakeTransport:
    def __init__(self, *, fail_for: set[str] | None = None):
        self.sent: list[tuple[str, str]] = []
        self.fail_for = fail_for or set()

    async def __call__(self, bare_id: str, text: str) -> None:
        if bare_id in self.fail_for:
            raise RuntimeError(f"boom {bare_id}")
        self.sent.append((bare_id, text))


@pytest.mark.asyncio
async def test_hub_routes_by_prefix():
    hub = MessagingHub()
    fb = FakeTransport()
    dc = FakeTransport()
    hub.register("fb", fb, "fb:bot")
    hub.register("discord", dc, "discord:bot")

    await hub.send("fb:1", "a")
    await hub.send("discord:2", "b")
    assert fb.sent == [("1", "a")]
    assert dc.sent == [("2", "b")]
    assert hub.live_platforms == {"fb", "discord"}
    assert hub.bot_ids == {"fb:bot", "discord:bot"}


@pytest.mark.asyncio
async def test_hub_skips_down_platform():
    hub = MessagingHub()
    fb = FakeTransport()
    hub.register("fb", fb, "fb:bot")
    await hub.send("discord:1", "nope")
    assert fb.sent == []


@pytest.mark.asyncio
async def test_hub_skips_malformed_id():
    hub = MessagingHub()
    fb = FakeTransport()
    hub.register("fb", fb, "fb:bot")
    await hub.send("not-an-id", "x")
    assert fb.sent == []


@pytest.mark.asyncio
async def test_broadcast_isolates_failures_and_chunks():
    hub = MessagingHub()
    fb = FakeTransport(fail_for={"bad"})
    hub.register("fb", fb, "fb:bot")
    long = "x" * 2500
    await hub.broadcast(("fb:ok", "fb:bad", "fb:ok2"), long)
    # ok got 2 chunks; bad failed after first chunk attempt; ok2 still delivered
    assert ("ok", long[:2000]) in fb.sent
    assert ("ok", long[2000:]) in fb.sent
    assert ("ok2", long[:2000]) in fb.sent
    assert ("ok2", long[2000:]) in fb.sent


@pytest.mark.asyncio
async def test_hub_logs_outbound(caplog):
    import logging

    hub = MessagingHub()
    fb = FakeTransport()
    hub.register("fb", fb, "fb:bot")
    with caplog.at_level(logging.INFO, logger="alarm_monitor.messaging"):
        await hub.send("fb:1", "hello\nworld")
    assert any("hello | world -> fb:1" in r.message for r in caplog.records)
    assert fb.sent == [("1", "hello\nworld")]


@pytest.mark.asyncio
async def test_unregister():
    hub = MessagingHub()
    fb = FakeTransport()
    hub.register("fb", fb, "fb:bot")
    hub.unregister("fb")
    await hub.send("fb:1", "x")
    assert fb.sent == []
    assert hub.live_platforms == set()
