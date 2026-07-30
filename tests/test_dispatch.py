from asyncio import Lock
from datetime import datetime, timezone

import pytest

from alarm_monitor.dispatch import (
    AlarmConfig,
    MonitorContext,
    handle_user_command,
    load_config,
    process_inbound_messages,
)
from alarm_monitor.messaging import InputMessage, MessagingHub, parse_messages
from alarm_monitor.platforms import PlatformRegistry, PlatformState
from alarm_monitor.status import RuntimeStatus


class StubAlarm:
    def __init__(self):
        self.armed = None
        self.disarmed = None
        self.queries: list[str] = []
        self.inbox = ["STATUS OK"]

    def describe_move(self):
        return "brak ruchu"

    def query_armed_partitions(self):
        self.queries.append("armed")

    def send_arm(self, code, partitions):
        self.armed = (code, list(partitions))

    def send_disarm(self, code, partitions):
        self.disarmed = (code, list(partitions))

    def receive_data(self):
        return list(self.inbox)

    def query_alarm(self):
        return None

    def query_move(self):
        return None


async def alarm_runner(fn, *args):
    return fn(*args)


class RecordingHub(MessagingHub):
    def __init__(self):
        super().__init__()
        self.outbox: list[tuple[str, str]] = []

        async def send_fb(bare, text):
            self.outbox.append((f"fb:{bare}", text))

        self.register("fb", send_fb, "fb:bot")


def make_ctx(tmp_path, *, secret="sekret", cfg=None):
    hub = RecordingHub()
    alarm = StubAlarm()
    registry = PlatformRegistry({"fb", "discord"})
    registry.set_state("fb", PlatformState.UP)
    runtime = RuntimeStatus(
        alarm_endpoint="192.168.1.1:10967",
        alarm_connected_at=datetime.now(timezone.utc),
    )
    ctx = MonitorContext(
        alarm=alarm_runner,
        alarm_conn=alarm,
        cfg=cfg or AlarmConfig(code="1234", partitions={1}),
        config_file=str(tmp_path / "cfg.json"),
        secret=secret,
        hub=hub,
        alarm_lock=Lock(),
        config_lock=Lock(),
        dispatch_lock=Lock(),
        runtime=runtime,
        registry=registry,
    )
    return ctx, alarm, hub


@pytest.mark.asyncio
async def test_auth_subscribe_and_persist(tmp_path):
    ctx, _alarm, hub = make_ctx(tmp_path)
    now = datetime.now(timezone.utc)
    await process_inbound_messages(
        (InputMessage("1", now, "zaloguj sekret", "fb:user1"),),
        ctx,
    )
    assert "fb:user1" in ctx.cfg.authorize_ids
    assert any(t == "Zautoryzowano" for _, t in hub.outbox)

    await process_inbound_messages(
        (InputMessage("2", now, "informuj", "fb:user1"),),
        ctx,
    )
    assert "fb:user1" in ctx.cfg.alert_ids

    loaded = await load_config(ctx.config_file)
    assert "fb:user1" in loaded.authorize_ids
    assert "fb:user1" in loaded.alert_ids


@pytest.mark.asyncio
async def test_unauthorized_alarm_ignored(tmp_path):
    ctx, alarm, hub = make_ctx(tmp_path)
    now = datetime.now(timezone.utc)
    await process_inbound_messages(
        (InputMessage("1", now, "wlacz alarm 1", "fb:stranger"),),
        ctx,
    )
    assert alarm.armed is None
    assert hub.outbox == []


@pytest.mark.asyncio
async def test_arm_and_alarm_reply(tmp_path):
    ctx, alarm, hub = make_ctx(tmp_path)
    ctx.cfg.authorize_ids.add("fb:user1")
    now = datetime.now(timezone.utc)
    await process_inbound_messages(
        (InputMessage("1", now, "wlacz alarm 1", "fb:user1"),),
        ctx,
    )
    assert alarm.armed == ("1234", [1])
    assert ("fb:user1", "STATUS OK") in hub.outbox


@pytest.mark.asyncio
async def test_bot_messages_skipped(tmp_path):
    ctx, _alarm, hub = make_ctx(tmp_path)
    cmd = next(
        parse_messages(
            (
                InputMessage(
                    "1",
                    datetime.now(timezone.utc),
                    "hej",
                    "fb:bot",
                ),
            )
        )
    )
    assert await handle_user_command(cmd, ctx) is None
    assert hub.outbox == []


@pytest.mark.asyncio
async def test_status_authorized(tmp_path):
    ctx, _alarm, hub = make_ctx(tmp_path)
    ctx.cfg.authorize_ids.add("fb:user1")
    ctx.runtime.note_alarm_messages(
        ["Alarm w strefie 3"],
        now=datetime(2026, 7, 30, 9, 12, 5, tzinfo=timezone.utc),
    )
    now = datetime.now(timezone.utc)
    await process_inbound_messages(
        (InputMessage("1", now, "status", "fb:user1"),),
        ctx,
    )
    assert hub.outbox
    report = hub.outbox[-1][1]
    assert "Alarm: OK" in report
    assert "fb: UP" in report
    assert "discord: DOWN" in report
    assert "Ostatni alarm: Alarm w strefie 3" in report


@pytest.mark.asyncio
async def test_status_unauthorized(tmp_path):
    ctx, _alarm, hub = make_ctx(tmp_path)
    now = datetime.now(timezone.utc)
    await process_inbound_messages(
        (InputMessage("1", now, "status", "fb:stranger"),),
        ctx,
    )
    assert hub.outbox == []
