from asyncio import Event, Lock, create_task, sleep, wait_for
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from alarm_monitor.dispatch import (
    AlarmConfig,
    ArmChange,
    MonitorContext,
    arm_watch_pending,
    deliver_alarm_messages,
    format_arming_ack,
    handle_user_command,
    load_config,
    matches_arm_intent,
    process_inbound_messages,
)
from alarm_monitor.messaging import InputMessage, MessagingHub, parse_messages
from alarm_monitor.monitor import poll_alarm
from alarm_monitor.platforms import PlatformRegistry, PlatformState
from alarm_monitor.status import RuntimeStatus

UTC = timezone.utc


class StubAlarm:
    def __init__(self):
        self.armed = None
        self.disarmed = None
        self.queries: list[str] = []
        self.inbox = ["Zazbrojone strefy: 1"]
        self.inbox_sequence: list[list[str]] | None = None
        self._recv_i = 0

    def describe_move(self):
        return "brak ruchu"

    def query_armed_partitions(self):
        self.queries.append("armed")

    def send_arm(self, code, partitions):
        self.armed = (code, list(partitions))

    def send_disarm(self, code, partitions):
        self.disarmed = (code, list(partitions))

    def receive_data(self):
        if self.inbox_sequence is not None:
            i = min(self._recv_i, len(self.inbox_sequence) - 1)
            self._recv_i += 1
            return list(self.inbox_sequence[i])
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


def make_ctx(tmp_path, *, secret="sekret", cfg=None, alarm_ready=True):
    hub = RecordingHub()
    alarm = StubAlarm()
    registry = PlatformRegistry({"fb", "discord"})
    registry.set_state("fb", PlatformState.UP)
    runtime = RuntimeStatus(
        alarm_endpoint="192.168.1.1:10967",
        alarm_connected_at=datetime.now(UTC) if alarm_ready else None,
    )
    ready = Event()
    ctx = MonitorContext(
        alarm=alarm_runner,
        alarm_conn=alarm if alarm_ready else None,
        alarm_ready=ready,
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
    if alarm_ready:
        ready.set()
    return ctx, alarm, hub


async def wait_arm_watch(ctx, timeout=2.0):
    task = ctx.arm_watch_task
    if task is not None:
        await wait_for(task, timeout=timeout)


@pytest.mark.asyncio
async def test_auth_subscribe_and_persist(tmp_path):
    ctx, _alarm, hub = make_ctx(tmp_path)
    now = datetime.now(UTC)
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
    now = datetime.now(UTC)
    await process_inbound_messages(
        (InputMessage("1", now, "wlacz alarm 1", "fb:stranger"),),
        ctx,
    )
    assert alarm.armed is None
    assert hub.outbox == []


@pytest.mark.asyncio
async def test_arm_ack_then_armed_confirm(tmp_path):
    ctx, alarm, hub = make_ctx(tmp_path)
    ctx.cfg.authorize_ids.add("fb:user1")
    now = datetime.now(UTC)
    with patch("alarm_monitor.dispatch.ARM_WATCH_INTERVAL_SECONDS", 0.01):
        await process_inbound_messages(
            (InputMessage("1", now, "wlacz alarm 1", "fb:user1"),),
            ctx,
        )
        assert ("fb:user1", "Trwa zazbrajanie stref: 1") in hub.outbox
        await wait_arm_watch(ctx)
    assert alarm.armed == ("1234", [1])
    assert ("fb:user1", "Zazbrojone strefy: 1") in hub.outbox
    assert not any(t == "Brak zazbrojenia" for _, t in hub.outbox)
    assert ctx.last_arm_change is not None
    assert ctx.last_arm_change.arming is True


@pytest.mark.asyncio
async def test_bot_messages_skipped(tmp_path):
    ctx, _alarm, hub = make_ctx(tmp_path)
    cmd = next(
        parse_messages(
            (
                InputMessage(
                    "1",
                    datetime.now(UTC),
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
        now=datetime(2026, 7, 30, 9, 12, 5, tzinfo=UTC),
    )
    now = datetime.now(UTC)
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
    now = datetime.now(UTC)
    await process_inbound_messages(
        (InputMessage("1", now, "status", "fb:stranger"),),
        ctx,
    )
    assert hub.outbox == []


@pytest.mark.asyncio
async def test_status_works_before_alarm_ready(tmp_path):
    ctx, _alarm, hub = make_ctx(tmp_path, alarm_ready=False)
    ctx.cfg.authorize_ids.add("fb:user1")
    now = datetime.now(UTC)
    await process_inbound_messages(
        (InputMessage("1", now, "status", "fb:user1"),),
        ctx,
    )
    assert hub.outbox
    assert "Alarm: brak połączenia" in hub.outbox[-1][1]


@pytest.mark.asyncio
async def test_require_alarm_waits_until_ready(tmp_path):
    ctx, alarm, hub = make_ctx(tmp_path, alarm_ready=False)
    ctx.cfg.authorize_ids.add("fb:user1")
    now = datetime.now(UTC)

    async def release_alarm():
        await sleep(0.05)
        ctx.alarm_conn = alarm
        ctx.runtime.alarm_connected_at = datetime.now(UTC)
        ctx.alarm_ready.set()

    create_task(release_alarm())
    with patch("alarm_monitor.dispatch.ARM_WATCH_INTERVAL_SECONDS", 0.01):
        await wait_for(
            process_inbound_messages(
                (InputMessage("1", now, "wlacz alarm 1", "fb:user1"),),
                ctx,
            ),
            timeout=1.0,
        )
        await wait_arm_watch(ctx)
    assert alarm.armed == ("1234", [1])
    assert any(t.startswith("Trwa zazbrajanie") for _, t in hub.outbox)


def test_matches_arm_intent():
    arm = ArmChange(arming=True, partitions=frozenset({1, 2}))
    assert matches_arm_intent("Zazbrojone strefy: 1 2", arm)
    assert matches_arm_intent("Zazbrojone strefy: 1 2 3", arm)
    assert not matches_arm_intent("Zazbrojone strefy: 1", arm)
    assert not matches_arm_intent("Brak zazbrojenia", arm)

    disarm = ArmChange(arming=False, partitions=frozenset({1}))
    assert matches_arm_intent("Brak zazbrojenia", disarm)
    assert matches_arm_intent("Zazbrojone strefy: 2", disarm)
    assert not matches_arm_intent("Zazbrojone strefy: 1 2", disarm)


def test_format_arming_ack():
    change = ArmChange(arming=True, partitions=frozenset({2, 1}))
    assert format_arming_ack(change) == "Trwa zazbrajanie stref: 1 2"


@pytest.mark.asyncio
async def test_deliver_alert_to_alert_ids_not_only_asker(tmp_path):
    ctx, _alarm, hub = make_ctx(tmp_path)
    ctx.cfg.alert_ids.add("fb:watcher")
    replies = await deliver_alarm_messages(
        ctx,
        ["Alarm w strefie 1", "Zazbrojone strefy: 1"],
        reply_to=("fb:user1",),
    )
    assert replies == ["Zazbrojone strefy: 1"]
    assert ("fb:watcher", "Alarm w strefie 1") in hub.outbox
    assert ("fb:user1", "Alarm w strefie 1") not in hub.outbox
    assert ("fb:user1", "Zazbrojone strefy: 1") in hub.outbox
    assert ctx.runtime.last_alarm_where == "Alarm w strefie 1"


@pytest.mark.asyncio
async def test_poll_drops_command_replies_without_sender(tmp_path):
    ctx, alarm, hub = make_ctx(tmp_path)
    ctx.cfg.alert_ids.add("fb:watcher")
    alarm.inbox = ["Brak zazbrojenia", "Alarm w strefie 2"]
    await poll_alarm(ctx)
    assert ("fb:watcher", "Alarm w strefie 2") in hub.outbox
    assert not any(t == "Brak zazbrojenia" for _, t in hub.outbox)


@pytest.mark.asyncio
async def test_arm_watch_waits_through_brak(tmp_path):
    ctx, alarm, hub = make_ctx(tmp_path)
    ctx.cfg.authorize_ids.add("fb:user1")
    alarm.inbox_sequence = [
        ["Brak zazbrojenia"],
        ["Brak zazbrojenia"],
        ["Zazbrojone strefy: 1"],
    ]
    now = datetime.now(UTC)
    with patch("alarm_monitor.dispatch.ARM_WATCH_INTERVAL_SECONDS", 0.01):
        await process_inbound_messages(
            (InputMessage("1", now, "wlacz alarm 1", "fb:user1"),),
            ctx,
        )
        assert ("fb:user1", "Trwa zazbrajanie stref: 1") in hub.outbox
        await wait_arm_watch(ctx)
    assert alarm.queries.count("armed") >= 3
    armed_replies = [t for _, t in hub.outbox if t.startswith("Zazbrojone")]
    assert armed_replies == ["Zazbrojone strefy: 1"]
    assert not any(t == "Brak zazbrojenia" for _, t in hub.outbox)


@pytest.mark.asyncio
async def test_czy_alarm_joins_pending_arm_watch(tmp_path):
    ctx, alarm, hub = make_ctx(tmp_path)
    ctx.cfg.authorize_ids.add("fb:user1")
    alarm.inbox_sequence = [
        ["Brak zazbrojenia"],
        ["Brak zazbrojenia"],
        ["Zazbrojone strefy: 1"],
    ]
    now = datetime.now(UTC)
    with patch("alarm_monitor.dispatch.ARM_WATCH_INTERVAL_SECONDS", 0.05):
        await process_inbound_messages(
            (InputMessage("1", now, "wlacz alarm 1", "fb:user1"),),
            ctx,
        )
        await process_inbound_messages(
            (InputMessage("2", now, "czy alarm", "fb:user1"),),
            ctx,
        )
        acks = [t for _, t in hub.outbox if t.startswith("Trwa zazbrajanie")]
        assert len(acks) >= 2
        await wait_arm_watch(ctx)
    assert ("fb:user1", "Zazbrojone strefy: 1") in hub.outbox
    assert not any(t == "Brak zazbrojenia" for _, t in hub.outbox)


@pytest.mark.asyncio
async def test_czy_alarm_single_shot_when_not_pending(tmp_path):
    ctx, alarm, hub = make_ctx(tmp_path)
    ctx.cfg.authorize_ids.add("fb:user1")
    ctx.last_arm_change = ArmChange(
        arming=True,
        partitions=frozenset({1}),
        at=datetime.now(UTC) - timedelta(seconds=120),
    )
    assert not arm_watch_pending(ctx)
    alarm.inbox = ["Brak zazbrojenia"]
    now = datetime.now(UTC)
    await process_inbound_messages(
        (InputMessage("1", now, "czy alarm", "fb:user1"),),
        ctx,
    )
    assert alarm.queries == ["armed"]
    assert ("fb:user1", "Brak zazbrojenia") in hub.outbox


@pytest.mark.asyncio
async def test_disarm_sync_settle(tmp_path):
    ctx, alarm, hub = make_ctx(tmp_path)
    ctx.cfg.authorize_ids.add("fb:user1")
    alarm.inbox = ["Brak zazbrojenia"]
    now = datetime.now(UTC)
    with patch("alarm_monitor.dispatch.SETTLE_INTERVAL_SECONDS", 0.01):
        await process_inbound_messages(
            (InputMessage("1", now, "wylacz alarm 1", "fb:user1"),),
            ctx,
        )
    assert alarm.disarmed == ("1234", [1])
    assert ("fb:user1", "Brak zazbrojenia") in hub.outbox
    assert ctx.arm_watch_task is None


@pytest.mark.asyncio
async def test_disarm_during_arm_cancels_watch(tmp_path):
    ctx, alarm, hub = make_ctx(tmp_path)
    ctx.cfg.authorize_ids.add("fb:user1")
    alarm.inbox_sequence = [
        ["Brak zazbrojenia"],
        ["Brak zazbrojenia"],
        ["Brak zazbrojenia"],
        ["Zazbrojone strefy: 1"],
    ]
    now = datetime.now(UTC)
    gen_before = ctx.arm_watch_generation
    with patch("alarm_monitor.dispatch.ARM_WATCH_INTERVAL_SECONDS", 0.05):
        await process_inbound_messages(
            (InputMessage("1", now, "wlacz alarm 1", "fb:user1"),),
            ctx,
        )
        assert ("fb:user1", "Trwa zazbrajanie stref: 1") in hub.outbox
        assert ctx.arm_watch_task is not None
        await sleep(0.08)
        await process_inbound_messages(
            (InputMessage("2", now, "wylacz alarm 1", "fb:user1"),),
            ctx,
        )
    assert alarm.disarmed == ("1234", [1])
    assert ("fb:user1", "Brak zazbrojenia") in hub.outbox
    assert not any(t.startswith("Zazbrojone") for _, t in hub.outbox)
    assert ctx.arm_watch_generation > gen_before
    await sleep(0.15)
    assert not any(t.startswith("Zazbrojone") for _, t in hub.outbox)
    assert ctx.pending_arm_replies == set()


@pytest.mark.asyncio
async def test_same_batch_arm_then_disarm_does_not_restart_watch(tmp_path):
    ctx, alarm, hub = make_ctx(tmp_path)
    ctx.cfg.authorize_ids.add("fb:user1")
    alarm.inbox = ["Brak zazbrojenia"]
    now = datetime.now(UTC)
    with patch("alarm_monitor.dispatch.SETTLE_INTERVAL_SECONDS", 0.01):
        await process_inbound_messages(
            (
                InputMessage("1", now, "wlacz alarm 1", "fb:user1"),
                InputMessage("2", now, "wylacz alarm 1", "fb:user1"),
            ),
            ctx,
        )
    assert alarm.armed == ("1234", [1])
    assert alarm.disarmed == ("1234", [1])
    assert ("fb:user1", "Brak zazbrojenia") in hub.outbox
    assert not any(t.startswith("Trwa zazbrajanie") for _, t in hub.outbox)
    assert ctx.arm_watch_task is None
    assert ctx.pending_arm_replies == set()


@pytest.mark.asyncio
async def test_arm_watch_sends_alert_mid_loop(tmp_path):
    ctx, alarm, hub = make_ctx(tmp_path)
    ctx.cfg.authorize_ids.add("fb:user1")
    ctx.cfg.alert_ids.add("fb:watcher")
    alarm.inbox_sequence = [
        ["Alarm w strefie 9", "Brak zazbrojenia"],
        ["Zazbrojone strefy: 1"],
    ]
    now = datetime.now(UTC)
    with patch("alarm_monitor.dispatch.ARM_WATCH_INTERVAL_SECONDS", 0.01):
        await process_inbound_messages(
            (InputMessage("1", now, "wlacz alarm 1", "fb:user1"),),
            ctx,
        )
        await wait_arm_watch(ctx)
    assert ("fb:watcher", "Alarm w strefie 9") in hub.outbox
    assert ("fb:user1", "Zazbrojone strefy: 1") in hub.outbox
