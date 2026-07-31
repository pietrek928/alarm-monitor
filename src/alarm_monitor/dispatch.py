import logging
import re
from asyncio import Event, Lock, Task, create_task, sleep
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from os import replace
from pathlib import Path
from typing import Callable, Iterable

import aiofiles
from dataclasses_json import dataclass_json

from .alarm import AlarmConnection
from .commands import (
    AlarmOFF,
    AlarmON,
    AuthME,
    Hello,
    Help,
    QueryArmedPartitions,
    QueryMove,
    QueryStatus,
    SetAlarmCode,
    SetDefaultPartitions,
    Subscribe,
    UserCommand,
    get_help,
)
from .messaging import (
    MESSAGE_VALID_SECONDS,
    InputMessage,
    MessageFilter,
    MessagingHub,
    parse_messages,
)
from .status import ALERT_PREFIXES, RuntimeStatus

logger = logging.getLogger("alarm_monitor.dispatch")
logger.setLevel(logging.INFO)

UTC = timezone.utc
AlarmRunner = Callable[..., object]
_ALARM_REPLY_COMMANDS = (QueryArmedPartitions, AlarmON, AlarmOFF)

SETTLE_INTERVAL_SECONDS = 0.5
SETTLE_DEADLINE_SECONDS = 4.0
ARM_WATCH_DEADLINE_SECONDS = 45.0
ARM_WATCH_INTERVAL_SECONDS = 1.0

ARMED_PREFIX = "Zazbrojone strefy:"
DISARMED_TEXT = "Brak zazbrojenia"
ARM_FAILURE_PREFIX = "zazbrojenie niemożliwe"
_ZONE_RE = re.compile(r"\d+")


@dataclass_json
@dataclass
class AlarmConfig:
    code: str = ""
    partitions: set[int] = field(default_factory=set)
    alert_ids: set[str] = field(default_factory=set)
    authorize_ids: set[str] = field(default_factory=set)


@dataclass
class ArmChange:
    arming: bool
    partitions: frozenset[int]
    at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class MonitorContext:
    alarm: AlarmRunner
    cfg: AlarmConfig
    config_file: str
    secret: str
    hub: MessagingHub
    alarm_lock: Lock
    config_lock: Lock
    dispatch_lock: Lock
    runtime: RuntimeStatus
    registry: object  # PlatformRegistry; avoided import cycle with platforms
    alarm_conn: AlarmConnection | None = None
    alarm_ready: Event = field(default_factory=Event)
    last_arm_change: ArmChange | None = None
    pending_arm_replies: set[str] = field(default_factory=set)
    arm_watch_task: Task | None = None
    arm_watch_generation: int = 0

    async def require_alarm(self) -> AlarmConnection:
        await self.alarm_ready.wait()
        if self.alarm_conn is None:
            raise RuntimeError("Alarm marked ready but connection is missing")
        return self.alarm_conn


def is_alert_message(message: str) -> bool:
    return message.startswith(ALERT_PREFIXES)


def parse_armed_zones(message: str) -> set[int] | None:
    if message == DISARMED_TEXT:
        return set()
    if not message.startswith(ARMED_PREFIX):
        return None
    return {int(n) for n in _ZONE_RE.findall(message[len(ARMED_PREFIX) :])}


def is_arm_failure(message: str) -> bool:
    return message.startswith(ARM_FAILURE_PREFIX)


def matches_arm_intent(message: str, change: ArmChange) -> bool:
    zones = parse_armed_zones(message)
    if zones is None:
        return False
    if change.arming:
        return change.partitions <= zones
    return change.partitions.isdisjoint(zones)


def format_arming_ack(change: ArmChange) -> str:
    zones = " ".join(str(p) for p in sorted(change.partitions))
    return f"Trwa zazbrajanie stref: {zones}"


def arm_watch_pending(ctx: MonitorContext) -> bool:
    if ctx.pending_arm_replies:
        return True
    task = ctx.arm_watch_task
    return task is not None and not task.done()


def cancel_arm_watch(ctx: MonitorContext) -> set[str]:
    """Cancel in-flight arm watch. Returns pending recipients that were waiting."""
    pending = set(ctx.pending_arm_replies)
    ctx.arm_watch_generation += 1
    task = ctx.arm_watch_task
    ctx.arm_watch_task = None
    if task is not None and not task.done():
        task.cancel()
    ctx.pending_arm_replies.clear()
    return pending


def ensure_arm_watch_started(ctx: MonitorContext) -> None:
    task = ctx.arm_watch_task
    if task is not None and not task.done():
        return
    ctx.arm_watch_generation += 1
    gen = ctx.arm_watch_generation
    ctx.arm_watch_task = create_task(
        watch_arm_settle(ctx, gen), name="arm_watch"
    )


async def deliver_alarm_messages(
    ctx: MonitorContext,
    messages: Iterable[str],
    *,
    reply_to: Iterable[str] = (),
) -> list[str]:
    """Route panel strings: alerts → alert_ids; other → reply_to or drop."""
    reply_recipients = tuple(reply_to)
    alerts: list[str] = []
    replies: list[str] = []
    for message in messages:
        if is_alert_message(message):
            alerts.append(message)
        else:
            replies.append(message)

    if alerts:
        ctx.runtime.note_alarm_messages(alerts)
        async with ctx.config_lock:
            alert_ids = tuple(ctx.cfg.alert_ids)
        for message in alerts:
            await ctx.hub.broadcast(alert_ids, message)

    if replies:
        if reply_recipients:
            for message in replies:
                await ctx.hub.broadcast(reply_recipients, message)
        else:
            for message in replies:
                logger.info("Dropping panel reply with no command sender: %s", message)

    return replies


async def _receive_panel_messages(
    ctx: MonitorContext, alarm_conn: AlarmConnection
) -> tuple[str, ...]:
    try:
        messages = await ctx.alarm(alarm_conn.receive_data)
    except Exception:
        logger.exception("Alarm receive_data failed")
        return ()
    return tuple(messages or ())


async def _poll_armed_once(
    ctx: MonitorContext, alarm_conn: AlarmConnection
) -> tuple[str, ...]:
    """Query armed partitions, deliver any alerts, return non-alert replies."""
    await ctx.alarm(alarm_conn.query_armed_partitions)
    messages = await _receive_panel_messages(ctx, alarm_conn)
    alerts = [m for m in messages if is_alert_message(m)]
    replies = tuple(m for m in messages if not is_alert_message(m))
    if alerts:
        await deliver_alarm_messages(ctx, alerts, reply_to=())
    return replies


async def wait_for_armed_state(
    ctx: MonitorContext,
    *,
    intent: ArmChange,
    deadline_s: float,
    interval_s: float,
    manage_lock: bool,
    alarm_conn: AlarmConnection | None = None,
    still_active: Callable[[], bool] | None = None,
) -> str | None:
    """Poll until intent matches, arm failure, or deadline. Returns last/done text."""
    deadline = datetime.now(UTC) + timedelta(seconds=deadline_s)
    last_reply: str | None = None

    while True:
        if still_active is not None and not still_active():
            return None

        if manage_lock:
            async with ctx.alarm_lock:
                conn = await ctx.require_alarm()
                replies = await _poll_armed_once(ctx, conn)
        else:
            assert alarm_conn is not None
            replies = await _poll_armed_once(ctx, alarm_conn)

        for message in replies:
            last_reply = message
            if matches_arm_intent(message, intent) or is_arm_failure(message):
                return message

        if datetime.now(UTC) >= deadline:
            return last_reply

        await sleep(interval_s)


async def settle_armed_state(
    ctx: MonitorContext,
    alarm_conn: AlarmConnection,
    reply_to: Iterable[str],
    *,
    intent: ArmChange,
) -> str | None:
    """Sync settle (caller holds alarm_lock). Broadcasts result to reply_to."""
    reply_recipients = tuple(reply_to)
    result = await wait_for_armed_state(
        ctx,
        intent=intent,
        deadline_s=SETTLE_DEADLINE_SECONDS,
        interval_s=SETTLE_INTERVAL_SECONDS,
        manage_lock=False,
        alarm_conn=alarm_conn,
    )
    if result is not None and reply_recipients:
        await ctx.hub.broadcast(reply_recipients, result)
    return result


async def watch_arm_settle(ctx: MonitorContext, generation: int) -> None:
    """Background wait until panel shows armed (exit delay), then notify."""
    try:
        intent = ctx.last_arm_change
        if intent is None or not intent.arming:
            return
        if ctx.arm_watch_generation != generation:
            return

        result = await wait_for_armed_state(
            ctx,
            intent=intent,
            deadline_s=ARM_WATCH_DEADLINE_SECONDS,
            interval_s=ARM_WATCH_INTERVAL_SECONDS,
            manage_lock=True,
            still_active=lambda: ctx.arm_watch_generation == generation,
        )

        if ctx.arm_watch_generation != generation:
            return

        recipients = tuple(ctx.pending_arm_replies)
        ctx.pending_arm_replies.clear()
        if not recipients:
            return

        if result is not None and (
            matches_arm_intent(result, intent) or is_arm_failure(result)
        ):
            await ctx.hub.broadcast(recipients, result)
        else:
            text = result or DISARMED_TEXT
            await ctx.hub.broadcast(recipients, f"Timeout zazbrajania: {text}")
    except Exception:
        logger.exception("Arm watch failed")
        if ctx.arm_watch_generation == generation:
            ctx.pending_arm_replies.clear()
    finally:
        if (
            ctx.arm_watch_generation == generation
            and ctx.arm_watch_task is not None
            and ctx.arm_watch_task.done()
        ):
            ctx.arm_watch_task = None


async def save_config(config_file: str, cfg: AlarmConfig) -> None:
    logger.info("Saving config")
    path = Path(config_file)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    async with aiofiles.open(tmp_path, "w") as f:
        await f.write(cfg.to_json())
    replace(tmp_path, path)


async def load_config(config_file: str) -> AlarmConfig:
    cfg = AlarmConfig()
    try:
        async with aiofiles.open(config_file, "r") as f:
            cfg = AlarmConfig.from_json(await f.read())
        cfg.partitions = set(cfg.partitions)
        cfg.alert_ids = set(cfg.alert_ids)
        cfg.authorize_ids = set(cfg.authorize_ids)
    except FileNotFoundError:
        logger.info("Config file %s not found; using defaults", config_file)
    except Exception:
        logger.exception("Failed to load config from %s; using defaults", config_file)
    return cfg


async def _mutate_config(ctx: MonitorContext, mutator) -> None:
    async with ctx.config_lock:
        mutator(ctx.cfg)
        await save_config(ctx.config_file, cfg=ctx.cfg)


@asynccontextmanager
async def _maybe_alarm_lock(ctx: MonitorContext, already_locked: bool):
    if already_locked:
        yield
    else:
        async with ctx.alarm_lock:
            yield


async def _send_arm_or_disarm(
    ctx: MonitorContext,
    *,
    arming: bool,
    partitions: list[int],
    alarm_locked: bool,
) -> None:
    async with _maybe_alarm_lock(ctx, alarm_locked):
        alarm_conn = await ctx.require_alarm()
        if arming:
            await ctx.alarm(alarm_conn.send_arm, ctx.cfg.code, partitions)
        else:
            await ctx.alarm(alarm_conn.send_disarm, ctx.cfg.code, partitions)
    ctx.last_arm_change = ArmChange(
        arming=arming, partitions=frozenset(partitions)
    )


async def handle_user_command(
    cmd: UserCommand,
    ctx: MonitorContext,
    *,
    alarm_locked: bool = False,
) -> str | None:
    """Dispatch one command. Return sender_id if an alarm reply is expected."""
    if cmd.sender_id in ctx.hub.bot_ids:
        return None

    if isinstance(cmd, Hello):
        await ctx.hub.send(cmd.sender_id, "Cześć! Tu rezydencja Malużyn")
        return None

    if isinstance(cmd, Help):
        authorized = cmd.sender_id in ctx.cfg.authorize_ids
        await ctx.hub.send(cmd.sender_id, get_help(authorized))
        return None

    if isinstance(cmd, AuthME):
        if cmd.password == ctx.secret:

            def add_auth(cfg: AlarmConfig) -> None:
                cfg.authorize_ids.add(cmd.sender_id)

            await _mutate_config(ctx, add_auth)
            await ctx.hub.send(cmd.sender_id, "Zautoryzowano")
        return None

    if cmd.sender_id not in ctx.cfg.authorize_ids:
        logger.info("Command from %s not authorized: %s", cmd.sender_id, cmd)
        return None

    if isinstance(cmd, Subscribe):
        if cmd.subscribe:

            def subscribe(cfg: AlarmConfig) -> None:
                cfg.alert_ids.add(cmd.sender_id)

            await _mutate_config(ctx, subscribe)
            await ctx.hub.send(cmd.sender_id, "Powiadomienia włączone")
        else:

            def unsubscribe(cfg: AlarmConfig) -> None:
                cfg.alert_ids.discard(cmd.sender_id)

            await _mutate_config(ctx, unsubscribe)
            await ctx.hub.send(cmd.sender_id, "Powiadomienia wyłączone")
        return None

    if isinstance(cmd, QueryMove):
        async with _maybe_alarm_lock(ctx, alarm_locked):
            alarm_conn = await ctx.require_alarm()
            move = await ctx.alarm(alarm_conn.describe_move)
        await ctx.hub.send(cmd.sender_id, move)
        return None

    if isinstance(cmd, QueryStatus):
        await ctx.hub.send(cmd.sender_id, ctx.runtime.format_report(ctx.registry))
        return None

    if isinstance(cmd, QueryArmedPartitions):
        return cmd.sender_id

    if isinstance(cmd, SetAlarmCode):

        def set_code(cfg: AlarmConfig) -> None:
            cfg.code = cmd.code

        await _mutate_config(ctx, set_code)
        return None

    if isinstance(cmd, SetDefaultPartitions):

        def set_partitions(cfg: AlarmConfig) -> None:
            cfg.partitions = set(cmd.zones)

        await _mutate_config(ctx, set_partitions)
        return None

    if isinstance(cmd, AlarmON):
        partitions = list(cmd.partitions or ctx.cfg.partitions)
        if partitions:
            await _send_arm_or_disarm(
                ctx, arming=True, partitions=partitions, alarm_locked=alarm_locked
            )
            return cmd.sender_id
        return None

    if isinstance(cmd, AlarmOFF):
        partitions = list(cmd.partitions or ctx.cfg.partitions)
        if partitions:
            await _send_arm_or_disarm(
                ctx, arming=False, partitions=partitions, alarm_locked=alarm_locked
            )
            return cmd.sender_id
        return None

    return None


async def process_inbound_messages(
    messages: tuple[InputMessage, ...],
    ctx: MonitorContext,
    message_filter: MessageFilter | None = None,
) -> None:
    """Filter (optional), parse, handle commands, deliver any alarm replies."""
    async with ctx.dispatch_lock:
        if message_filter is not None:
            messages = message_filter.filter(messages, MESSAGE_VALID_SECONDS)
            message_filter.clear_processed()

        commands = tuple(parse_messages(messages))
        early: list[UserCommand] = []
        alarm_cmds: list[UserCommand] = []
        for cmd in commands:
            if isinstance(cmd, _ALARM_REPLY_COMMANDS):
                alarm_cmds.append(cmd)
            else:
                early.append(cmd)

        for cmd in early:
            await handle_user_command(cmd, ctx)

        if not alarm_cmds:
            return

        disarm_resp: set[str] = set()
        query_resp: set[str] = set()
        arm_ack_recipients: set[str] = set()
        had_arm_on = False
        had_arm_off = False

        async with ctx.alarm_lock:
            alarm_conn = await ctx.require_alarm()
            for cmd in alarm_cmds:
                reply_to = await handle_user_command(cmd, ctx, alarm_locked=True)
                if reply_to is None:
                    continue

                if isinstance(cmd, AlarmON):
                    had_arm_on = True
                    ctx.pending_arm_replies.add(reply_to)
                    arm_ack_recipients.add(reply_to)
                elif isinstance(cmd, AlarmOFF):
                    had_arm_off = True
                    disarm_resp.add(reply_to)
                elif isinstance(cmd, QueryArmedPartitions):
                    if arm_watch_pending(ctx) or had_arm_on:
                        ctx.pending_arm_replies.add(reply_to)
                        arm_ack_recipients.add(reply_to)
                    else:
                        query_resp.add(reply_to)

            if had_arm_off:
                pending_arm = cancel_arm_watch(ctx)
                intent = ctx.last_arm_change
                assert intent is not None and not intent.arming
                settle_recipients = set(disarm_resp) | pending_arm
                await settle_armed_state(
                    ctx, alarm_conn, settle_recipients, intent=intent
                )

            if query_resp and not had_arm_off:
                await ctx.alarm(alarm_conn.query_armed_partitions)
                panel_messages = await _receive_panel_messages(ctx, alarm_conn)
                await deliver_alarm_messages(ctx, panel_messages, reply_to=query_resp)

        if (
            not had_arm_off
            and arm_ack_recipients
            and ctx.last_arm_change is not None
            and ctx.last_arm_change.arming
        ):
            ack = format_arming_ack(ctx.last_arm_change)
            for recipient in arm_ack_recipients:
                await ctx.hub.send(recipient, ack)

        if not had_arm_off and (had_arm_on or ctx.pending_arm_replies):
            ensure_arm_watch_started(ctx)
