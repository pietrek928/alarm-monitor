import logging
from asyncio import Lock
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from os import replace
from pathlib import Path
from typing import Callable

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
from .status import RuntimeStatus

logger = logging.getLogger("alarm_monitor.dispatch")
logger.setLevel(logging.INFO)

AlarmRunner = Callable[..., object]
_ALARM_REPLY_COMMANDS = (QueryArmedPartitions, AlarmON, AlarmOFF)


@dataclass_json
@dataclass
class AlarmConfig:
    code: str = ""
    partitions: set[int] = field(default_factory=set)
    alert_ids: set[str] = field(default_factory=set)
    authorize_ids: set[str] = field(default_factory=set)


@dataclass
class MonitorContext:
    alarm: AlarmRunner
    alarm_conn: AlarmConnection
    cfg: AlarmConfig
    config_file: str
    secret: str
    hub: MessagingHub
    alarm_lock: Lock
    config_lock: Lock
    dispatch_lock: Lock
    runtime: RuntimeStatus
    registry: object  # PlatformRegistry; avoided import cycle with platforms


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
            move = await ctx.alarm(ctx.alarm_conn.describe_move)
        await ctx.hub.send(cmd.sender_id, move)
        return None

    if isinstance(cmd, QueryStatus):
        await ctx.hub.send(cmd.sender_id, ctx.runtime.format_report(ctx.registry))
        return None

    if isinstance(cmd, QueryArmedPartitions):
        async with _maybe_alarm_lock(ctx, alarm_locked):
            await ctx.alarm(ctx.alarm_conn.query_armed_partitions)
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
            async with _maybe_alarm_lock(ctx, alarm_locked):
                await ctx.alarm(ctx.alarm_conn.send_arm, ctx.cfg.code, partitions)
            return cmd.sender_id
        return None

    if isinstance(cmd, AlarmOFF):
        partitions = list(cmd.partitions or ctx.cfg.partitions)
        if partitions:
            async with _maybe_alarm_lock(ctx, alarm_locked):
                await ctx.alarm(ctx.alarm_conn.send_disarm, ctx.cfg.code, partitions)
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

        resp: set[str] = set()
        async with ctx.alarm_lock:
            for cmd in alarm_cmds:
                reply_to = await handle_user_command(cmd, ctx, alarm_locked=True)
                if reply_to is not None:
                    resp.add(reply_to)
            alarm_messages = (
                await ctx.alarm(ctx.alarm_conn.receive_data) if resp else ()
            )

        for message in alarm_messages:
            await ctx.hub.broadcast(tuple(resp), message)
