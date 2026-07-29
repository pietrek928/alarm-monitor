import logging
from asyncio import (
    FIRST_EXCEPTION,
    create_task,
    gather,
    get_running_loop,
    run,
    sleep,
    wait,
)
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from functools import partial
from os import environ
from typing import Callable

import aiofiles
from click import ClickException, command, option
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
    SetAlarmCode,
    SetDefaultPartitions,
    Subscribe,
    UserCommand,
    get_help,
    parse_sentence,
    split_sentences,
)
from .facebook_msg import (
    InputMessage,
    get_fb_user_id,
    receive_fb_messages,
    send_fb_message,
)

UTC = timezone.utc
ALARM_POLL_SECONDS = 5
FACEBOOK_POLL_SECONDS = 60
MESSAGE_VALID_SECONDS = 120
ERROR_LIMIT = 3
ERROR_WINDOW = timedelta(minutes=1)

logger = logging.getLogger("alarm_monitor")
logger.setLevel(logging.INFO)

# alarm(fn, *args) -> awaitable from run_in_executor
AlarmRunner = Callable[..., object]


class ErrorWindow:
    """Sliding window: returns True from record() when errors exceed the limit."""

    def __init__(
        self, limit: int = ERROR_LIMIT, window: timedelta = ERROR_WINDOW
    ):
        self.limit = limit
        self.window = window
        self._times: list[datetime] = []

    def record(self) -> bool:
        now = datetime.now(UTC)
        cutoff = now - self.window
        self._times = [t for t in self._times if t > cutoff]
        self._times.append(now)
        return len(self._times) > self.limit


@dataclass_json
@dataclass
class AlarmConfig:
    code: str = ""
    partitions: set[int] = field(default_factory=set)
    alert_fb_ids: set[str] = field(default_factory=set)
    authorize_fb_ids: set[str] = field(default_factory=set)


class MessageFilter:
    def __init__(self):
        self.processed: dict[str, InputMessage] = {}

    def filter(self, messages: tuple[InputMessage, ...], valid_seconds: int):
        if not messages:
            return ()

        messages = sorted(messages, key=lambda x: x.timestamp)

        current_timestamp = datetime.now(UTC)
        if current_timestamp < messages[-1].timestamp:
            logger.warning(
                "Current time is backward by %s",
                messages[-1].timestamp - current_timestamp,
            )
            current_timestamp = messages[-1].timestamp

        valid_since = current_timestamp - timedelta(seconds=valid_seconds)
        r = []
        for m in messages:
            if m.timestamp < valid_since:
                continue
            if m.id in self.processed:
                continue
            self.processed[m.id] = m
            logger.info("Processing message from %s: %s", m.sender_id, m.content)
            r.append(m)
        return tuple(r)

    def clear_processed(self, valid_seconds: int = MESSAGE_VALID_SECONDS):
        if self.processed:
            last_timestamp = max(
                self.processed.values(), key=lambda x: x.timestamp
            ).timestamp
            valid_since = last_timestamp - timedelta(seconds=valid_seconds)
            self.processed = {
                mid: m for mid, m in self.processed.items() if m.timestamp > valid_since
            }


def parse_messages(messages: tuple[InputMessage, ...]):
    for m in messages:
        for s in split_sentences(m.content):
            for cmd in parse_sentence(s):
                cmd.sender_id = m.sender_id
                cmd.timestamp = m.timestamp
                yield cmd


async def save_config(config_file: str, cfg: AlarmConfig):
    logger.info("Saving config")
    async with aiofiles.open(config_file, "w") as f:
        await f.write(cfg.to_json())


async def load_config(config_file: str) -> AlarmConfig:
    cfg = AlarmConfig()
    try:
        async with aiofiles.open(config_file, "r") as f:
            cfg = AlarmConfig.from_json(await f.read())
        cfg.partitions = set(cfg.partitions)
        cfg.alert_fb_ids = set(cfg.alert_fb_ids)
        cfg.authorize_fb_ids = set(cfg.authorize_fb_ids)
    except FileNotFoundError:
        logger.info("Config file %s not found; using defaults", config_file)
    except Exception:
        logger.exception("Failed to load config from %s; using defaults", config_file)
    return cfg


async def notify_fb(
    recipients: tuple[str, ...], message: str, facebook_token: str
) -> None:
    for recipient_id in recipients:
        await send_fb_message(recipient_id, message, facebook_token)


async def poll_alarm(
    alarm: AlarmRunner,
    alarm_conn: AlarmConnection,
    cfg: AlarmConfig,
    facebook_token: str,
) -> None:
    await alarm(alarm_conn.query_alarm)
    await alarm(alarm_conn.query_move)
    alarm_messages = await alarm(alarm_conn.receive_data)
    recipients = tuple(cfg.alert_fb_ids)
    for message in alarm_messages:
        await notify_fb(recipients, message, facebook_token)


async def handle_user_command(
    cmd: UserCommand,
    alarm: AlarmRunner,
    alarm_conn: AlarmConnection,
    cfg: AlarmConfig,
    config_file: str,
    secret: str,
    facebook_token: str,
    fb_user_id: str,
) -> str | None:
    """Dispatch one command. Return sender_id if an alarm reply is expected."""
    if cmd.sender_id == fb_user_id:
        return None

    if isinstance(cmd, Hello):
        await send_fb_message(
            cmd.sender_id,
            "Cześć! Tu rezydencja Malużyn",
            facebook_token,
        )
        return None

    if isinstance(cmd, Help):
        await send_fb_message(
            cmd.sender_id,
            get_help(cmd.sender_id in cfg.authorize_fb_ids),
            facebook_token,
        )
        return None

    if isinstance(cmd, AuthME):
        if cmd.password == secret:
            cfg.authorize_fb_ids.add(cmd.sender_id)
            await save_config(config_file, cfg)
            await send_fb_message(cmd.sender_id, "Zautoryzowano", facebook_token)
        return None

    if cmd.sender_id not in cfg.authorize_fb_ids:
        logger.info("Command from %s not authorized: %s", cmd.sender_id, cmd)
        return None

    if isinstance(cmd, Subscribe):
        if cmd.subscribe:
            cfg.alert_fb_ids.add(cmd.sender_id)
            await save_config(config_file, cfg)
            await send_fb_message(
                cmd.sender_id, "Powiadomienia włączone", facebook_token
            )
        else:
            cfg.alert_fb_ids.discard(cmd.sender_id)
            await save_config(config_file, cfg)
            await send_fb_message(
                cmd.sender_id, "Powiadomienia wyłączone", facebook_token
            )
        return None

    if isinstance(cmd, QueryMove):
        move = await alarm(alarm_conn.describe_move)
        await send_fb_message(cmd.sender_id, move, facebook_token)
        return None

    if isinstance(cmd, QueryArmedPartitions):
        await alarm(alarm_conn.query_armed_partitions)
        return cmd.sender_id

    if isinstance(cmd, SetAlarmCode):
        cfg.code = cmd.code
        await save_config(config_file, cfg)
        return None

    if isinstance(cmd, SetDefaultPartitions):
        cfg.partitions = set(cmd.zones)
        await save_config(config_file, cfg)
        return None

    if isinstance(cmd, AlarmON):
        partitions = list(cmd.partitions or cfg.partitions)
        if partitions:
            await alarm(alarm_conn.send_arm, cfg.code, partitions)
            return cmd.sender_id
        return None

    if isinstance(cmd, AlarmOFF):
        partitions = list(cmd.partitions or cfg.partitions)
        if partitions:
            await alarm(alarm_conn.send_disarm, cfg.code, partitions)
            return cmd.sender_id
        return None

    return None


async def poll_facebook(
    alarm: AlarmRunner,
    alarm_conn: AlarmConnection,
    cfg: AlarmConfig,
    config_file: str,
    secret: str,
    facebook_token: str,
    fb_user_id: str,
    message_filter: MessageFilter,
) -> None:
    input_messages = await receive_fb_messages(facebook_token)
    input_messages = message_filter.filter(input_messages, MESSAGE_VALID_SECONDS)
    message_filter.clear_processed()

    resp: set[str] = set()
    for cmd in tuple(parse_messages(input_messages)):
        reply_to = await handle_user_command(
            cmd,
            alarm,
            alarm_conn,
            cfg,
            config_file,
            secret,
            facebook_token,
            fb_user_id,
        )
        if reply_to is not None:
            resp.add(reply_to)

    if resp:
        recipients = tuple(resp)
        alarm_messages = await alarm(alarm_conn.receive_data)
        for message in alarm_messages:
            await notify_fb(recipients, message, facebook_token)


async def alarm_poll_loop(
    alarm: AlarmRunner,
    alarm_conn: AlarmConnection,
    cfg: AlarmConfig,
    facebook_token: str,
) -> None:
    errors = ErrorWindow()
    while True:
        try:
            await poll_alarm(alarm, alarm_conn, cfg, facebook_token)
        except Exception:
            logger.exception("alarm poll iteration failed")
            if errors.record():
                raise
        await sleep(ALARM_POLL_SECONDS)


async def facebook_poll_loop(
    alarm: AlarmRunner,
    alarm_conn: AlarmConnection,
    cfg: AlarmConfig,
    config_file: str,
    secret: str,
    facebook_token: str,
    fb_user_id: str,
    message_filter: MessageFilter,
) -> None:
    errors = ErrorWindow()
    while True:
        try:
            await poll_facebook(
                alarm,
                alarm_conn,
                cfg,
                config_file,
                secret,
                facebook_token,
                fb_user_id,
                message_filter,
            )
        except Exception:
            logger.exception("facebook poll iteration failed")
            if errors.record():
                raise
        await sleep(FACEBOOK_POLL_SECONDS)


async def monitor_alarm_async(
    ip: str,
    port: int,
    facebook_token: str,
    config_file: str,
    secret: str,
):
    cfg = await load_config(config_file)
    message_filter = MessageFilter()
    loop = get_running_loop()

    with ThreadPoolExecutor(max_workers=1) as pool:
        alarm = partial(loop.run_in_executor, pool)
        alarm_conn = None
        try:
            fb_user_id = await get_fb_user_id(facebook_token)
            if not fb_user_id:
                raise RuntimeError("Could not get fb user id")
            logger.info("FB user id: %s", fb_user_id)

            alarm_conn = await alarm(AlarmConnection, ip, port)
            logger.info("Connected to alarm at %s:%s", ip, port)

            tasks = (
                create_task(
                    alarm_poll_loop(alarm, alarm_conn, cfg, facebook_token),
                    name="alarm_poll",
                ),
                create_task(
                    facebook_poll_loop(
                        alarm,
                        alarm_conn,
                        cfg,
                        config_file,
                        secret,
                        facebook_token,
                        fb_user_id,
                        message_filter,
                    ),
                    name="facebook_poll",
                ),
            )
            done, pending = await wait(tasks, return_when=FIRST_EXCEPTION)
            for t in pending:
                t.cancel()
            if pending:
                await gather(*pending, return_exceptions=True)
            for t in done:
                exc = t.exception()
                if exc is not None:
                    raise exc
        finally:
            if alarm_conn is not None:
                try:
                    await alarm(alarm_conn.disconnect)
                except Exception:
                    logger.exception("Failed to disconnect alarm")
            await save_config(config_file, cfg)


@command()
@option("--alarm_ip", required=True, help="IP address of alarm")
@option("--alarm_port", default=10967, help="Port of alarm")
@option("--config_file", required=True, help="Path to config file")
def monitor_alarm(alarm_ip, alarm_port, config_file):
    logging.basicConfig()
    facebook_token = environ.get("FACEBOOK_TOKEN")
    secret = environ.get("SECRET")
    if not facebook_token:
        raise ClickException("FACEBOOK_TOKEN environment variable is not set")
    if not secret:
        raise ClickException("SECRET environment variable is not set")
    run(
        monitor_alarm_async(
            alarm_ip,
            alarm_port,
            facebook_token,
            config_file=config_file,
            secret=secret,
        )
    )
