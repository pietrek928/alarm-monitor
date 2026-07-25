import logging
from functools import partial
from os import environ
from asyncio import CancelledError, get_running_loop, run, sleep
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import aiofiles
from click import ClickException, command, option
from dataclasses_json import dataclass_json

from .commands import (
    AlarmOFF, AlarmON, AuthME, Hello, Help, QueryArmedPartitions, QueryMove,
    SetAlarmCode, SetDefaultPartitions, Subscribe, get_help, parse_sentence,
    split_sentences,
)
from .facebook_msg import InputMessage, get_fb_user_id, receive_fb_messages, send_fb_message
from .alarm import AlarmConnection


UTC = timezone.utc
SLEEP_SECONDS = 5
FB_POLL_EVERY = 12
MESSAGE_VALID_SECONDS = 120

logger = logging.getLogger('alarm_monitor')
logger.setLevel(logging.INFO)


@dataclass_json
@dataclass
class AlarmConfig:
    code: str = ''
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
                'Current time is backward by %s',
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
            logger.info('Processing message from %s: %s', m.sender_id, m.content)
            r.append(m)
        return tuple(r)

    def clear_processed(self, valid_seconds: int = MESSAGE_VALID_SECONDS):
        if self.processed:
            last_timestamp = max(
                self.processed.values(), key=lambda x: x.timestamp
            ).timestamp
            valid_since = last_timestamp - timedelta(seconds=valid_seconds)
            self.processed = {
                mid: m for mid, m in self.processed.items()
                if m.timestamp > valid_since
            }


def parse_messages(messages: tuple[InputMessage, ...]):
    for m in messages:
        for s in split_sentences(m.content):
            for cmd in parse_sentence(s):
                cmd.sender_id = m.sender_id
                cmd.timestamp = m.timestamp
                yield cmd


async def save_config(config_file: str, cfg: AlarmConfig):
    logger.info('Saving config')
    async with aiofiles.open(config_file, 'w') as f:
        await f.write(cfg.to_json())


async def load_config(config_file: str) -> AlarmConfig:
    cfg = AlarmConfig()
    try:
        async with aiofiles.open(config_file, 'r') as f:
            cfg = AlarmConfig.from_json(await f.read())
        cfg.partitions = set(cfg.partitions)
        cfg.alert_fb_ids = set(cfg.alert_fb_ids)
        cfg.authorize_fb_ids = set(cfg.authorize_fb_ids)
    except FileNotFoundError:
        logger.info('Config file %s not found; using defaults', config_file)
    except Exception:
        logger.exception('Failed to load config from %s; using defaults', config_file)
    return cfg


async def monitor_alarm_async(
    ip: str, port: int, facebook_token: str,
    config_file: str, secret: str,
):
    cfg = await load_config(config_file)
    message_filter = MessageFilter()
    loop = get_running_loop()

    with ThreadPoolExecutor() as pool:
        alarm = partial(loop.run_in_executor, pool)
        alarm_conn = None
        try:
            fb_user_id = await get_fb_user_id(facebook_token)
            if not fb_user_id:
                raise RuntimeError('Could not get fb user id')
            logger.info('FB user id: %s', fb_user_id)

            alarm_conn = await alarm(AlarmConnection, ip, port)
            logger.info('Connected to alarm at %s:%s', ip, port)

            recv_it = 0
            while True:
                try:
                    await alarm(alarm_conn.query_alarm)
                    await alarm(alarm_conn.query_move)
                    alarm_messages = await alarm(alarm_conn.receive_data)
                    if alarm_messages:
                        for message in alarm_messages:
                            for alert_id in cfg.alert_fb_ids:
                                await send_fb_message(
                                    alert_id, message, facebook_token
                                )

                    if recv_it <= 0:
                        input_messages = await receive_fb_messages(facebook_token)
                        input_messages = message_filter.filter(
                            input_messages, MESSAGE_VALID_SECONDS
                        )
                        message_filter.clear_processed()

                        resp = set()
                        for cmd in tuple(parse_messages(input_messages)):
                            if cmd.sender_id == fb_user_id:
                                continue

                            if isinstance(cmd, Hello):
                                await send_fb_message(
                                    cmd.sender_id,
                                    'Cześć! Tu rezydencja Malużyn',
                                    facebook_token,
                                )
                                continue
                            if isinstance(cmd, Help):
                                await send_fb_message(
                                    cmd.sender_id,
                                    get_help(cmd.sender_id in cfg.authorize_fb_ids),
                                    facebook_token,
                                )
                                continue
                            if isinstance(cmd, AuthME):
                                if cmd.password == secret:
                                    cfg.authorize_fb_ids.add(cmd.sender_id)
                                    await save_config(config_file, cfg)
                                    await send_fb_message(
                                        cmd.sender_id,
                                        'Zautoryzowano',
                                        facebook_token,
                                    )
                                continue

                            if cmd.sender_id not in cfg.authorize_fb_ids:
                                logger.info(
                                    'Command from %s not authorized: %s',
                                    cmd.sender_id, cmd,
                                )
                                continue

                            if isinstance(cmd, Subscribe):
                                if cmd.subscribe:
                                    cfg.alert_fb_ids.add(cmd.sender_id)
                                    await save_config(config_file, cfg)
                                    await send_fb_message(
                                        cmd.sender_id,
                                        'Powiadomienia włączone',
                                        facebook_token,
                                    )
                                else:
                                    cfg.alert_fb_ids.discard(cmd.sender_id)
                                    await save_config(config_file, cfg)
                                    await send_fb_message(
                                        cmd.sender_id,
                                        'Powiadomienia wyłączone',
                                        facebook_token,
                                    )
                            elif isinstance(cmd, QueryMove):
                                move = await alarm(alarm_conn.describe_move)
                                await send_fb_message(
                                    cmd.sender_id, move, facebook_token
                                )
                            elif isinstance(cmd, QueryArmedPartitions):
                                await alarm(alarm_conn.query_armed_partitions)
                                resp.add(cmd.sender_id)
                            elif isinstance(cmd, SetAlarmCode):
                                cfg.code = cmd.code
                                await save_config(config_file, cfg)
                            elif isinstance(cmd, SetDefaultPartitions):
                                cfg.partitions = set(cmd.zones)
                                await save_config(config_file, cfg)
                            elif isinstance(cmd, AlarmON):
                                partitions = list(cmd.partitions or cfg.partitions)
                                if partitions:
                                    await alarm(
                                        alarm_conn.send_arm, cfg.code, partitions
                                    )
                                    resp.add(cmd.sender_id)
                            elif isinstance(cmd, AlarmOFF):
                                partitions = list(cmd.partitions or cfg.partitions)
                                if partitions:
                                    await alarm(
                                        alarm_conn.send_disarm, cfg.code, partitions
                                    )
                                    resp.add(cmd.sender_id)

                        if resp:
                            alarm_messages = await alarm(alarm_conn.receive_data)
                            for message in alarm_messages:
                                for alert_id in resp:
                                    await send_fb_message(
                                        alert_id, message, facebook_token
                                    )

                        recv_it = FB_POLL_EVERY
                    else:
                        recv_it -= 1
                except (CancelledError, KeyboardInterrupt):
                    raise
                except Exception:
                    logger.exception('monitor loop iteration failed')

                await sleep(SLEEP_SECONDS)
        finally:
            if alarm_conn is not None:
                try:
                    await alarm(alarm_conn.disconnect)
                except Exception:
                    logger.exception('Failed to disconnect alarm')
            await save_config(config_file, cfg)


@command()
@option('--alarm_ip', required=True, help='IP address of alarm')
@option('--alarm_port', default=10967, help='Port of alarm')
@option('--config_file', required=True, help='Path to config file')
def monitor_alarm(alarm_ip, alarm_port, config_file):
    logging.basicConfig()
    facebook_token = environ.get('FACEBOOK_TOKEN')
    secret = environ.get('SECRET')
    if not facebook_token:
        raise ClickException('FACEBOOK_TOKEN environment variable is not set')
    if not secret:
        raise ClickException('SECRET environment variable is not set')
    run(monitor_alarm_async(
        alarm_ip, alarm_port, facebook_token,
        config_file=config_file, secret=secret,
    ))
