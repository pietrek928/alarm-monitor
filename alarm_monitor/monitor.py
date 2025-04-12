import logging
from os import environ
from typing import Set, Tuple
import aiofiles
from click import command, option
from asyncio import get_running_loop, run, sleep
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from dataclasses_json import dataclass_json

from .commands import (
    AlarmOFF, AlarmON, AuthME, Hello, Help, QueryArmedPartitions, QueryMove, SetAlarmCode,
    SetDefaultPartitions, Subscribe, get_help, parse_sentence, split_sentences
)
from .facebook_msg import InputMessage, get_fb_user_id, receive_fb_messages, send_fb_message
from .alarm import AlarmConnection


UTC = timezone.utc

logger = logging.getLogger('alarm_monitor')
logger.setLevel(logging.INFO)


@dataclass_json
@dataclass
class AlarmConfig:
    code: str = ''
    partitions: Set[int] = field(default_factory=set)
    alert_fb_ids: Set[str] = field(default_factory=set)
    authorize_fb_ids: Set[str] = field(default_factory=set)


class MessageFilter:
    processed = {}

    def filter(self, messages: Tuple[InputMessage], valid_seconds):
        if not messages:
            return ()

        messages = sorted(messages, key=lambda x: x.timestamp)

        current_timestamp = datetime.now(UTC)
        if current_timestamp < messages[-1].timestamp:
            logger.warning(f'Current time is backward by {messages[-1].timestamp - current_timestamp}')
            current_timestamp = messages[-1].timestamp

        valid_since = current_timestamp - timedelta(seconds=valid_seconds)
        r = []
        for m in messages:
            if m.timestamp < valid_since:
                continue
            if m.id in self.processed:
                continue
            self.processed[m.id] = m
            logger.info(f'Processing message from {m.sender_id}: {m.content}')
            r.append(m)
        return tuple(r)

    def clear_processed(self, valid_seconds: int = 120):
        if self.processed:
            last_timestamp = max(self.processed.values(), key=lambda x: x.timestamp).timestamp
            valid_since = last_timestamp - timedelta(seconds=valid_seconds)
            self.processed = {
                mid: m for mid, m in self.processed.items() if m.timestamp > valid_since
            }


def parse_messages(messages: Tuple[InputMessage, ...]):
    for m in messages:
        for s in split_sentences(m.content):
            for cmd in parse_sentence(s):
                cmd.sender_id = m.sender_id
                cmd.timestamp = m.timestamp
                yield cmd


async def monitor_alarm_async(
    ip: str, port: int, facebookToken: str,
    config_file: str, secret: str
):
    try:
        async with aiofiles.open(config_file, 'r') as f:
            cfg = AlarmConfig.from_json(await f.read())
        cfg.partitions = set(cfg.partitions)
        cfg.alert_fb_ids = set(cfg.alert_fb_ids)
        cfg.authorize_fb_ids = set(cfg.authorize_fb_ids)
    except FileNotFoundError:
        cfg = AlarmConfig()

    try:
        message_filter = MessageFilter()
        loop = get_running_loop()
        pool = ThreadPoolExecutor()

        fb_user_id = await get_fb_user_id(facebookToken)
        if not fb_user_id:
            raise RuntimeError('Could not get fb user id')
        logger.info(f'FB user id: {fb_user_id}')

        alarm_conn = AlarmConnection(ip, port)
        logger.info(f'Connected to alarm at {ip}:{port}')

        recv_it = 0

        while True:
            await loop.run_in_executor(pool, alarm_conn.query_alarm)
            await loop.run_in_executor(pool, alarm_conn.query_move)
            alarm_messages = await loop.run_in_executor(pool, alarm_conn.receive_data)
            if alarm_messages:
                for message in alarm_messages:
                    for alert_id in cfg.alert_fb_ids:
                        await send_fb_message(alert_id, message, facebookToken)

            if recv_it <= 0:
                input_messages = await receive_fb_messages(facebookToken)
                input_messages = message_filter.filter(input_messages, 120)
                message_filter.clear_processed()

                resp = set()
                for cmd in tuple(parse_messages(input_messages)):
                    if cmd.sender_id == fb_user_id:
                        continue

                    if isinstance(cmd, Hello):
                        await send_fb_message(cmd.sender_id, 'Cześć! Tu rezydencja Malużyn', facebookToken)
                        continue
                    if isinstance(cmd, Help):
                        await send_fb_message(cmd.sender_id, get_help(cmd.sender_id in cfg.authorize_fb_ids), facebookToken)
                        continue
                    if isinstance(cmd, AuthME):
                        if cmd.password == secret:
                            cfg.authorize_fb_ids.add(cmd.sender_id)
                            await send_fb_message(cmd.sender_id, 'Zautoryzowano', facebookToken)
                        continue

                    if cmd.sender_id not in cfg.authorize_fb_ids:
                        logger.info(f'Command from {cmd.sender_id} not authorized: {cmd}')
                        continue

                    if isinstance(cmd, Subscribe):
                        if cmd.subscribe:
                            cfg.alert_fb_ids.add(cmd.sender_id)
                            await send_fb_message(cmd.sender_id, 'Powiadomienia włączone', facebookToken)
                        else:
                            cfg.alert_fb_ids.discard(cmd.sender_id)
                            await send_fb_message(cmd.sender_id, 'Powiadomienia wyłączone', facebookToken)
                    elif isinstance(cmd, QueryMove):
                        await send_fb_message(cmd.sender_id, alarm_conn.describe_move(), facebookToken)
                    elif isinstance(cmd, QueryArmedPartitions):
                        await loop.run_in_executor(pool, alarm_conn.query_armed_partitions)
                        resp.add(cmd.sender_id)
                    elif isinstance(cmd, SetAlarmCode):
                        cfg.code = cmd.code
                    elif isinstance(cmd, SetDefaultPartitions):
                        cfg.partitions = set(cmd.zones)
                    elif isinstance(cmd, AlarmON):
                        partitions = cmd.partitions or cfg.partitions
                        if partitions:
                            await loop.run_in_executor(pool, alarm_conn.send_arm, cfg.code, partitions)
                            resp.add(cmd.sender_id)
                    elif isinstance(cmd, AlarmOFF):
                        partitions = cmd.partitions or cfg.partitions
                        if partitions:
                            await loop.run_in_executor(pool, alarm_conn.send_disarm, cfg.code, partitions)
                            resp.add(cmd.sender_id)

                if resp:
                    alarm_messages = await loop.run_in_executor(pool, alarm_conn.receive_data)
                    for message in alarm_messages:
                        for alert_id in resp:
                            await send_fb_message(alert_id, message, facebookToken)

                recv_it = 12
            else:
                recv_it -= 1

            await sleep(5)

    finally:
        logger.info('Saving config')
        async with aiofiles.open(config_file, 'w') as f:
            await f.write(cfg.to_json())


@command()
@option("--alarm_ip", help="IP address of alarm")
@option("--alarm_port", default=10967, help="Port of alarm")
@option("--config_file", help="Path to config file")
def monitor_alarm(alarm_ip, alarm_port, config_file):
    logging.basicConfig()
    run(monitor_alarm_async(
        alarm_ip, alarm_port, environ['FACEBOOK_TOKEN'],
        config_file=config_file, secret=environ['SECRET']
    ))
