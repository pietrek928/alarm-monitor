from asyncio import get_running_loop, run, sleep
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
import logging
from os import environ
from typing import Set, Tuple

from click import command, option

from alarm_monitor.commands import QueryHello, QueryMove, parse_sentence, split_sentences

from .facebook_msg import InputMessage, get_fb_user_id, receive_fb_messages, send_fb_message
from .alarm import AlarmConnection


logger = logging.getLogger('alarm_monitor')
logger.setLevel(logging.INFO)


class MessageFilter:
    allow_fb_ids: Set[str]
    processed = {}

    def __init__(self, allow_fb_ids):
        self.allow_fb_ids = set(allow_fb_ids)

    def filter(self, messages: Tuple[InputMessage], valid_seconds: int = 120):
        messages = sorted(messages, key=lambda x: x.timestamp)

        current_timestamp = datetime.now(UTC)
        if current_timestamp < messages[-1].timestamp:
            logger.warning(f'Current time is backward by {messages[-1].timestamp - current_timestamp}')
            current_timestamp = messages[-1].timestamp

        valid_since = current_timestamp - timedelta(seconds=valid_seconds)
        r = []
        for m in messages:
            if m.timestamp < valid_since:
                break
            if m.id in self.processed:
                continue
            if m.sender_id not in self.allow_fb_ids:
                logger.info(f'Ignoring message from {m.sender_id}: {m.content}')
                continue
            self.processed[m.id] = m
            logger.info(f'Processing message from {m.sender_id}: {m.content}')
            r.append(m)
        return tuple(r)

    def clear_processed(self, valid_seconds: int = 120):
        last_timestamp = max(self.processed.values(), key=lambda x: x.timestamp).timestamp
        valid_since = last_timestamp - timedelta(seconds=valid_seconds)
        self.processed = {
            mid: m for m, mid in self.processed.items() if m.timestamp > valid_since
        }

    def allow_user(self, fb_id: str):
        self.allow_fb_ids.add(fb_id)

    def disallow_user(self, fb_id: str):
        self.allow_fb_ids.discard(fb_id)


def parse_messages(messages: Tuple[InputMessage, ...]):
    for m in messages:
        for s in split_sentences(m.content):
            yield from parse_sentence(m.sender_id, m.timestamp, s):


async def monitor_alarm_async(
    ip: str, port: int, facebookToken: str,
    alert_fb_ids: Tuple[str, ...], authorize_fb_ids: Tuple[str, ...]
):
    message_filter = MessageFilter(authorize_fb_ids)
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
                for alert_id in alert_fb_ids:
                    await send_fb_message(alert_id, message, facebookToken)

        if recv_it <= 0:
            input_messages = await receive_fb_messages(facebookToken)
            input_messages = message_filter.filter(input_messages)
            message_filter.clear_processed()

            for cmd in tuple(parse_messages(input_messages)):
                if isinstance(cmd, QueryHello):
                    await send_fb_message(cmd.sender_id, 'Cześć! Tu rezydencja Malużyn', facebookToken)
                elif isinstance(cmd, QueryMove):
                    await send_fb_message(cmd.sender_id, alarm_conn.describe_move(), facebookToken)

            recv_it = 12

        await sleep(5)


def _clear_list(v: str):
    v = v.strip()
    return tuple(
        s.strip() for s in v.split(',') if s.strip()
    )


@command()
@option("--alarm_ip", help="IP address of alarm")
@option("--alarm_port", default=10967, help="Port of alarm")
@option("--alert_fb_ids", help="FB ids to send alert messages")
@option("--authorize_fb_ids", help="FB ids allowed to send commands")
def monitor_alarm(alarm_ip, alarm_port, alert_fb_ids, authorize_fb_ids):
    run(monitor_alarm_async(
        alarm_ip, alarm_port, environ['FACEBOOK_TOKEN'],
        _clear_list(alert_fb_ids), _clear_list(authorize_fb_ids)
    ))


if __name__ == "__main__":
    logging.basicConfig()
    monitor_alarm()