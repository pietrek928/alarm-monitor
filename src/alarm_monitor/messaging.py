import logging
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TypeAlias

from .commands import AuthME, parse_sentence, split_sentences

UTC = timezone.utc
MESSAGE_VALID_SECONDS = 120
MESSAGE_CHUNK_SIZE = 2000

PLATFORM_FB = "fb"
PLATFORM_DISCORD = "discord"
KNOWN_PLATFORMS = frozenset({PLATFORM_FB, PLATFORM_DISCORD})

logger = logging.getLogger("alarm_monitor.messaging")
logger.setLevel(logging.INFO)

SendFn: TypeAlias = Callable[[str, str], Awaitable[None]]


@dataclass
class InputMessage:
    id: str
    timestamp: datetime
    content: str
    sender_id: str


class UserIdError(ValueError):
    """Malformed or unknown prefixed user id."""


def prefix_id(platform: str, raw_id: str | int) -> str:
    if platform not in KNOWN_PLATFORMS:
        raise UserIdError(f"Unknown platform: {platform}")
    return f"{platform}:{raw_id}"


def parse_user_id(user_id: str) -> tuple[str, str]:
    if ":" not in user_id:
        raise UserIdError(f"Missing platform prefix: {user_id!r}")
    platform, raw = user_id.split(":", 1)
    if platform not in KNOWN_PLATFORMS or not raw:
        raise UserIdError(f"Invalid user id: {user_id!r}")
    return platform, raw


def chunk_text(text: str, size: int = MESSAGE_CHUNK_SIZE) -> tuple[str, ...]:
    if not text:
        return ("",)
    return tuple(text[i : i + size] for i in range(0, len(text), size))


def _log_message(message: InputMessage) -> None:
    preview = message.content
    try:
        for sentence in split_sentences(message.content):
            for cmd in parse_sentence(sentence):
                if isinstance(cmd, AuthME):
                    preview = "<redacted auth>"
                    break
            else:
                continue
            break
    except Exception:
        logger.exception("Failed to build log preview for message %s", message.id)
        preview = "<unloggable>"
    logger.info("Processing message from %s: %s", message.sender_id, preview)


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
            _log_message(m)
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


class MessagingHub:
    def __init__(self) -> None:
        self._sends: dict[str, SendFn] = {}
        self._bot_ids: dict[str, str] = {}

    def register(self, platform: str, send: SendFn, bot_id: str) -> None:
        if platform not in KNOWN_PLATFORMS:
            raise UserIdError(f"Unknown platform: {platform}")
        self._sends[platform] = send
        self._bot_ids[platform] = bot_id
        logger.info("Registered platform %s as %s", platform, bot_id)

    def unregister(self, platform: str) -> None:
        self._sends.pop(platform, None)
        self._bot_ids.pop(platform, None)
        logger.info("Unregistered platform %s", platform)

    @property
    def live_platforms(self) -> set[str]:
        return set(self._sends)

    @property
    def bot_ids(self) -> set[str]:
        return set(self._bot_ids.values())

    async def send(self, user_id: str, text: str) -> None:
        try:
            platform, raw = parse_user_id(user_id)
        except UserIdError:
            logger.warning("Skipping send to malformed user id %r", user_id)
            return
        send_fn = self._sends.get(platform)
        if send_fn is None:
            logger.warning(
                "Skipping send to %s; platform %s is down", user_id, platform
            )
            return
        for chunk in chunk_text(text):
            try:
                logger.info("%s -> %s", chunk.replace("\n", " | "), user_id)
                await send_fn(raw, chunk)
            except Exception:
                logger.exception("Failed to send to %s", user_id)
                return

    async def broadcast(self, recipients: Iterable[str], text: str) -> None:
        for recipient in tuple(recipients):
            await self.send(recipient, text)
