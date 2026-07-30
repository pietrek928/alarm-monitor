import logging
from asyncio import CancelledError, Event, sleep
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta, timezone
from enum import Enum, auto
from functools import partial

from .discord_msg import make_discord_client
from .dispatch import MonitorContext, process_inbound_messages
from .facebook_msg import get_fb_user_id, receive_fb_messages, send_fb_message
from .messaging import (
    PLATFORM_DISCORD,
    PLATFORM_FB,
    MessageFilter,
    MessagingHub,
)

UTC = timezone.utc
PLATFORM_RETRY_SECONDS = 300
FACEBOOK_POLL_SECONDS = 60
ERROR_LIMIT = 3
ERROR_WINDOW = timedelta(minutes=1)

logger = logging.getLogger("alarm_monitor.platforms")
logger.setLevel(logging.INFO)


class PlatformsUnavailable(RuntimeError):
    """Every configured messaging platform is down."""


class PlatformState(Enum):
    STARTING = auto()
    UP = auto()
    DOWN = auto()


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


class PlatformRegistry:
    def __init__(self, configured: set[str]):
        self.configured = set(configured)
        self._states = {name: PlatformState.DOWN for name in configured}
        self._up_since: dict[str, datetime | None] = {
            name: None for name in configured
        }

    def set_state(self, name: str, state: PlatformState) -> None:
        if name not in self.configured:
            raise KeyError(name)
        self._states[name] = state
        if state is PlatformState.UP:
            self._up_since[name] = datetime.now(UTC)
        else:
            self._up_since[name] = None
        logger.info("Platform %s -> %s", name, state.name)

    def state(self, name: str) -> PlatformState:
        return self._states[name]

    def all_down(self) -> bool:
        return bool(self.configured) and all(
            self._states[name] is PlatformState.DOWN for name in self.configured
        )

    def snapshot(self) -> dict[str, tuple[PlatformState, datetime | None]]:
        return {
            name: (self._states[name], self._up_since[name])
            for name in sorted(self.configured)
        }


async def run_platform_supervisor(
    name: str,
    registry: PlatformRegistry,
    run_once: Callable[[], Awaitable[None]],
    *,
    retry_seconds: float = PLATFORM_RETRY_SECONDS,
    sleep_fn=sleep,
) -> None:
    """Run a platform until cancelled. Raises PlatformsUnavailable if all down."""
    while True:
        registry.set_state(name, PlatformState.STARTING)
        try:
            await run_once()
            # run_once returned cleanly (e.g. Discord disconnect without error)
            logger.warning("Platform %s session ended", name)
        except CancelledError:
            registry.set_state(name, PlatformState.DOWN)
            raise
        except Exception:
            logger.exception("Platform %s failed", name)
        finally:
            if registry.state(name) is not PlatformState.DOWN:
                registry.set_state(name, PlatformState.DOWN)

        if registry.all_down():
            raise PlatformsUnavailable(
                f"All messaging platforms are down (failed on {name})"
            )
        logger.info("Retrying platform %s in %s seconds", name, retry_seconds)
        await sleep_fn(retry_seconds)


async def facebook_session(
    token: str,
    hub: MessagingHub,
    ctx: MonitorContext,
    registry: PlatformRegistry,
    message_filter: MessageFilter,
    *,
    poll_seconds: float = FACEBOOK_POLL_SECONDS,
    up_event: Event | None = None,
) -> None:
    """Connect Facebook, register, poll until ErrorWindow overflows or cancel."""
    bot_id = await get_fb_user_id(token)
    if not bot_id:
        raise RuntimeError("Could not get Facebook user id")

    async def send(bare_id: str, text: str) -> None:
        ok = await send_fb_message(bare_id, text, token)
        if not ok:
            raise RuntimeError(f"Facebook send failed for {bare_id}")

    hub.register(PLATFORM_FB, send, bot_id)
    registry.set_state(PLATFORM_FB, PlatformState.UP)
    if up_event is not None:
        up_event.set()
    try:
        errors = ErrorWindow()
        while True:
            try:
                messages = await receive_fb_messages(token)
                await process_inbound_messages(messages, ctx, message_filter)
            except CancelledError:
                raise
            except Exception:
                logger.exception("facebook poll iteration failed")
                if errors.record():
                    raise
            await sleep(poll_seconds)
    finally:
        hub.unregister(PLATFORM_FB)


async def discord_session(
    token: str,
    hub: MessagingHub,
    ctx: MonitorContext,
    registry: PlatformRegistry,
    message_filter: MessageFilter,
    *,
    up_event: Event | None = None,
) -> None:
    """Create a fresh Discord client, register on_ready, run until disconnect."""

    async def on_ready_register(client) -> None:
        bot_id = client.prefixed_bot_id
        if not bot_id:
            raise RuntimeError("Discord ready without user id")

        async def send(bare_id: str, text: str) -> None:
            await client.send_dm(bare_id, text)

        hub.register(PLATFORM_DISCORD, send, bot_id)
        registry.set_state(PLATFORM_DISCORD, PlatformState.UP)
        if up_event is not None:
            up_event.set()

    async def on_inbound(messages) -> None:
        await process_inbound_messages(messages, ctx)

    client = make_discord_client(
        on_ready_register=on_ready_register,
        on_inbound=on_inbound,
        message_filter=message_filter,
    )
    try:
        await client.start(token)
    finally:
        hub.unregister(PLATFORM_DISCORD)
        if not client.is_closed():
            await client.close()


def facebook_runner(
    token: str,
    hub: MessagingHub,
    ctx: MonitorContext,
    registry: PlatformRegistry,
    message_filter: MessageFilter,
    **kwargs,
) -> Callable[[], Awaitable[None]]:
    return partial(
        facebook_session,
        token,
        hub,
        ctx,
        registry,
        message_filter,
        **kwargs,
    )


def discord_runner(
    token: str,
    hub: MessagingHub,
    ctx: MonitorContext,
    registry: PlatformRegistry,
    message_filter: MessageFilter,
    **kwargs,
) -> Callable[[], Awaitable[None]]:
    return partial(
        discord_session,
        token,
        hub,
        ctx,
        registry,
        message_filter,
        **kwargs,
    )
