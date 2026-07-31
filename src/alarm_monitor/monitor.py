import logging
from asyncio import (
    FIRST_EXCEPTION,
    Event,
    Lock,
    create_task,
    gather,
    get_running_loop,
    run,
    sleep,
    wait,
)
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from functools import partial
from os import environ
from typing import Callable

from click import ClickException, command, option

from .alarm import AlarmConnection
from .dispatch import MonitorContext, deliver_alarm_messages, load_config, save_config
from .messaging import PLATFORM_DISCORD, PLATFORM_FB, MessageFilter, MessagingHub
from .platforms import (
    PlatformRegistry,
    PlatformsUnavailable,
    discord_runner,
    facebook_runner,
    run_platform_supervisor,
)
from .status import RuntimeStatus

UTC = timezone.utc
ALARM_POLL_SECONDS = 5
ERROR_LIMIT = 3
ERROR_WINDOW = timedelta(minutes=1)

logger = logging.getLogger("alarm_monitor")
logger.setLevel(logging.INFO)

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


async def poll_alarm(ctx: MonitorContext) -> None:
    async with ctx.alarm_lock:
        alarm_conn = await ctx.require_alarm()
        await ctx.alarm(alarm_conn.query_alarm)
        await ctx.alarm(alarm_conn.query_move)
        alarm_messages = await ctx.alarm(alarm_conn.receive_data)
    await deliver_alarm_messages(ctx, alarm_messages, reply_to=())


async def alarm_poll_loop(ctx: MonitorContext) -> None:
    errors = ErrorWindow()
    while True:
        try:
            await poll_alarm(ctx)
        except Exception:
            logger.exception("alarm poll iteration failed")
            if errors.record():
                raise
        await sleep(ALARM_POLL_SECONDS)


async def alarm_connect_and_poll(
    ctx: MonitorContext,
    alarm: AlarmRunner,
    ip: str,
    port: int,
) -> None:
    conn = await alarm(AlarmConnection, ip, port)
    ctx.alarm_conn = conn
    ctx.runtime.alarm_connected_at = datetime.now(UTC)
    ctx.alarm_ready.set()
    logger.info("Connected to alarm at %s:%s", ip, port)
    await alarm_poll_loop(ctx)


async def monitor_alarm_async(
    ip: str,
    port: int,
    config_file: str,
    secret: str,
    *,
    facebook_token: str | None = None,
    discord_token: str | None = None,
):
    if not facebook_token:
        logger.warning("FACEBOOK_TOKEN not set; Facebook messaging disabled")
    if not discord_token:
        logger.warning("DISCORD_TOKEN not set; Discord messaging disabled")
    if not facebook_token and not discord_token:
        raise RuntimeError("At least one of FACEBOOK_TOKEN or DISCORD_TOKEN is required")

    cfg = await load_config(config_file)
    hub = MessagingHub()
    alarm_lock = Lock()
    config_lock = Lock()
    dispatch_lock = Lock()
    loop = get_running_loop()

    configured: set[str] = set()
    if facebook_token:
        configured.add(PLATFORM_FB)
    if discord_token:
        configured.add(PLATFORM_DISCORD)
    registry = PlatformRegistry(configured)
    runtime = RuntimeStatus(alarm_endpoint=f"{ip}:{port}")

    with ThreadPoolExecutor(max_workers=1) as pool:
        alarm = partial(loop.run_in_executor, pool)
        ctx: MonitorContext | None = None
        tasks = []
        try:
            ctx = MonitorContext(
                alarm=alarm,
                alarm_conn=None,
                alarm_ready=Event(),
                cfg=cfg,
                config_file=config_file,
                secret=secret,
                hub=hub,
                alarm_lock=alarm_lock,
                config_lock=config_lock,
                dispatch_lock=dispatch_lock,
                runtime=runtime,
                registry=registry,
            )

            tasks = [
                create_task(
                    alarm_connect_and_poll(ctx, alarm, ip, port),
                    name="alarm_poll",
                ),
            ]
            if facebook_token:
                fb_filter = MessageFilter()
                tasks.append(
                    create_task(
                        run_platform_supervisor(
                            PLATFORM_FB,
                            registry,
                            facebook_runner(
                                facebook_token, hub, ctx, registry, fb_filter
                            ),
                        ),
                        name="facebook_supervisor",
                    )
                )
            if discord_token:
                dc_filter = MessageFilter()
                tasks.append(
                    create_task(
                        run_platform_supervisor(
                            PLATFORM_DISCORD,
                            registry,
                            discord_runner(
                                discord_token, hub, ctx, registry, dc_filter
                            ),
                        ),
                        name="discord_supervisor",
                    )
                )

            done, pending = await wait(tuple(tasks), return_when=FIRST_EXCEPTION)
            for t in pending:
                t.cancel()
            if pending:
                await gather(*pending, return_exceptions=True)
            for t in done:
                exc = t.exception()
                if exc is not None:
                    raise exc
        finally:
            if ctx is not None and ctx.alarm_conn is not None:
                try:
                    await alarm(ctx.alarm_conn.disconnect)
                except Exception:
                    logger.exception("Failed to disconnect alarm")
            async with config_lock:
                await save_config(config_file, cfg)


@command()
@option("--alarm_ip", required=True, help="IP address of alarm")
@option("--alarm_port", default=10967, help="Port of alarm")
@option("--config_file", required=True, help="Path to config file")
def monitor_alarm(alarm_ip, alarm_port, config_file):
    logging.basicConfig()
    facebook_token = environ.get("FACEBOOK_TOKEN") or None
    discord_token = environ.get("DISCORD_TOKEN") or None
    secret = environ.get("SECRET")
    if not facebook_token and not discord_token:
        raise ClickException(
            "At least one of FACEBOOK_TOKEN or DISCORD_TOKEN must be set"
        )
    if not secret:
        raise ClickException("SECRET environment variable is not set")
    try:
        run(
            monitor_alarm_async(
                alarm_ip,
                alarm_port,
                config_file=config_file,
                secret=secret,
                facebook_token=facebook_token,
                discord_token=discord_token,
            )
        )
    except PlatformsUnavailable as exc:
        raise SystemExit(str(exc)) from exc
