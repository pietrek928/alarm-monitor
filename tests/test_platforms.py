from asyncio import CancelledError, Event, create_task, sleep

import pytest

from alarm_monitor.platforms import (
    PlatformRegistry,
    PlatformState,
    PlatformsUnavailable,
    run_platform_supervisor,
)


@pytest.mark.asyncio
async def test_all_down_raises():
    registry = PlatformRegistry({"fb"})
    calls = {"n": 0}

    async def run_once():
        calls["n"] += 1
        raise RuntimeError("down")

    with pytest.raises(PlatformsUnavailable):
        await run_platform_supervisor(
            "fb",
            registry,
            run_once,
            retry_seconds=0.01,
            sleep_fn=sleep,
        )
    assert calls["n"] == 1
    assert registry.state("fb") is PlatformState.DOWN


@pytest.mark.asyncio
async def test_retry_when_other_platform_up():
    registry = PlatformRegistry({"fb", "discord"})
    registry.set_state("discord", PlatformState.UP)
    calls = {"n": 0}
    slept = {"n": 0}

    async def run_once():
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("transient")
        raise RuntimeError("second")

    async def fake_sleep(_seconds):
        slept["n"] += 1
        if slept["n"] >= 1:
            registry.set_state("discord", PlatformState.DOWN)

    with pytest.raises(PlatformsUnavailable):
        await run_platform_supervisor(
            "fb",
            registry,
            run_once,
            retry_seconds=0.01,
            sleep_fn=fake_sleep,
        )
    assert calls["n"] == 2
    assert slept["n"] == 1


@pytest.mark.asyncio
async def test_cancelled_does_not_raise_platforms_unavailable():
    registry = PlatformRegistry({"fb", "discord"})
    registry.set_state("discord", PlatformState.UP)
    started = Event()

    async def run_once():
        started.set()
        await Event().wait()

    task = create_task(
        run_platform_supervisor("fb", registry, run_once, retry_seconds=60)
    )
    await started.wait()
    task.cancel()
    with pytest.raises(CancelledError):
        await task
    assert registry.state("fb") is PlatformState.DOWN
