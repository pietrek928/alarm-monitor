from datetime import datetime, timedelta, timezone

from alarm_monitor.commands import (
    QueryArmedPartitions,
    QueryStatus,
    parse_sentence,
    split_sentences,
)
from alarm_monitor.platforms import PlatformRegistry, PlatformState
from alarm_monitor.status import RuntimeStatus, format_duration


UTC = timezone.utc


def _cmds(text: str):
    out = []
    for sentence in split_sentences(text):
        out.extend(parse_sentence(sentence))
    return out


def test_parse_status_variants():
    assert isinstance(_cmds("status")[0], QueryStatus)
    assert isinstance(_cmds("stan")[0], QueryStatus)
    assert isinstance(_cmds("czy status")[0], QueryStatus)
    assert isinstance(_cmds("jak stan")[0], QueryStatus)


def test_parse_czy_alarm_still_armed_query():
    assert isinstance(_cmds("czy alarm")[0], QueryArmedPartitions)


def test_format_duration():
    start = datetime(2026, 7, 30, 10, 0, 0, tzinfo=UTC)
    assert format_duration(start, now=start + timedelta(seconds=5)) == "0:00:05"
    assert format_duration(start, now=start + timedelta(minutes=3)) == "0:03:00"
    assert (
        format_duration(start, now=start + timedelta(hours=2, minutes=15))
        == "2:15:00"
    )
    assert (
        format_duration(start, now=start + timedelta(days=1, hours=1, minutes=3))
        == "1 day, 1:03:00"
    )


def test_note_alarm_messages_ignores_end_keeps_latest_start():
    runtime = RuntimeStatus()
    t1 = datetime(2026, 7, 30, 9, 0, 0, tzinfo=UTC)
    t2 = datetime(2026, 7, 30, 9, 5, 0, tzinfo=UTC)
    runtime.note_alarm_messages(
        ["Koniec alarmu w strefie 1", "Alarm w strefie 2"],
        now=t1,
    )
    assert runtime.last_alarm_where == "Alarm w strefie 2"
    assert runtime.last_alarm_at == t1
    runtime.note_alarm_messages(["Alarm w strefie 3"], now=t2)
    assert runtime.last_alarm_where == "Alarm w strefie 3"
    assert runtime.last_alarm_at == t2


def test_format_report():
    registry = PlatformRegistry({"fb", "discord"})
    registry.set_state("fb", PlatformState.UP)
    registry.set_state("discord", PlatformState.DOWN)
    connected = datetime(2026, 7, 30, 8, 0, 0, tzinfo=UTC)
    now = datetime(2026, 7, 30, 10, 15, 0, tzinfo=UTC)
    runtime = RuntimeStatus(
        alarm_endpoint="192.168.1.207:10967",
        alarm_connected_at=connected,
        last_alarm_where="Alarm w strefie 3",
        last_alarm_at=datetime(2026, 7, 30, 9, 12, 5, tzinfo=UTC),
    )
    # Force known up_since for fb
    registry._up_since["fb"] = datetime(2026, 7, 30, 9, 12, 0, tzinfo=UTC)
    report = runtime.format_report(registry, now=now)
    assert "Alarm: OK, od 2:15:00 (192.168.1.207:10967)" in report
    assert "fb: UP od 1:03:00" in report
    assert "discord: DOWN" in report
    assert "Ostatni alarm: Alarm w strefie 3 (2026-07-30 09:12:05 UTC)" in report
