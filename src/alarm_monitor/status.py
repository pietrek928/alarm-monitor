from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

UTC = timezone.utc
ALARM_START_PREFIX = "Alarm w strefie"
ALARM_END_PREFIX = "Koniec alarmu w strefie"
ALERT_PREFIXES = (ALARM_START_PREFIX, ALARM_END_PREFIX)


def format_duration(started: datetime | None, *, now: datetime | None = None) -> str:
    if started is None:
        return "?"
    now = now or datetime.now(UTC)
    delta = max(timedelta(0), now - started)
    delta = timedelta(seconds=int(delta.total_seconds()))
    return str(delta)


@dataclass
class RuntimeStatus:
    alarm_endpoint: str = ""
    alarm_connected_at: datetime | None = None
    last_alarm_at: datetime | None = None
    last_alarm_where: str | None = None

    def note_alarm_messages(
        self,
        messages: Iterable[str],
        *,
        now: datetime | None = None,
    ) -> None:
        stamp = now or datetime.now(UTC)
        for message in messages:
            if message.startswith(ALARM_START_PREFIX):
                self.last_alarm_where = message
                self.last_alarm_at = stamp

    def format_report(self, registry, *, now: datetime | None = None) -> str:
        now = now or datetime.now(UTC)
        lines: list[str] = []
        if self.alarm_connected_at is not None:
            lines.append(
                f"Alarm: OK, od {format_duration(self.alarm_connected_at, now=now)}"
                f" ({self.alarm_endpoint})"
            )
        else:
            lines.append("Alarm: brak połączenia")

        for name, (state, up_since) in registry.snapshot().items():
            if state.name == "UP" and up_since is not None:
                lines.append(
                    f"{name}: UP od {format_duration(up_since, now=now)}"
                )
            else:
                lines.append(f"{name}: {state.name}")

        if self.last_alarm_where and self.last_alarm_at:
            when = self.last_alarm_at.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
            lines.append(f"Ostatni alarm: {self.last_alarm_where} ({when})")
        else:
            lines.append("Ostatni alarm: brak")

        return "\n".join(lines)
