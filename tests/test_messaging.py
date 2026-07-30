from datetime import datetime, timedelta, timezone

import pytest

from alarm_monitor.messaging import (
    InputMessage,
    MessageFilter,
    UserIdError,
    chunk_text,
    parse_messages,
    parse_user_id,
    prefix_id,
)

UTC = timezone.utc


def test_prefix_and_parse_roundtrip():
    assert prefix_id("fb", "123") == "fb:123"
    assert prefix_id("discord", 99) == "discord:99"
    assert parse_user_id("fb:123") == ("fb", "123")
    assert parse_user_id("discord:99") == ("discord", "99")


@pytest.mark.parametrize(
    "bad",
    ["123", "fb:", "twitter:1", ":1", ""],
)
def test_parse_user_id_rejects_bad(bad):
    with pytest.raises(UserIdError):
        parse_user_id(bad)


def test_chunk_text():
    assert chunk_text("hi", 10) == ("hi",)
    assert chunk_text("abcdefghij", 3) == ("abc", "def", "ghi", "j")
    assert chunk_text("", 10) == ("",)


def test_message_filter_dedup_and_ttl():
    filt = MessageFilter()
    now = datetime.now(UTC)
    messages = (
        InputMessage("1", now - timedelta(seconds=200), "old", "fb:1"),
        InputMessage("2", now - timedelta(seconds=10), "zaloguj secret", "fb:1"),
        InputMessage("2", now - timedelta(seconds=5), "dup", "fb:1"),
        InputMessage("3", now - timedelta(seconds=5), "hej", "fb:2"),
    )
    kept = filt.filter(messages, valid_seconds=120)
    assert [m.id for m in kept] == ["2", "3"]
    assert filt.filter(messages, valid_seconds=120) == ()


def test_parse_messages_auth_and_hello():
    now = datetime.now(UTC)
    msgs = (
        InputMessage("1", now, "zaloguj haslo", "fb:1"),
        InputMessage("2", now, "hej", "discord:2"),
    )
    cmds = list(parse_messages(msgs))
    assert cmds[0].sender_id == "fb:1"
    assert cmds[0].password == "haslo"
    assert cmds[1].sender_id == "discord:2"
