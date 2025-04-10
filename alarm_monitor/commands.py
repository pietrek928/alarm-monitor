import re
from datetime import datetime
from dataclasses import dataclass, field
from typing import Tuple
from unidecode import unidecode


@dataclass
class UserCommand:
    sender_id: str
    timestamp: datetime

@dataclass
class QueryMove(UserCommand):
    pass

@dataclass
class Hello(UserCommand):
    pass

@dataclass
class AuthME(UserCommand):
    password: str

@dataclass
class AlarmON(UserCommand):
    partitions: Tuple[int, ...] = field(default_factory=tuple)

@dataclass
class AlarmOFF(UserCommand):
    partitions: Tuple[int, ...] = field(default_factory=tuple)

@dataclass
class SetAlarmCode(UserCommand):
    code: str


SPLIT_SENTENCE_PATTERN = re.compile(r'[\n,.]|\bi\b|\boraz\b')
WHITESPACE_PATTERN = re.compile(r'\s+')
INT_PATTERN = re.compile(r'\d+')
IGNORE_WORDS = {'sie', 'sobie', 'jest'}


def split_sentences(s: str) -> Tuple[Tuple[str, ...], ...]:
    s = unidecode(s).lower()
    r = []
    current_sentence = []
    for v in SPLIT_SENTENCE_PATTERN.split(s):
        v = WHITESPACE_PATTERN.sub(' ', v)
        v = v.split(' ')
        v = tuple(x for x in v if x not in IGNORE_WORDS)
        if len(v) <= 1:
            current_sentence.extend(v)
            continue

        if current_sentence:
            r.append(tuple(current_sentence))
            current_sentence = []
        current_sentence = v
    if current_sentence:
        r.append(tuple(current_sentence))
    return tuple(r)


def get_sentence_numbers(s: Tuple[str, ...]) -> Tuple[int, ...]:
    return tuple(
        int(x) for x in INT_PATTERN.findall(' '.join(s))
    )


QUERY_PREF = ('czy', 'jak', 'co')
AUTH_ME_WORDS_PREF = ('zaloguj', 'autoryzuj', 'loguj', 'pozwol', 'zezwol')
MOVE_WORD_PREF = ('ruch', 'rusz', 'porusz')
HELLO_WORD_PREF = ('hej', 'czesc', 'witaj', 'witam')
ON_WORS_PREF = ('wlacz', 'zalacz', 'odpal')
OFF_WORDS_PREF = ('wylacz', 'zgas')
ALARM_WORDS = ('alarm', 'system')
SET_WORDS = ('ustaw', )
CODE_WORDS = ('kod', 'haslo')



def has_word_by_pref(s: Tuple[str, ...], pref: Tuple[str, ...]):
    return any(
        x.startswith(p) for p in pref for x in s
    )

def parse_sentence(sender_id, timestamp, s: Tuple[str, ...]):
    if has_word_by_pref(s, AUTH_ME_WORDS_PREF):
        yield AuthME(
            sender_id=sender_id, timestamp=timestamp,
            password=s[-1]
        )

    if has_word_by_pref(s[:1], HELLO_WORD_PREF):
        s = s[1:]
        yield Hello(
            sender_id=sender_id, timestamp=timestamp
        )

    if has_word_by_pref(s[:1], SET_WORDS):
        if has_word_by_pref(s, CODE_WORDS):
            yield SetAlarmCode(
                sender_id=sender_id, timestamp=timestamp,
                code=s[-1]
            )
            return

    if s and s[0] in QUERY_PREF:
        s = s[1:]
        if has_word_by_pref(s, MOVE_WORD_PREF):
            yield QueryMove(
                sender_id=sender_id, timestamp=timestamp
            )
            return

    if has_word_by_pref(s, OFF_WORDS_PREF):
        if has_word_by_pref(s, ALARM_WORDS):
            yield AlarmOFF(
                sender_id=sender_id, timestamp=timestamp,
                partitions=get_sentence_numbers(s)
            )
            return

    if has_word_by_pref(s, ON_WORS_PREF):
        if has_word_by_pref(s, ALARM_WORDS):
            yield AlarmON(
                sender_id=sender_id, timestamp=timestamp,
                partitions=get_sentence_numbers(s)
            )
            return
