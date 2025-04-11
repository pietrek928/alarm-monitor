import re
from datetime import datetime
from dataclasses import dataclass, field
from typing import Iterable, Tuple
from unidecode import unidecode


@dataclass
class UserCommand:
    sender_id: str = None
    timestamp: datetime = None

@dataclass
class QueryMove(UserCommand):
    pass

@dataclass
class Hello(UserCommand):
    pass

@dataclass
class Help(UserCommand):
    pass

@dataclass
class Subscribe(UserCommand):
    subscribe: bool = None

@dataclass
class AuthME(UserCommand):
    password: str = None

@dataclass
class AlarmON(UserCommand):
    partitions: Tuple[int, ...] = field(default_factory=tuple)

@dataclass
class AlarmOFF(UserCommand):
    partitions: Tuple[int, ...] = field(default_factory=tuple)

@dataclass
class SetAlarmCode(UserCommand):
    code: str = None

@dataclass
class SetDefaultPartitions(UserCommand):
    zones: Tuple[int, ...] = None


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


NOT_WORDS = ('nie', )
QUERY_PREF = ('czy', 'jak', 'co')
AUTH_ME_WORDS_PREF = ('zaloguj', 'autoryzuj', 'loguj', 'pozwol', 'zezwol')
HELP_WORDS_PREF = ('pomoc', 'pomoz', 'instrukcja', 'instrukcje', 'komendy', 'help')
SUBSCRIBE_WORDS_PREF = ('informuj', 'subskrybuj', 'powiadom', 'powiadamiaj')
MOVE_WORD_PREF = ('ruch', 'rusz', 'porusz')
HELLO_WORD_PREF = ('hej', 'czesc', 'witaj', 'witam')
ON_WORS_PREF = ('wlacz', 'zalacz', 'odpal', 'zazbroj')
OFF_WORDS_PREF = ('wylacz', 'zgas', 'rozbroj')
ALARM_WORDS = ('alarm', 'system', 'zazbroj', 'rozbroj')
PARTITIONS_WORDS = ('partycj', 'stref')
SET_WORDS = ('ustaw', )
CODE_WORDS = ('kod', 'haslo')


def get_help(auth: bool = False):
    help = f'''
Autoryzacja: zaloguj <haslo>
    '''
    if auth:
        help += f'''
Powiadomienia: informuj
Włącz alarm: wlacz alarm <partycje?> | zazbroj <partycje?>
Wyłącz alarm: wylacz alarm <partycje?> | rozbroj <partycje?>
Ustaw kod: ustaw kod <kod>
Ustaw domyślne partycje: ustaw partycje <partycje>
    '''
    return help


def has_word_by_pref(s: Tuple[str, ...], pref: Tuple[str, ...]):
    return any(
        x.startswith(p) for p in pref for x in s
    )

def has_word(s: Tuple[str, ...], words: Tuple[str, ...]):
    return any(
        x in words for x in s
    )

def parse_sentence(s: Tuple[str, ...]) -> Iterable[UserCommand]:
    if has_word_by_pref(s, AUTH_ME_WORDS_PREF):
        yield AuthME(password=s[-1])

    if has_word_by_pref(s, HELP_WORDS_PREF):
        yield Help()
        return

    if has_word_by_pref(s[:1], HELLO_WORD_PREF):
        s = s[1:]
        yield Hello()

    if has_word_by_pref(s[:1], SET_WORDS):
        if has_word_by_pref(s, CODE_WORDS):
            yield SetAlarmCode(code=s[-1])
            return
        if has_word_by_pref(s, PARTITIONS_WORDS):
            yield SetDefaultPartitions(zones=get_sentence_numbers(s))
            return

    if has_word_by_pref(s, SUBSCRIBE_WORDS_PREF):
        yield Subscribe(subscribe=not has_word(s, NOT_WORDS))
        return

    if s and s[0] in QUERY_PREF:
        s = s[1:]
        if has_word_by_pref(s, MOVE_WORD_PREF):
            yield QueryMove()
            return

    if has_word_by_pref(s, OFF_WORDS_PREF):
        if has_word_by_pref(s, ALARM_WORDS):
            yield AlarmOFF(partitions=get_sentence_numbers(s))
            return

    if has_word_by_pref(s, ON_WORS_PREF):
        if has_word_by_pref(s, ALARM_WORDS):
            yield AlarmON(partitions=get_sentence_numbers(s))
            return
