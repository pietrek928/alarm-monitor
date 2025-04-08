import re
from datetime import datetime
from dataclasses import dataclass
from typing import Tuple
from unicodedata import normalize


@dataclass
class UserCommand:
    sender_id: str
    timestamp: datetime

@dataclass
class QueryMove(UserCommand):
    pass

@dataclass
class QueryHello(UserCommand):
    pass


SPLIT_SENTENCE_PATTERN = re.compile(r'\n|,|.|\bi\b|\boraz\b')
WHITESPACE_PATTERN = re.compile(r'\s+')
IGNORE_WORDS = {'sie', 'sobie', 'jest'}

def split_sentences(s: str):
    s = normalize(s).lower()
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


QUERY_PREF = ('czy', 'jak', 'co')
MOVE_WORD_PREF = ('ruch', 'rusz', 'porusz')
HELLO_WORD_PREF = ('hej', 'czesc', 'witaj', 'witam')

def has_word_by_pref(s: Tuple[str, ...], pref: Tuple[str, ...]):
    return any(
        x.startswith(p) for p in pref
        for x in s
    )

def parse_sentence(sender_id, timestamp, s: Tuple[str, ...]):
    if has_word_by_pref(s[:1], HELLO_WORD_PREF):
        s = s[1:]
        yield QueryHello(
            sender_id=sender_id, timestamp=timestamp
        )
    if s[0] in QUERY_PREF:
        s = s[1:]
        if has_word_by_pref(s, MOVE_WORD_PREF):
            yield QueryMove(
                sender_id=sender_id, timestamp=timestamp
            )
