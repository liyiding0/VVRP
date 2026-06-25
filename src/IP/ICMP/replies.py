from __future__ import annotations

import time
from dataclasses import dataclass
from threading import Condition


g_ICMP_REPLY_INBOX_STATE_KEY = "icmp.echo_reply_inbox"


@dataclass(frozen=True)
class ICMP_EchoReply:
    ICMP_source: str
    ICMP_destination: str
    ICMP_identifier: int
    ICMP_sequence: int
    ICMP_ttl: int
    ICMP_payload: bytes
    ICMP_received_at: float


class ICMP_EchoReplyInbox:
    def __init__(self) -> None:
        self._ICMP_condition = Condition()
        self._ICMP_replies: list[ICMP_EchoReply] = []

    def ICMP_record(self, ICMP_reply: ICMP_EchoReply) -> None:
        with self._ICMP_condition:
            self._ICMP_replies.append(ICMP_reply)
            self._ICMP_condition.notify_all()

    def ICMP_wait(
        self,
        *,
        ICMP_source: str,
        ICMP_destination: str,
        ICMP_identifier: int,
        ICMP_sequence: int,
        ICMP_timeout_seconds: float,
    ) -> ICMP_EchoReply | None:
        ICMP_deadline = time.monotonic() + ICMP_timeout_seconds
        with self._ICMP_condition:
            while True:
                for ICMP_index, ICMP_reply in enumerate(self._ICMP_replies):
                    if (
                        ICMP_reply.ICMP_source == ICMP_source
                        and ICMP_reply.ICMP_destination == ICMP_destination
                        and ICMP_reply.ICMP_identifier == ICMP_identifier
                        and ICMP_reply.ICMP_sequence == ICMP_sequence
                    ):
                        return self._ICMP_replies.pop(ICMP_index)
                ICMP_remaining = ICMP_deadline - time.monotonic()
                if ICMP_remaining <= 0:
                    return None
                self._ICMP_condition.wait(ICMP_remaining)


def ICMP_echo_reply_inbox(ICMP_state: dict) -> ICMP_EchoReplyInbox:
    ICMP_existing = ICMP_state.get(g_ICMP_REPLY_INBOX_STATE_KEY)
    if isinstance(ICMP_existing, ICMP_EchoReplyInbox):
        return ICMP_existing
    ICMP_existing = ICMP_EchoReplyInbox()
    ICMP_state[g_ICMP_REPLY_INBOX_STATE_KEY] = ICMP_existing
    return ICMP_existing


def ICMP_record_echo_reply(
    ICMP_state: dict,
    *,
    ICMP_source: str,
    ICMP_destination: str,
    ICMP_identifier: int,
    ICMP_sequence: int,
    ICMP_ttl: int,
    ICMP_payload: bytes,
) -> None:
    ICMP_echo_reply_inbox(ICMP_state).ICMP_record(
        ICMP_EchoReply(
            ICMP_source=ICMP_source,
            ICMP_destination=ICMP_destination,
            ICMP_identifier=ICMP_identifier,
            ICMP_sequence=ICMP_sequence,
            ICMP_ttl=ICMP_ttl,
            ICMP_payload=ICMP_payload,
            ICMP_received_at=time.monotonic(),
        )
    )


def ICMP_wait_echo_reply(
    ICMP_state: dict,
    *,
    ICMP_source: str,
    ICMP_destination: str,
    ICMP_identifier: int,
    ICMP_sequence: int,
    ICMP_timeout_seconds: float,
) -> ICMP_EchoReply | None:
    return ICMP_echo_reply_inbox(ICMP_state).ICMP_wait(
        ICMP_source=ICMP_source,
        ICMP_destination=ICMP_destination,
        ICMP_identifier=ICMP_identifier,
        ICMP_sequence=ICMP_sequence,
        ICMP_timeout_seconds=ICMP_timeout_seconds,
    )
