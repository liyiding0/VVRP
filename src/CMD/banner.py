from __future__ import annotations

import sys
from collections.abc import Callable
from typing import TextIO


g_CMD_LOGIN_BANNER = """

***********************************************************
* Copyright (C) 2010-2026 Huavvei Technologies Co., Ltd.  *
*       Without the owner's prior written consent,        *
* no decompiling or reverse-engineering shall be allowed. *
* Notice:                                                 *
*      This is a private communication system.            *
*   Unauthorized access or use may lead to prosecution.   *
***********************************************************

User interface con0 is available




Please Press ENTER.
"""


def CMD_wait_for_login(
    *,
    CMD_input: Callable[[], str] = input,
    CMD_output: TextIO | None = None,
) -> None:
    CMD_stream = CMD_output or sys.stdout
    CMD_stream.write(g_CMD_LOGIN_BANNER)
    CMD_stream.flush()
    try:
        CMD_input()
    except EOFError:
        return
