from __future__ import annotations

import os
import shlex
import subprocess
import sys


g_CMD_REBOOT_MODULE_ENV = "VVRP_REBOOT_MODULE"
g_CMD_REBOOT_ARGS_ENV = "VVRP_REBOOT_ARGS"


def CMD_process_reboot() -> None:
    CMD_module = os.environ.get(g_CMD_REBOOT_MODULE_ENV, "src.VVRP")
    CMD_extra_args = shlex.split(os.environ.get(g_CMD_REBOOT_ARGS_ENV, ""))
    CMD_argv = [sys.executable, "-m", CMD_module, *CMD_extra_args]
    sys.stdout.flush()
    sys.stderr.flush()
    if os.name == "nt":
        CMD_exit_code = subprocess.call(CMD_argv)
        os._exit(CMD_exit_code)
    os.execv(sys.executable, CMD_argv)
