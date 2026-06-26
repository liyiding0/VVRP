from __future__ import annotations

import os
import shlex
import subprocess
import sys


g_CCMD_REBOOT_MODULE_ENV = "VVRP_REBOOT_MODULE"
g_CCMD_REBOOT_ARGS_ENV = "VVRP_REBOOT_ARGS"


def CCMD_process_reboot() -> None:
    CCMD_module = os.environ.get(g_CCMD_REBOOT_MODULE_ENV, "src.VVRP")
    CCMD_extra_args = shlex.split(os.environ.get(g_CCMD_REBOOT_ARGS_ENV, ""))
    CCMD_argv = [sys.executable, "-m", CCMD_module, *CCMD_extra_args]
    sys.stdout.flush()
    sys.stderr.flush()
    if os.name == "nt":
        CCMD_exit_code = subprocess.call(CCMD_argv)
        os._exit(CCMD_exit_code)
    os.execv(sys.executable, CCMD_argv)
