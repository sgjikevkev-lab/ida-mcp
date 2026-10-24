"""IDA startup script for a disposable test database only."""
import os
from pathlib import Path
import ida_auto
import ida_kernwin
import ida_pro
import idc

directory = Path(os.environ['IDA_MCP_QA_DIR'])
ida_auto.auto_wait()
# Exercise the plugin's scoped dialog suppression rather than relying on -A.
idc.batch(0)


def finish_when_requested():
    if (directory / 'stop').exists():
        ida_pro.qexit(0)
        return -1
    return 100


ida_kernwin.register_timer(100, finish_when_requested)
(directory / 'ready').write_text('ready', encoding='utf-8')
