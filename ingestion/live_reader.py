"""
Live Windows Event Log ingestion placeholder.

The offline EVTX path is implemented first because it is portable and easy to
test from exported logs. Live querying should eventually wrap wevtutil or
pywin32 and return the same WindowsEvent objects as ingestion.evtx_reader.
"""


def load_live_events(*_args, **_kwargs):
    raise NotImplementedError("Live event log ingestion is not implemented yet.")
