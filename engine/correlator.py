import sys
sys.path.insert(0, r"C:\lockout-forensics")
from parsers.event_parser import WindowsEvent
from datetime import datetime
from collections import defaultdict
from dataclasses import dataclass, field


def parse_time(ts: str) -> datetime:
    
    ts = ts.rstrip("Z").split(".")[0]
    return datetime.fromisoformat(ts)


@dataclass
class LockoutEvent:
    account: str
    lockout_time: datetime
    lockout_computer: str
    failed_attempts: list[WindowsEvent] = field(default_factory=list)

    @property
    def source_machines(self) -> set:
        return {e.source_machine for e in self.failed_attempts if e.source_machine and e.source_machine != "-"}

    @property
    def source_ips(self) -> set:
        return {e.source_ip for e in self.failed_attempts if e.source_ip and e.source_ip not in ("-", "::1", "127.0.0.1")}

    @property
    def logon_types(self) -> set:
        return {e.logon_type for e in self.failed_attempts if e.logon_type}


def correlate(events: list[WindowsEvent]) -> list[LockoutEvent]:
    lockouts = [e for e in events if e.event_id == "4740"]
    failures = [e for e in events if e.event_id == "4625"]

    failures_by_account=defaultdict(list)
    for e in failures:
        if e.account_name:
            failures_by_account[e.account_name].append(e)
    results = []

    for lockout in lockouts:
        account = lockout.account_name
        lockout_time = parse_time(lockout.timestamp)

        related_failures = [
            f for f in failures_by_account[account]
            if parse_time(f.timestamp) <= lockout_time
        ]
    lockout_event = LockoutEvent(
            account=account,
            lockout_time=lockout_time,
            lockout_computer=lockout.computer,
            failed_attempts=related_failures,
        )
    results.append(lockout_event)
    return results

if __name__ == "__main__":
    from parsers.event_parser import parse_event, WindowsEvent
    from Evtx.Evtx import Evtx
    import xml.etree.ElementTree as ET

    events = []
    with Evtx(r"C:\lockout-forensics\tests\sample_logs\lockout_test.evtx") as log:
        for record in log.records():
            root = ET.fromstring(record.xml())
            event = parse_event(root)
            if event:
                events.append(event)

    results = correlate(events)
    for r in results:
        print(f"Account: {r.account}")
        print(f"Lockout time: {r.lockout_time}")
        print(f"Failed attempts: {len(r.failed_attempts)}")
        print(f"Source machines: {r.source_machines}")