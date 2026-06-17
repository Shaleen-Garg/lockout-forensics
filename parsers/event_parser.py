from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional
from collections import Counter
ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


@dataclass
class WindowsEvent:
    event_id: str
    timestamp: str
    computer: str
    account_name: Optional[str]=None
    account_domain: Optional[str]=None
    source_ip: Optional[str]=None
    source_machine: Optional[str]=None
    logon_type: Optional[str]=None
    failure_reason: Optional[str]=None
    raw: dict=field(default_factory=dict)

def get_sys_data(root):
    event_id = root.find(".//e:EventID", ns).text
    time = root.find(".//e:TimeCreated", ns).attrib["SystemTime"]
    computer = root.find(".//e:Computer", ns).text
    return event_id, time, computer


def get_event_data(root):
    data={}
    for item in root.findall(".//e:EventData/e:Data",ns):
        name=item.attrib.get("Name")
        value=item.text
        if name:
            data[name]=value 
    return data


def parse_event(root)->Optional[WindowsEvent]:
    event_id, timestamp, computer = get_sys_data(root)
    if event_id not in {"4624","4625","4720","4740"}:
        return None
    data=get_event_data(root)
    return WindowsEvent(
        event_id=event_id,
        timestamp=timestamp,
        computer=computer,
        account_name=data.get("TargetUserName") or data.get("SubjectUserName"),
        account_domain=data.get("TargetDomainName"),
        source_ip=data.get("IpAddress"),
        source_machine=data.get("WorkstationName"),
        logon_type=data.get("LogonType"),
        failure_reason=data.get("FailureReason"),
        raw=data,
    )


interesting_ids = {"4624", "4625", "4720", "4740"}
events: list[WindowsEvent]=[]


with Evtx(r"tests\sample_logs\lockout_test.evtx") as log:
    for total, record in enumerate(log.records(), start=1):
        root = ET.fromstring(record.xml())
        event = parse_event(root)
        if event:
            events.append(event)

print(f"Total records scanned: {total}")
print(f"Matching events found: {len(events)}")

id_counts = Counter(e.event_id for e in events)
print("Breakdown:", id_counts)
for e in events[:5]:
    print(e)


    