from dataclasses import dataclass, field
from typing import Optional

ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
INTERESTING_EVENT_IDS = {"4625", "4740", "4771", "4776"}


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
    if event_id not in INTERESTING_EVENT_IDS:
        return None
    data=get_event_data(root)
    account_name = (
        data.get("TargetUserName")
        or data.get("SubjectUserName")
        or data.get("AccountName")
        or data.get("TargetUser")
    )
    source_machine = (
        data.get("WorkstationName")
        or data.get("Workstation")
        or data.get("CallerComputerName")
        or data.get("ClientAddress")
    )
    return WindowsEvent(
        event_id=event_id,
        timestamp=timestamp,
        computer=computer,
        account_name=account_name,
        account_domain=data.get("TargetDomainName") or data.get("AccountDomain"),
        source_ip=data.get("IpAddress") or data.get("ClientAddress"),
        source_machine=source_machine,
        logon_type=data.get("LogonType"),
        failure_reason=data.get("FailureReason") or data.get("Status") or data.get("ErrorCode"),
        raw=data,
    )




    
