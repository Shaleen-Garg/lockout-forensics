from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET

with Evtx(r"tests/sample_logs/logs1.evtx") as log:

    for record in log.records():

        print(record.xml())

        break
    ns={
        "e":"http://schemas.microsoft.com/win/2004/08/events/event"
    }
    root = ET.fromstring(record.xml())
    print(root.tag)
    event_id=root.find(".//e:EventID",ns)
    print(event_id.text)
    time=root.find(".//e:TimeCreated",ns)
    print(time.attrib["SystemTime"])
    computer=root.find(".//e:Computer",ns)
    print(computer.text)
    for item in root.findall(".//e:Data",ns):
        print(item.attrib)
        print(item.text)

    def get_data(root,name):
        for item in root.findall(".//e:Data",ns):
            if item.attrib.get("Name")==name:
                return item.text
        return None
    

username = get_data(root,"TargetUserName")
print(username)