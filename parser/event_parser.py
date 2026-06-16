from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET


def get_sys_data(root):

    event_id = root.find(".//e:EventID", ns).text

    time = root.find(".//e:TimeCreated", ns).attrib["SystemTime"]

    computer = root.find(".//e:Computer", ns).text

    return event_id, time, computer


ns = {
    "e": "http://schemas.microsoft.com/win/2004/08/events/event"
}

interesting_ids = {"4624", "4625", "4720", "4740"}


with Evtx(r"tests/sample_logs/logs1.evtx") as log:

    for record in log.records():

        root = ET.fromstring(record.xml())

        event_id, time, computer = get_sys_data(root)

        if event_id in interesting_ids:

            print()

            print("Event:", event_id)

            print("Time:", time)

            print("Computer:", computer)