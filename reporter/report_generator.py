import sys
sys.path.insert(0, r"C:\lockout-forensics")

from jinja2 import Environment, FileSystemLoader
from datetime import datetime
from engine.correlator import LockoutEvent
from engine.classifier import ClassificationResult
import os


def generate_report(lockout: LockoutEvent, result: ClassificationResult, output_dir: str = r"C:\lockout-forensics\output") -> str:
    template_dir = r"C:\lockout-forensics\reporter\templates"
    env = Environment(loader=FileSystemLoader(template_dir))
    template = env.get_template("report.html")

    source_machines = ", ".join(lockout.source_machines) if lockout.source_machines else "Unknown"

    html = template.render(
        lockout=lockout,
        result=result,
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        source_machines=source_machines,
    )

    os.makedirs(output_dir, exist_ok=True)
    filename = f"lockout_{lockout.account}_{lockout.lockout_time.strftime('%Y%m%d_%H%M%S')}.html"
    output_path = os.path.join(output_dir, filename)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    return output_path


if __name__ == "__main__":
    from Evtx.Evtx import Evtx
    import xml.etree.ElementTree as ET
    from parsers.event_parser import parse_event
    from engine.correlator import correlate
    from engine.classifier import classify

    events = []
    with Evtx(r"C:\lockout-forensics\tests\sample_logs\lockout_test.evtx") as log:
        for record in log.records():
            root = ET.fromstring(record.xml())
            event = parse_event(root)
            if event:
                events.append(event)

    lockouts = correlate(events)
    for lockout in lockouts:
        result = classify(lockout)
        path = generate_report(lockout, result)
        print(f"Report generated: {path}")