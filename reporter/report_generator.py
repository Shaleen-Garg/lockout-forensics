import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import json
from jinja2 import Environment, FileSystemLoader
from datetime import datetime
from engine.correlator import LockoutEvent
from engine.classifier import ClassificationResult
import os


def _report_filename(lockout: LockoutEvent, extension: str) -> str:
    safe_account = "".join(char if char.isalnum() or char in "._-" else "_" for char in lockout.account)
    return f"lockout_{safe_account}_{lockout.lockout_time.strftime('%Y%m%d_%H%M%S')}.{extension}"


def generate_report(lockout: LockoutEvent, result: ClassificationResult, output_dir: str | None = None) -> str:
    base_dir = Path(__file__).resolve().parents[1]
    template_dir = base_dir / "reporter" / "templates"
    if output_dir is None:
        output_dir = str(base_dir / "output")
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
    filename = _report_filename(lockout, "html")
    output_path = os.path.join(output_dir, filename)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    return output_path


def generate_case_json(lockout: LockoutEvent, result: ClassificationResult, output_dir: str | None = None) -> str:
    base_dir = Path(__file__).resolve().parents[1]
    if output_dir is None:
        output_dir = str(base_dir / "output")

    payload = {
        "account": lockout.account,
        "lockout_time": str(lockout.lockout_time),
        "lockout_computer": lockout.lockout_computer,
        "source_machines": sorted(lockout.source_machines),
        "source_ips": sorted(lockout.source_ips),
        "failure_count": len(lockout.failed_attempts),
        "credential_event_count": len(lockout.credential_events),
        "failure_window_minutes": lockout.failure_window_minutes,
        "incident_summary": result.incident_summary,
        "verdict": result.verdict,
        "risk_score": result.risk_score,
        "urgency": result.urgency,
        "likely_owner": result.likely_owner,
        "possible_causes": [
            {"cause": cause, "confidence": confidence}
            for cause, confidence in result.possible_causes
        ],
        "evidence": result.evidence,
        "recommendations": result.recommendations,
        "timeline": [
            {
                "timestamp": event.timestamp,
                "event_id": event.event_id,
                "account": event.account_name,
                "source_machine": event.source_machine,
                "source_ip": event.source_ip,
                "logon_type": event.logon_type,
                "failure_reason": event.failure_reason,
            }
            for event in lockout.investigation_events
        ]
        + [
            {
                "timestamp": str(lockout.lockout_time),
                "event_id": "4740",
                "account": lockout.account,
                "source_machine": lockout.lockout_computer,
                "source_ip": None,
                "logon_type": None,
                "failure_reason": None,
            }
        ],
    }

    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, _report_filename(lockout, "json"))
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
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
