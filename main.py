import sys
sys.path.insert(0, r"C:\lockout-forensics")

import argparse
from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET
from parsers.event_parser import parse_event
from engine.correlator import correlate
from engine.classifier import classify
from reporter.report_generator import generate_report
from datetime import datetime
from tqdm import tqdm

def load_events(evtx_path: str):
    interesting_ids = {"4624", "4625", "4720", "4740"}
    events = []
    with Evtx(evtx_path) as log:
        records = list(log.records())
        for record in tqdm(records, desc="Parsing logs", unit="rec"):
            root = ET.fromstring(record.xml())
            event = parse_event(root)
            if event:
                events.append(event)
    return events


def print_summary(lockout, result):
    print()
    print("=" * 60)
    print(f"  LOCKOUT FORENSICS REPORT")
    print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    print(f"\nTARGET ACCOUNT:  {lockout.account}")
    print(f"LOCKOUT TIME:    {lockout.lockout_time}")
    print(f"LOCKED OUT ON:   {lockout.lockout_computer}")
    print(f"SOURCE MACHINE:  {', '.join(lockout.source_machines) or 'Unknown'}")

    print(f"\nPOSSIBLE CAUSES:")
    for cause, confidence in result.possible_causes:
        print(f"  {cause}: {confidence}%")

    print(f"\nEVIDENCE:")
    for item in result.evidence:
        print(f"  {item}")

    print(f"\nTIMELINE:")
    for attempt in lockout.failed_attempts:
        print(f"  {attempt.timestamp}  4625 - Failed logon from {attempt.source_machine or 'unknown'}")
    print(f"  {lockout.lockout_time}  4740 - Account locked out")

    print(f"\nVERDICT:     {result.verdict}")
    print(f"RISK SCORE:  {result.risk_score}/10")

    print(f"\nRECOMMENDED ACTIONS:")
    for i, rec in enumerate(result.recommendations, 1):
        print(f"  {i}. {rec}")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="Windows Account Lockout Forensics Tool",
        epilog="Example: python main.py --file security.evtx --account jsmith"
    )
    parser.add_argument("--file", required=True, help="Path to .evtx log file")
    parser.add_argument("--account", default=None, help="Filter to specific account (optional)")
    parser.add_argument("--output", default=r"C:\lockout-forensics\output", help="Output directory for HTML report")

    args = parser.parse_args()

    print(f"[*] Loading events from {args.file}...")
    events = load_events(args.file)
    print(f"[*] Parsed {len(events)} relevant events")

    lockouts = correlate(events)

    if not lockouts:
        print("[!] No lockout events (4740) found in this log file.")
        sys.exit(0)

    if args.account:
        lockouts = [l for l in lockouts if l.account.lower() == args.account.lower()]
        if not lockouts:
            print(f"[!] No lockouts found for account: {args.account}")
            sys.exit(0)

    print(f"[*] Found {len(lockouts)} lockout(s)\n")

    for lockout in lockouts:
        result = classify(lockout)
        print_summary(lockout, result)
        path = generate_report(lockout, result, args.output)
        print(f"\n[+] HTML report saved: {path}\n")


if __name__ == "__main__":
    main()