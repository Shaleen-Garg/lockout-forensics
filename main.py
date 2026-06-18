import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

import argparse
import time
from engine.correlator import correlate
from engine.classifier import classify, refresh_context
from reporter.report_generator import generate_case_json, generate_report
from datetime import datetime
from engine.history import save_history, check_history
from ingestion.evtx_reader import load_events


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

    print(f"\nINCIDENT SUMMARY:")
    print(f"  {result.incident_summary}")
    print(f"  Urgency: {result.urgency}")
    print(f"  Likely owner: {result.likely_owner}")

    print(f"\nPOSSIBLE CAUSES:")
    for cause, confidence in result.possible_causes:
        print(f"  {cause}: {confidence}%")

    print(f"\nEVIDENCE:")
    for item in result.evidence:
        print(f"  {item}")

    print(f"\nTIMELINE:")
    for attempt in lockout.failed_attempts:
        print(f"  {attempt.timestamp}  4625 - Failed logon from {attempt.source_machine or 'unknown'}")
    for event in lockout.credential_events:
        print(f"  {event.timestamp}  {event.event_id} - Credential validation for {event.account_name}")
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
    parser.add_argument("--output", default=str(BASE_DIR / "output"), help="Output directory for HTML report")
    parser.add_argument("--no-cache", action="store_true", help="Ignore parsed-event cache and rebuild from the EVTX file")
    parser.add_argument("--progress", action="store_true", help="Show record-by-record progress when using the Python EVTX fallback")

    args = parser.parse_args()

    print(f"[*] Loading events from {args.file}...")
    started = time.perf_counter()
    events = load_events(args.file, show_progress=args.progress, use_cache=not args.no_cache)
    elapsed = time.perf_counter() - started
    print(f"[*] Parsed {len(events)} relevant events in {elapsed:.2f}s")

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
        history = check_history(lockout)
        if history:
            print(f"\n[!] Recurring Issue Detected:")
            print(f"    Account seen {history['count']} time(s) before")
            print(f"    Dates: {', '.join(history['dates'])}")
            result.risk_score = min(10, result.risk_score + 2)  # history penalty
            result.evidence.append(f"[WARN] Recurring issue seen {history['count']} time(s) before")
            if result.risk_score > 6:
                result.verdict = "CRITICAL"
            elif result.risk_score > 3:
                result.verdict = "SUSPICIOUS"
            refresh_context(lockout, result)

        save_history(lockout, result)
        print_summary(lockout, result)
        html_path = generate_report(lockout, result, args.output)
        json_path = generate_case_json(lockout, result, args.output)
        print(f"\n[+] HTML report saved: {html_path}")
        print(f"[+] Case JSON saved:   {json_path}\n")


if __name__ == "__main__":
    main()
