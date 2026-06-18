# Windows Account Lockout Forensics

## The Problem

Windows account lockouts are painful to investigate manually. An admin usually
has to search Event Viewer, jump between failed logons and lockout events, and
guess whether the cause is a stale password, a service, a scheduled task, or
something suspicious.

Enterprise SIEM tools can solve this, but they are often too expensive or too
heavy for small and mid-size teams. This project is a lightweight local tool for
turning exported Windows Security logs into a readable lockout investigation.

## What This Does

Given a Windows `.evtx` Security log, the tool:

- extracts key lockout-related events: `4740`, `4625`, `4771`, and `4776`
- uses native Windows event filtering when available, avoiding full-log scans
- caches parsed event data so repeated investigations are near-instant
- correlates failed authentication activity into a lockout timeline
- infers likely causes with confidence scores
- scores risk and labels the incident as `ROUTINE`, `SUSPICIOUS`, or `CRITICAL`
- produces a human-readable console summary, HTML report, and structured JSON case file
- saves local JSON history so recurring lockouts become visible over time

## How It Works

```text
Windows Security .evtx
        |
        v
Ingestion -> Parser -> Correlator -> Classifier -> History Check -> Report
```

The project intentionally avoids a database, cloud service, or frontend
framework. It runs locally and outputs portable reports.

On Windows, the ingestion layer first uses `wevtutil` to ask the operating
system for only the relevant event IDs. If that is unavailable, it falls back to
`python-evtx`. Parsed results are cached under `.cache/` and invalidated when
the source file changes.

## Usage

```powershell
python main.py --file tests\sample_logs\lockout_test.evtx
```

Filter to one account:

```powershell
python main.py --file tests\sample_logs\lockout_test.evtx --account testlockout
```

Choose an output folder:

```powershell
python main.py --file tests\sample_logs\lockout_test.evtx --output output
```

Force a fresh parse and bypass cache:

```powershell
python main.py --file tests\sample_logs\lockout_test.evtx --no-cache
```

Show progress when the Python EVTX fallback is used:

```powershell
python main.py --file tests\sample_logs\lockout_test.evtx --progress
```

## Project Structure

```text
main.py                     CLI entry point
ingestion/evtx_reader.py    Reads exported .evtx files
ingestion/live_reader.py    Placeholder for future live Windows log querying
parsers/event_parser.py     Extracts fields from Windows event XML
engine/correlator.py        Builds lockout timelines
engine/classifier.py        Infers causes, evidence, verdict, recommendations
engine/history.py           Saves and checks prior lockout history
reporter/                   Generates HTML reports
tests/sample_logs/          Sample exported logs
```

## Why This Is More Than Log Parsing

The value is in the investigation layer:

- correlation across event IDs and time
- confidence-based cause inference
- risk scoring based on suspicious signals
- recurring issue detection from prior runs
- incident summary, urgency, and likely-owner guidance
- structured JSON case export for tickets or automation
- analyst-friendly recommendations

The goal is to turn a manual 30-45 minute investigation into a short, repeatable
tool run with evidence the admin can act on.
