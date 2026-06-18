import json
import re
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import asdict
from pathlib import Path

from Evtx.Evtx import Evtx
from tqdm import tqdm

from parsers.event_parser import WindowsEvent, parse_event

EVENT_ID_PATTERN = re.compile(r"<EventID(?:\s+[^>]*)?>(4625|4740|4771|4776)</EventID>")
QUERY = "*[System[(EventID=4625 or EventID=4740 or EventID=4771 or EventID=4776)]]"
PARSER_VERSION = 3


def _cache_path(evtx_path: Path, cache_dir: Path) -> Path:
    stat = evtx_path.stat()
    key = f"{evtx_path.resolve()}|{stat.st_size}|{stat.st_mtime_ns}|{PARSER_VERSION}"
    import hashlib

    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
    return cache_dir / f"{digest}.json"


def _event_to_dict(event: WindowsEvent) -> dict:
    return asdict(event)


def _event_from_dict(data: dict) -> WindowsEvent:
    return WindowsEvent(**data)


def _load_cache(evtx_path: Path, cache_dir: Path) -> list[WindowsEvent] | None:
    path = _cache_path(evtx_path, cache_dir)
    if not path.exists():
        return None
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    return [_event_from_dict(item) for item in data.get("events", [])]


def _save_cache(evtx_path: Path, cache_dir: Path, events: list[WindowsEvent]) -> None:
    cache_dir.mkdir(parents=True, exist_ok=True)
    path = _cache_path(evtx_path, cache_dir)
    payload = {
        "parser_version": PARSER_VERSION,
        "source": str(evtx_path.resolve()),
        "events": [_event_to_dict(event) for event in events],
    }
    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def _parse_xml_events(xml_text: str) -> list[WindowsEvent]:
    cleaned = re.sub(r"<\?xml[^>]*\?>", "", xml_text).strip()
    if not cleaned:
        return []
    root = ET.fromstring(f"<Events>{cleaned}</Events>")
    events = []
    for event_root in list(root):
        event = parse_event(event_root)
        if event:
            events.append(event)
    return events


def _load_events_with_wevtutil(evtx_path: Path) -> list[WindowsEvent] | None:
    command = [
        "wevtutil",
        "qe",
        str(evtx_path),
        "/lf:true",
        f"/q:{QUERY}",
        "/f:xml",
    ]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None

    if result.returncode != 0:
        return None

    try:
        return _parse_xml_events(result.stdout)
    except ET.ParseError:
        return None


def _load_events_with_python_evtx(evtx_path: Path, show_progress: bool) -> list[WindowsEvent]:
    events = []
    with Evtx(evtx_path) as log:
        for record in tqdm(log.records(), desc="Parsing logs", unit="rec", disable=not show_progress):
            xml = record.xml()
            if not EVENT_ID_PATTERN.search(xml):
                continue
            root = ET.fromstring(xml)
            event = parse_event(root)
            if event:
                events.append(event)
    return events


def load_events(
    evtx_path: str,
    show_progress: bool = False,
    use_cache: bool = True,
    cache_dir: str | None = None,
) -> list[WindowsEvent]:
    path = Path(evtx_path).resolve()
    project_root = Path(__file__).resolve().parents[1]
    cache_path = Path(cache_dir) if cache_dir else project_root / ".cache" / "events"

    if use_cache:
        cached = _load_cache(path, cache_path)
        if cached is not None:
            return cached

    events = _load_events_with_wevtutil(path)
    if events is None:
        events = _load_events_with_python_evtx(path, show_progress)

    if use_cache:
        _save_cache(path, cache_path, events)

    return events
