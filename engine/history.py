import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import json
import os
import glob
import re
from datetime import datetime
from engine.correlator import LockoutEvent
from engine.classifier import ClassificationResult

HISTORY_DIR = Path(__file__).resolve().parents[1] / "history"


def save_history(lockout: LockoutEvent, result: ClassificationResult):
    os.makedirs(HISTORY_DIR, exist_ok=True)
    date_str = lockout.lockout_time.strftime("%Y-%m-%d")
    safe_account = re.sub(r"[^A-Za-z0-9_.-]+", "_", lockout.account)
    filename = f"{date_str}_{safe_account}.json"
    path = HISTORY_DIR / filename
    data = {
        "date": date_str,
        "account": lockout.account,
        "source_machines": list(lockout.source_machines),
        "lockout_time": str(lockout.lockout_time),
        "verdict": result.verdict,
        "risk_score": result.risk_score,
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def check_history(lockout: LockoutEvent) -> dict:
    if not os.path.exists(HISTORY_DIR):
        return {}

    prior = []
    for filepath in glob.glob(os.path.join(HISTORY_DIR, "*.json")):
        with open(filepath) as f:
            record = json.load(f)
        if record.get("lockout_time") == str(lockout.lockout_time):
            continue
        
        same_account = record.get("account") == lockout.account
        same_machine = bool(set(record.get("source_machines", [])) & lockout.source_machines)
        if same_account or same_machine:
            prior.append(record)

    if not prior:
        return {}

    
    prior.sort(key=lambda x: x["date"])

    return {
        "count": len(prior),
        "dates": [r["date"] for r in prior],
        "accounts": list({r["account"] for r in prior}),
        "machines": list({m for r in prior for m in r["source_machines"]}),
    }
