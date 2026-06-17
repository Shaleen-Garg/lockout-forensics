import sys
sys.path.insert(0, r"C:\lockout-forensics")

from engine.correlator import LockoutEvent
from dataclasses import dataclass, field
from datetime import datetime

@dataclass
class ClassificationResult:
    possible_causes: list[tuple[str,int]]
    evidence:list[str]
    risk_score: int
    verdict: str
    recommendations: list[str]
    logon_type_interpretation: dict

def infer_causes(lockout: LockoutEvent)->list[tuple[str, int]]:
    causes = {
        "Stale network credentials": 0,
        "Cached credentials": 0,
        "Service misconfiguration": 0,
        "Scheduled task (stale password)": 0,
        "Credential stuffing": 0,
        "Manual brute force": 0,
    }

    logon_types = lockout.logon_types

    if "3" in logon_types:
        causes["Stale network credentials"] += 40
        causes["Cached credentials"] += 35
    if "5" in logon_types:
        causes["Service misconfiguration"]+=40
    if "4" in logon_types:
        causes["Scheduled task (stale password)"]+=40
    if "10" in logon_types:
        causes["Credential stuffing"]+=45
    if "7" in logon_types:
        causes["Cached credentials"] += 40

    num_machines = len(lockout.source_machines)
    if num_machines==1:
        causes["Stale network credentials"]+=30
        causes["Cached credentials"]+=25
    if num_machines>3:
        causes["Credential stuffing"]+=40
        causes["Manual brute force"]+=40

    failure_count = len(lockout.failed_attempts)
    if failure_count<=5:
        causes["Stale network credentials"]+=30
    if failure_count>10:
        causes["Manual brute force"]+=35
        causes["Credential stuffing"]+=30

    total=sum(causes.values())
    if total==0:
        return [("Unknown",0)]
    sorted_causes=sorted(causes.items(),key=lambda x:x[1], reverse=True)
    result = [(cause,round((score/total)*100)) for cause, score in sorted_causes if score>0]
    return result
def calculate_risk(lockout: LockoutEvent) -> tuple[int, str]:
    score = 0

    if len(lockout.source_machines) > 3:
        score += 3

    if len(lockout.failed_attempts) > 10:
        score += 2

    
    hour = lockout.lockout_time.hour
    if hour < 8 or hour >= 18:
        score += 2

    
    if not lockout.source_machines:
        score += 3

    if score <= 3:
        verdict = "ROUTINE"
    elif score <= 6:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CRITICAL"

    return score, verdict


LOGON_TYPE_MAP = {
    "2":  ("Interactive",       "User logged in directly at the machine"),
    "3":  ("Network",           "Mapped drive, file share, or net use command"),
    "4":  ("Batch",             "Scheduled task with stale credentials"),
    "5":  ("Service",           "Windows service using outdated password"),
    "7":  ("Unlock",            "Screen unlock with cached old password"),
    "8":  ("NetworkCleartext",  "IIS basic auth or legacy application"),
    "10": ("RemoteInteractive", "RDP session with wrong credentials"),
}

def interpret_logon_types(logon_types: set) -> dict:
    result = {}
    for lt in logon_types:
        if lt in LOGON_TYPE_MAP:
            meaning, cause = LOGON_TYPE_MAP[lt]
            result[lt] = {"meaning": meaning, "common_cause": cause}
    return result


RECOMMENDATIONS = {
    "Stale network credentials":      ["Check Windows Credential Manager", "Clear saved network passwords", "Re-map network drives with correct credentials"],
    "Cached credentials":             ["Check Windows Credential Manager", "Clear cached credentials", "Restart affected application"],
    "Service misconfiguration":       ["Check Services panel for failed services", "Update service account password", "Verify service configuration"],
    "Scheduled task (stale password)": ["Open Task Scheduler and check tasks for this account", "Update stored credentials in task", "Re-create the task with correct credentials"],
    "Credential stuffing":            ["Reset account password immediately", "Enable MFA if possible", "Review login attempts from all source IPs"],
    "Manual brute force":             ["Reset account password immediately", "Block source IPs at firewall", "Enable MFA", "Escalate to security team"],
}

def get_recommendations(causes: list[tuple[str, int]]) -> list[str]:
    if not causes:
        return ["Investigate manually — cause could not be determined"]
    top_cause = causes[0][0]
    return RECOMMENDATIONS.get(top_cause, ["Investigate manually"])


def build_evidence(lockout: LockoutEvent) -> list[str]:
    evidence = []
    evidence.append(f"✓ {len(lockout.failed_attempts)} failed attempts")
    evidence.append(f"✓ {len(lockout.source_machines)} source machine(s): {', '.join(lockout.source_machines) or 'unknown'}")
    for lt in lockout.logon_types:
        if lt in LOGON_TYPE_MAP:
            evidence.append(f"✓ Logon Type {lt} ({LOGON_TYPE_MAP[lt][0]})")
    hour = lockout.lockout_time.hour
    if hour < 8 or hour >= 18:
        evidence.append(f"⚠ Lockout occurred outside business hours ({lockout.lockout_time.strftime('%H:%M')})")
    else:
        evidence.append(f"✓ Lockout within business hours ({lockout.lockout_time.strftime('%H:%M')})")
    return evidence


def classify(lockout: LockoutEvent) -> ClassificationResult:
    causes = infer_causes(lockout)
    score, verdict = calculate_risk(lockout)
    evidence = build_evidence(lockout)
    recommendations = get_recommendations(causes)
    logon_interp = interpret_logon_types(lockout.logon_types)

    return ClassificationResult(
        possible_causes=causes,
        evidence=evidence,
        risk_score=score,
        verdict=verdict,
        recommendations=recommendations,
        logon_type_interpretation=logon_interp,
    )


if __name__ == "__main__":
    from Evtx.Evtx import Evtx
    import xml.etree.ElementTree as ET
    from parsers.event_parser import parse_event
    from engine.correlator import correlate

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
        print(f"\nAccount: {lockout.account}")
        print(f"Verdict: {result.verdict}")
        print(f"Risk Score: {result.risk_score}/10")
        print(f"\nPossible Causes:")
        for cause, confidence in result.possible_causes:
            print(f"  {cause}: {confidence}%")
        print(f"\nEvidence:")
        for e in result.evidence:
            print(f"  {e}")
        print(f"\nRecommendations:")
        for i, r in enumerate(result.recommendations, 1):
            print(f"  {i}. {r}")
        print(f"\nLogon Type Interpretation:")
        for lt, info in result.logon_type_interpretation.items():
            print(f"  Type {lt}: {info['meaning']} — {info['common_cause']}")