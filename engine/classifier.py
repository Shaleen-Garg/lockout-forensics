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
    