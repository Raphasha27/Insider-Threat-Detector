from dataclasses import dataclass, field
import json


@dataclass
class Event:
    user: str
    action: str
    resource: str
    risk_score: float = 0.0


@dataclass
class Alert:
    user: str
    score: float
    reason: str
    events: list[Event] = field(default_factory=list)


class ThreatDetector:
    HIGH_RISK_ACTIONS = {"data_exfiltration", "privilege_escalation", "unauthorized_access",
                         "mass_download", "credential_dump"}
    SENSITIVE_RESOURCES = {"financial_db", "hr_records", "source_code", "customer_pii",
                           "secrets_vault"}

    def __init__(self, threshold: float = 0.7):
        self.threshold = threshold

    def analyze_events(self, events: list[Event]) -> list[Alert]:
        user_events: dict[str, list[Event]] = {}
        for e in events:
            user_events.setdefault(e.user, []).append(e)

        alerts = []
        for user, user_evts in user_events.items():
            score = self._calculate_risk(user_evts)
            if score >= self.threshold:
                top = max(user_evts, key=lambda x: x.risk_score)
                alerts.append(Alert(user=user, score=score,
                                     reason=f"High-risk behavior detected ({top.action})",
                                     events=user_evts))
        return alerts

    def _calculate_risk(self, events: list[Event]) -> float:
        if not events:
            return 0.0
        score = 0.0
        for e in events:
            if e.action in self.HIGH_RISK_ACTIONS:
                e.risk_score = 0.8
            elif e.action in {"file_access", "email_sent", "login"}:
                e.risk_score = 0.1
            else:
                e.risk_score = 0.3

            if e.resource in self.SENSITIVE_RESOURCES:
                e.risk_score = min(e.risk_score + 0.2, 1.0)

            score += e.risk_score
        return min(score / len(events), 1.0)

    def generate_report(self, events: list[Event]) -> dict:
        alerts = self.analyze_events(events)
        return {
            "total_events": len(events),
            "unique_users": len(set(e.user for e in events)),
            "alerts_generated": len(alerts),
            "alerts": [
                {"user": a.user, "score": a.score, "reason": a.reason,
                 "events": len(a.events)}
                for a in alerts
            ],
        }


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Insider Threat Detector")
    parser.add_argument("--events", help="JSON file with events")
    parser.add_argument("--threshold", type=float, default=0.7)
    args = parser.parse_args()

    with open(args.events) as f:
        raw = json.load(f)

    events = [Event(**e) for e in raw]
    detector = ThreatDetector(threshold=args.threshold)
    report = detector.generate_report(events)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
