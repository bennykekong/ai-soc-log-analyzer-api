from collections import defaultdict
from datetime import timedelta

from .models import Finding, SecurityEvent


def detect_failed_login_bursts(
    events: list[SecurityEvent], threshold: int = 5, window_minutes: int = 10
) -> list[Finding]:
    findings: list[Finding] = []
    grouped: dict[tuple[str, str], list[SecurityEvent]] = defaultdict(list)

    for event in events:
        if event.event_type != "failed_login":
            continue
        key = (event.source_ip or "unknown", event.username or "unknown")
        grouped[key].append(event)

    window = timedelta(minutes=window_minutes)
    for (source_ip, username), group in grouped.items():
        group = sorted(group, key=lambda e: e.timestamp)
        left = 0
        for right, current in enumerate(group):
            while current.timestamp - group[left].timestamp > window:
                left += 1
            count = right - left + 1
            if count >= threshold:
                findings.append(
                    Finding(
                        rule_id="AUTH-001",
                        title="Repeated failed login attempts",
                        severity="High",
                        description=(
                            f"{count} failed login attempts were observed for user "
                            f"'{username}' from source {source_ip} within {window_minutes} minutes."
                        ),
                        evidence={
                            "source_ip": source_ip,
                            "username": username,
                            "count": count,
                            "window_minutes": window_minutes,
                            "first_seen": group[left].timestamp.isoformat(),
                            "last_seen": current.timestamp.isoformat(),
                        },
                    )
                )
                break
    return findings


def detect_port_scans(
    events: list[SecurityEvent], unique_port_threshold: int = 5, window_seconds: int = 60
) -> list[Finding]:
    findings: list[Finding] = []
    grouped: dict[str, list[SecurityEvent]] = defaultdict(list)

    for event in events:
        if event.event_type not in {"network_connection", "firewall_drop"}:
            continue
        if not event.source_ip or event.destination_port is None:
            continue
        grouped[event.source_ip].append(event)

    window = timedelta(seconds=window_seconds)
    for source_ip, group in grouped.items():
        group = sorted(group, key=lambda e: e.timestamp)
        left = 0
        for right, current in enumerate(group):
            while current.timestamp - group[left].timestamp > window:
                left += 1
            ports = {
                event.destination_port
                for event in group[left : right + 1]
                if event.destination_port is not None
            }
            if len(ports) >= unique_port_threshold:
                findings.append(
                    Finding(
                        rule_id="NET-001",
                        title="Possible port scan",
                        severity="High",
                        description=(
                            f"Source {source_ip} contacted {len(ports)} unique destination "
                            f"ports within {window_seconds} seconds."
                        ),
                        evidence={
                            "source_ip": source_ip,
                            "unique_ports": sorted(ports),
                            "count": len(ports),
                            "window_seconds": window_seconds,
                        },
                    )
                )
                break
    return findings


def detect_suspicious_outbound_ports(events: list[SecurityEvent]) -> list[Finding]:
    suspicious_ports = {1337, 31337, 4444, 5555, 6667}
    matches = [
        event
        for event in events
        if event.event_type == "network_connection"
        and event.destination_port in suspicious_ports
    ]

    if not matches:
        return []

    ports = sorted({event.destination_port for event in matches if event.destination_port})
    destinations = sorted({event.destination_ip for event in matches if event.destination_ip})
    return [
        Finding(
            rule_id="NET-002",
            title="Suspicious outbound connection",
            severity="Medium",
            description=(
                "Outbound traffic was observed to one or more ports commonly associated "
                "with remote shells or suspicious tooling."
            ),
            evidence={
                "ports": ports,
                "destinations": destinations,
                "event_count": len(matches),
            },
        )
    ]


def run_detectors(events: list[SecurityEvent]) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(detect_failed_login_bursts(events))
    findings.extend(detect_port_scans(events))
    findings.extend(detect_suspicious_outbound_ports(events))
    return findings
