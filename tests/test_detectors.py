from datetime import datetime, timedelta, timezone

from app.detectors import (
    detect_failed_login_bursts,
    detect_port_scans,
    detect_suspicious_outbound_ports,
)
from app.models import SecurityEvent

BASE = datetime(2026, 10, 6, 12, 0, tzinfo=timezone.utc)


def test_failed_login_burst_detected():
    events = [
        SecurityEvent(
            timestamp=BASE + timedelta(minutes=i),
            event_type="failed_login",
            source_ip="203.0.113.25",
            username="analyst",
        )
        for i in range(5)
    ]
    findings = detect_failed_login_bursts(events)
    assert len(findings) == 1
    assert findings[0].rule_id == "AUTH-001"


def test_port_scan_detected():
    events = [
        SecurityEvent(
            timestamp=BASE + timedelta(seconds=i * 5),
            event_type="firewall_drop",
            source_ip="198.51.100.10",
            destination_ip="10.0.2.4",
            destination_port=port,
        )
        for i, port in enumerate([21, 22, 80, 135, 445])
    ]
    findings = detect_port_scans(events)
    assert len(findings) == 1
    assert findings[0].rule_id == "NET-001"


def test_suspicious_outbound_port_detected():
    events = [
        SecurityEvent(
            timestamp=BASE,
            event_type="network_connection",
            source_ip="10.0.2.4",
            destination_ip="203.0.113.50",
            destination_port=4444,
        )
    ]
    findings = detect_suspicious_outbound_ports(events)
    assert len(findings) == 1
    assert findings[0].rule_id == "NET-002"
