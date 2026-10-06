from .models import Finding


def build_incident_summary(findings: list[Finding]) -> str:
    if not findings:
        return (
            "No rule-based indicators met the current detection thresholds. "
            "This does not prove that the activity is benign."
        )

    titles = ", ".join(finding.title for finding in findings)
    return (
        f"The analyzer produced {len(findings)} security finding(s): {titles}. "
        "Validate these findings against endpoint, identity, network, and SIEM telemetry "
        "before escalation."
    )


def build_recommended_actions(findings: list[Finding]) -> list[str]:
    actions: list[str] = []
    rule_ids = {finding.rule_id for finding in findings}

    if "AUTH-001" in rule_ids:
        actions.extend(
            [
                "Review authentication logs for successful logins following the failures.",
                "Validate the affected account and source IP with identity and endpoint telemetry.",
            ]
        )
    if "NET-001" in rule_ids:
        actions.extend(
            [
                "Correlate the scanning source with IDS, firewall, and endpoint telemetry.",
                "Confirm whether the source is an approved vulnerability scanner.",
            ]
        )
    if "NET-002" in rule_ids:
        actions.extend(
            [
                "Investigate the destination IPs and processes responsible for the outbound connections.",
                "Check threat-intelligence sources for the destination indicators.",
            ]
        )
    if not actions:
        actions.append("Continue monitoring and enrich the data with additional telemetry.")

    return list(dict.fromkeys(actions))
