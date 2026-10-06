from .models import Finding

SEVERITY_POINTS = {"Low": 10, "Medium": 25, "High": 40, "Critical": 60}


def calculate_risk_score(findings: list[Finding]) -> int:
    return min(100, sum(SEVERITY_POINTS[finding.severity] for finding in findings))


def risk_level(score: int) -> str:
    if score >= 80:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"
