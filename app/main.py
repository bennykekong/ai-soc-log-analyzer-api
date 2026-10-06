from fastapi import FastAPI

from .detectors import run_detectors
from .models import AnalysisResult, LogBatch
from .risk import calculate_risk_score, risk_level
from .summarizer import build_incident_summary, build_recommended_actions

app = FastAPI(
    title="AI-Powered SOC Log Analyzer API",
    version="0.1.0",
    description=(
        "A defensive SOC-analysis API that applies transparent detection rules, "
        "risk scoring, and incident summarization to structured security events."
    ),
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/analyze", response_model=AnalysisResult)
def analyze(batch: LogBatch) -> AnalysisResult:
    findings = run_detectors(batch.events)
    score = calculate_risk_score(findings)
    return AnalysisResult(
        total_events=len(batch.events),
        risk_score=score,
        risk_level=risk_level(score),
        findings=findings,
        incident_summary=build_incident_summary(findings),
        recommended_actions=build_recommended_actions(findings),
    )
