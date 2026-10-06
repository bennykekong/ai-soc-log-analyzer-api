# 🛡️ AI-Powered SOC Log Analyzer API

**Python + FastAPI cybersecurity project for automated security-log analysis, threat detection, risk scoring, incident summarization, and SOC analyst recommendations.**

This project demonstrates how Python can be used to transform structured security events into actionable SOC findings using transparent detection rules and an automated CI testing pipeline.

---

## 🔎 Project Overview

The **AI-Powered SOC Log Analyzer API** accepts batches of structured security events and analyzes them for potentially suspicious activity.

The analyzer currently detects:

- Repeated failed-login attempts
- Possible port-scanning activity
- Suspicious outbound network connections

After analyzing the events, the API:

1. Generates security findings
2. Assigns severity levels
3. Calculates an overall risk score
4. Determines the risk level
5. Generates an incident summary
6. Recommends investigation actions for a SOC analyst

---

## 🎯 Project Objectives

- Build a cybersecurity analysis API using Python
- Apply SOC-style detection logic to security events
- Detect authentication and network anomalies
- Calculate security risk scores
- Generate incident summaries
- Recommend analyst investigation actions
- Validate incoming data with Pydantic
- Test detection logic using Pytest
- Automate testing with GitHub Actions
- Demonstrate secure software-development practices

---

## 🧰 Technologies Used

- Python
- FastAPI
- Pydantic
- Pytest
- Uvicorn
- GitHub Actions
- REST API
- JSON
- SOC Detection Engineering

---

## 🏗️ Security Analysis Architecture

```text
Security Events
      ↓
Pydantic Data Validation
      ↓
Detection Engine
      ↓
Security Findings
      ↓
Risk Scoring
      ↓
Risk Classification
      ↓
Incident Summary
      ↓
Recommended Analyst Actions
```

---

## 🚨 Detection Rules

### AUTH-001 — Repeated Failed Login Attempts

Detects repeated failed authentication attempts involving the same username and source IP.

Default detection threshold:

```text
5 failed login attempts
within 10 minutes
```

**Severity:** High

Example analyst concern:

- Brute-force attack
- Password spraying
- Compromised credentials
- Unauthorized account-access attempts

---

### NET-001 — Possible Port Scan

Detects a source system contacting multiple unique destination ports within a short time period.

Default detection threshold:

```text
5 unique destination ports
within 60 seconds
```

**Severity:** High

Possible security implications:

- Reconnaissance
- Vulnerability discovery
- Network enumeration
- Pre-attack scanning activity

---

### NET-002 — Suspicious Outbound Connection

Detects outbound network activity involving selected ports commonly associated with suspicious tooling or remote-shell activity.

Monitored ports include:

```text
1337
31337
4444
5555
6667
```

**Severity:** Medium

Possible security implications:

- Command-and-control activity
- Reverse-shell communication
- Unauthorized remote access
- Malware communication

---

## 📊 Risk Scoring

Each finding contributes points based on its severity.

| Severity | Risk Points |
|---|---:|
| Low | 10 |
| Medium | 25 |
| High | 40 |
| Critical | 60 |

The final score is capped at:

```text
100
```

Risk classification:

| Score | Risk Level |
|---|---|
| 0–24 | Low |
| 25–49 | Medium |
| 50–79 | High |
| 80–100 | Critical |

---

## 🌐 API Endpoints

### Health Check

```http
GET /health
```

Example response:

```json
{
  "status": "ok"
}
```

---

### Analyze Security Events

```http
POST /analyze
```

The endpoint accepts a batch of structured security events.

The analyzer returns:

- Total number of events
- Risk score
- Risk level
- Security findings
- Incident summary
- Recommended analyst actions

---

## 📥 Example Security Event

```json
{
  "timestamp": "2026-10-06T12:00:00Z",
  "event_type": "failed_login",
  "source_ip": "203.0.113.25",
  "username": "admin"
}
```

Supported event types:

```text
failed_login
network_connection
firewall_drop
other
```

---

## 📤 Example Analysis Workflow

A group of failed-login events can generate a finding similar to:

```text
Rule: AUTH-001
Title: Repeated failed login attempts
Severity: High
```

Evidence can include:

- Source IP
- Username
- Number of attempts
- Detection time window
- First event observed
- Last event observed

The analyzer then calculates the overall risk score and produces recommended follow-up actions.

---

## 🧠 Incident Summarization

The project automatically creates a summary of detected activity.

For suspicious activity, the summary identifies the number and type of security findings.

If no rule exceeds the configured detection thresholds, the analyzer explains that no rule-based indicator was detected while noting that this does not prove the activity is benign.

---

## 🛡️ Recommended Analyst Actions

Depending on the detected activity, the API can recommend actions such as:

- Review authentication logs
- Check for successful logins after repeated failures
- Validate the affected user account
- Investigate the source IP
- Correlate activity with endpoint telemetry
- Correlate events with firewall and IDS data
- Confirm whether scanning originated from an approved vulnerability scanner
- Investigate suspicious destination IP addresses
- Identify processes responsible for outbound connections
- Check threat-intelligence sources

---

## 📁 Project Structure

```text
ai-soc-log-analyzer-api/
│
├── .github/
│   └── workflows/
│       └── tests.yml
│
├── app/
│   ├── __init__.py
│   ├── detectors.py
│   ├── main.py
│   ├── models.py
│   ├── risk.py
│   └── summarizer.py
│
├── sample_data/
│   ├── README.md
│   └── sample-events.json
│
├── tests/
│   ├── README.md
│   └── test_detectors.py
│
├── .gitignore
├── README.md
└── requirements.txt
```

---

## 🧩 Application Modules

### `main.py`

Provides the FastAPI application and API endpoints.

Main endpoints:

```text
GET /health
POST /analyze
```

---

### `models.py`

Defines validated security-data models using Pydantic.

Models include:

- SecurityEvent
- LogBatch
- Finding
- AnalysisResult

---

### `detectors.py`

Contains the project's threat-detection logic.

Implemented detection functions include:

```text
detect_failed_login_bursts()
detect_port_scans()
detect_suspicious_outbound_ports()
run_detectors()
```

---

### `risk.py`

Calculates cumulative security-risk scores and converts scores into:

```text
Low
Medium
High
Critical
```

---

### `summarizer.py`

Creates:

- Incident summaries
- Recommended analyst actions

based on the findings generated by the detection engine.

---

## 🧪 Automated Testing

The project contains automated tests for its primary detection rules.

Tests currently validate:

- Failed-login burst detection
- Port-scan detection
- Suspicious outbound-port detection

The test suite is executed with:

```bash
python -m pytest -q
```

Current verified result:

```text
3 passed
```

---

## ⚙️ GitHub Actions CI

A GitHub Actions workflow automatically tests the project whenever code is pushed or a pull request is created.

The CI pipeline performs:

```text
Checkout repository
        ↓
Set up Python
        ↓
Install dependencies
        ↓
Run Pytest
        ↓
Validate detection logic
```

Latest verified workflow result:

```text
✅ Checkout repository
✅ Set up Python
✅ Install dependencies
✅ Run tests

3 passed
```

This provides automated verification that the detection engine continues to function after code changes.

---

## 💻 Run the Project Locally

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Start the FastAPI application

```bash
uvicorn app.main:app --reload
```

### 3. Open the API documentation

```text
http://127.0.0.1:8000/docs
```

FastAPI provides an interactive Swagger interface where the `/analyze` endpoint can be tested.

---

## 🧪 Run Tests Locally

```bash
python -m pytest -q
```

Expected result:

```text
3 passed
```

---

## 📂 Sample Security Data

The `sample_data` directory contains sanitized example security events.

The sample dataset can be used to demonstrate how the API processes authentication and network events without exposing real production information.

---

## 🔐 Security Engineering Concepts Demonstrated

This project demonstrates practical understanding of:

- Security log analysis
- SOC operations
- Detection engineering
- Authentication anomaly detection
- Brute-force detection
- Network reconnaissance detection
- Port-scan detection
- Suspicious outbound traffic analysis
- Risk scoring
- Incident triage
- Security-event normalization
- REST API development
- Automated testing
- Continuous Integration
- Secure software-development practices

---

## 📈 Key Takeaways

This project strengthened my ability to combine cybersecurity analysis with Python software engineering.

It demonstrates how repeatable SOC detection logic can be implemented programmatically, exposed through a REST API, validated through automated tests, and continuously tested through GitHub Actions.

Rather than relying only on manual investigation, the application converts structured security telemetry into consistent findings, risk scores, incident summaries and recommended analyst actions.

---

## 🎯 Relevance to Cybersecurity Roles

This project is relevant to roles including:

- Cybersecurity Analyst
- SOC Analyst
- Security Operations Analyst
- Detection Engineer
- Cybersecurity Engineer
- Security Automation Engineer
- Junior Security Engineer
- Python Security Developer

---

## 👨‍💻 Author

**Benard Obi Kekong**

Cybersecurity Analyst | CompTIA Security+ | SOC & GRC | Microsoft Sentinel | SIEM | Python | Risk Assessment & Incident Response
