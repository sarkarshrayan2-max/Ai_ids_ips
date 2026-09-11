# AI Sentinel IDS/IPS

AI Sentinel is a hybrid AI-powered Intrusion Detection and Prevention System (IDS/IPS) that combines supervised machine learning, unsupervised anomaly detection, behavioral analysis, historical context, risk fusion, incident correlation, and simulated IPS response.

The system is designed as a security-focused prototype for detecting four network-flow classes:

* Normal
* Port Scan
* Brute Force
* DDoS

The live demonstration uses synthetic network flows, while the machine-learning pipeline also includes independent validation against the CIC-IDS2017 dataset.

The IPS component is intentionally operated in simulation mode. A `BLOCK` decision records the source as blocked in SQLite but does not modify the host operating system firewall.

---

# 1. Architecture

## High-Level Architecture

```text
                         AI SENTINEL IDS/IPS
                                |
                                v
                    +-------------------------+
                    |    Streamlit Dashboard   |
                    |     dashboard/app.py    |
                    +------------+------------+
                                 |
                                 v
                    +-------------------------+
                    | Synthetic Traffic       |
                    | Generator                |
                    |                         |
                    | Normal                   |
                    | Port Scan                |
                    | Brute Force              |
                    | DDoS                     |
                    +------------+------------+
                                 |
                                 v
                    +-------------------------+
                    | Detection Engine         |
                    | detection_engine.py      |
                    +------------+------------+
                                 |
             +-------------------+-------------------+
             |                   |                   |
             v                   v                   v
      +-------------+    +---------------+    +-------------+
      |   XGBoost   |    | Isolation     |    | Behavioral |
      | Classifier  |    | Forest        |    | Engine     |
      +------+------+    +-------+-------+    +------+------+
             |                   |                   |
             | Prediction        | Anomaly Score     | Behavior
             | Confidence        |                   | Score
             |                   |                   |
             +-------------------+-------------------+
                                 |
                                 v
                    +-------------------------+
                    | Historical Context      |
                    | Recent source activity  |
                    +------------+------------+
                                 |
                                 v
                    +-------------------------+
                    | Risk Engine              |
                    | risk_engine.py           |
                    |                         |
                    | Risk Fusion              |
                    +------------+------------+
                                 |
                                 v
                    +-------------------------+
                    | Risk Score 0 - 100      |
                    +------------+------------+
                                 |
             +-------------------+-------------------+
             |                   |                   |
             v                   v                   v
          LOW                 MEDIUM                HIGH
          ALLOW               MONITOR               ALERT
                                                     |
                                                     v
                                               CRITICAL
                                                     |
                                                     v
                                                  BLOCK
                                                     |
                                                     v
                    +-------------------------+
                    | Incident Correlation    |
                    | incident_engine.py      |
                    +------------+------------+
                                 |
                                 v
                    +-------------------------+
                    | IPS Controller           |
                    | ips_controller.py       |
                    |                         |
                    | SIMULATION MODE         |
                    +------------+------------+
                                 |
                                 v
                    +-------------------------+
                    | SQLite Persistence       |
                    | ids_ips.db              |
                    +-------------------------+
```

---

# 2. Detection Pipeline

Every network flow follows this pipeline:

```text
Network Flow
     |
     v
Feature Extraction
     |
     +------------------------+
     |                        |
     v                        v
XGBoost                  Isolation Forest
     |                        |
     v                        v
Prediction              Raw anomaly score
Confidence                    |
                              v
                       Calibration
                              |
                              v
                       Anomaly score
     |                        |
     +------------+-----------+
                  |
                  v
          Behavioral Analysis
                  |
                  v
           Behavior Score
                  |
                  v
          Historical Context
                  |
                  v
             Risk Fusion
                  |
                  v
            Risk Score
                  |
                  v
        Severity + Action
                  |
                  v
       Incident Correlation
                  |
                  v
          IPS Simulation
                  |
                  v
          SQLite Recording
                  |
                  v
             Dashboard
```

---

# 3. Repository Structure

The current repository contains:

```text
ai-ids-ips/
│
├── .gitignore
├── .python-version
├── README.md
├── pyproject.toml
├── uv.lock
├── main.py
│
├── dashboard/
│   └── app.py
│
├── models/
│   ├── anomaly_calibration.json
│   ├── cic_metrics.json
│   └── metrics.json
│
├── src/
│   ├── __init__.py
│   │
│   ├── capture/
│   │   ├── __init__.py
│   │   └── traffic_generator.py
│   │
│   ├── database/
│   │   ├── __init__.py
│   │   └── db.py
│   │
│   ├── detection/
│   │   ├── __init__.py
│   │   ├── detection_engine.py
│   │   ├── explainability.py
│   │   ├── incident_engine.py
│   │   └── risk_engine.py
│   │
│   ├── ml/
│   │   ├── __init__.py
│   │   ├── evaluate_cic_ids2017.py
│   │   ├── evaluate_cic_scenario.py
│   │   ├── generate.py
│   │   ├── train_cic_model.py
│   │   └── train_models.py
│   │
│   └── security/
│       ├── __init__.py
│       └── ips_controller.py
│
└── tests/
    ├── test_adversarial_detection.py
    ├── test_attack_chain.py
    ├── test_calibration_failure.py
    ├── test_closed_incident_isolation.py
    ├── test_database_failure.py
    ├── test_database_recovery.py
    ├── test_detection_robustness.py
    ├── test_incident_isolation.py
    ├── test_incident_time_window.py
    ├── test_invalid_flow.py
    ├── test_ips_failure.py
    ├── test_ips_recovery.py
    ├── test_misclassification_resilience.py
    ├── test_model_failure.py
    └── test_risk_engine.py
```

The trained `.pkl` model artifacts are intentionally excluded from Git by `.gitignore`.

---

# 4. Technology Stack

## Language

* Python 3.11+

The project declares:

```toml
requires-python = ">=3.11"
```

## Machine Learning

* XGBoost
* Scikit-learn
* Isolation Forest
* StandardScaler
* LabelEncoder
* Joblib

## Data Processing

* Pandas
* NumPy

## Network Simulation

* Scapy dependency
* Synthetic network-flow generator

## Dashboard

* Streamlit
* Plotly

## Persistence

* SQLite

## Testing

* Pytest

## Package Management

* uv
* `pyproject.toml`
* `uv.lock`

---

# 5. Installation

Clone the repository:

```powershell
git clone <repository-url>
cd ai-ids-ips
```

The project requires Python 3.11 or newer.

If using the existing environment:

```powershell
conda activate ai-ids-ips
```

Install the project dependencies:

```powershell
uv sync
```

Alternatively, if using pip:

```powershell
pip install -e .
```

For development/testing dependencies:

```powershell
uv sync --dev
```

---

# 6. Initialize the Database

The project uses SQLite.

The database file is:

```text
ids_ips.db
```

It is created in the repository root when `init_db()` runs.

Initialize it with:

```powershell
python main.py
```

Expected output:

```text
AI Sentinel IDS/IPS initialized.
```

The database contains three primary tables:

```text
flow_events
incidents
blocked_sources
```

---

# 7. Database Architecture

## flow_events

Stores individual analyzed network flows.

The table contains:

```text
id
timestamp
source_ip
destination_ip
source_port
destination_port
protocol
duration
packet_count
byte_count
packets_per_sec
bytes_per_sec
protocol_tcp
ml_prediction
ml_confidence
anomaly_score
behavior_score
history_score
risk_score
severity
action
incident_id
```

---

## incidents

Stores correlated security incidents.

Fields:

```text
id
incident_id
source_ip
first_seen
last_seen
event_count
max_risk
attack_types
status
action
```

Incidents are correlated by source IP and time window.

---

## blocked_sources

Stores simulated IPS blocking decisions.

Fields:

```text
id
source_ip
reason
risk_score
blocked_at
status
```

A source is considered blocked when:

```text
status = BLOCKED
```

---

# 8. No REST API

The current repository does not implement FastAPI or REST endpoints.

There are therefore no routes such as:

```text
/api/detect
/api/incidents
/api/block
```

The application interface is the Streamlit dashboard.

The detection functionality is exposed internally through Python functions, primarily:

```python
analyze_and_record_flow(flow)
```

from:

```text
src/detection/detection_engine.py
```

---

# 9. Starting the Dashboard

Run:

```powershell
streamlit run dashboard/app.py
```

Streamlit will start the dashboard and display the local URL in the terminal.

The dashboard provides:

* Attack Simulator
* Single Event simulation
* Attack Burst simulation
* SOC statistics
* Threat timeline
* Threat distribution
* Risk distribution
* Incident correlation
* Recent network events
* AI Decision Inspector
* Detection Evidence
* IPS Quarantine
* Detection Summary
* Latest Detection Result

---

# 10. Dashboard Controls

The left sidebar contains the attack simulator.

## Single Event

Available event types:

```text
Normal
DDoS
Port Scan
Brute Force
```

Selecting one generates a synthetic flow and immediately sends it through the detection pipeline.

---

## Attack Burst

The dashboard supports:

```text
DDoS
Port Scan
Brute Force
```

The number of flows can be selected from:

```text
1 - 30
```

The generated flows use the same attacker source IP so that incident correlation can group them.

---

## Clear SOC Data

The dashboard provides:

```text
Clear SOC Data
```

This deletes:

```text
flow_events
incidents
blocked_sources
```

from SQLite.

---

# 11. Synthetic Traffic Generator

The implementation is located at:

```text
src/capture/traffic_generator.py
```

The generator creates four types of traffic.

## Normal

Normal traffic uses:

* Duration: approximately 1-15 seconds
* Packet rate target: capped at 250 packets/sec
* 5-119 packets
* Destination ports:

  * 80
  * 443
  * 53
  * 22
  * 8080
* TCP or UDP

---

## Port Scan

Port Scan traffic uses:

* Duration: approximately 0.001-0.1 seconds
* 1-4 packets
* Random destination port
* TCP
* Short-duration probing behavior

This produces the behavioral indicator:

```text
Rapid probe pattern
```

when the corresponding conditions are met.

---

## Brute Force

Brute Force traffic uses:

* Duration: approximately 2-30 seconds
* 200-800 packets
* Destination ports:

  * 21
  * 22
  * 3389
* TCP

This produces:

```text
Credential-service interaction
```

when the behavioral thresholds are satisfied.

---

## DDoS

DDoS traffic uses:

* Duration: approximately 0.01-1.5 seconds
* 1,500-10,000 packets
* Destination ports:

  * 80
  * 443
* TCP

This creates high packet-rate and bandwidth behavior.

---

# 12. Machine-Learning Features

The live model uses exactly seven features:

```text
destination_port
duration
packet_count
byte_count
packets_per_sec
bytes_per_sec
protocol_tcp
```

These features are used by both the supervised classifier and the anomaly detector.

---

# 13. XGBoost Model

The live model is:

```text
XGBClassifier
```

The current model is trained using:

```text
n_estimators = 220
max_depth = 6
learning_rate = 0.08
subsample = 0.9
colsample_bytree = 0.9
objective = multi:softprob
eval_metric = mlogloss
random_state = 42
```

The classifier predicts:

```text
Normal
DDoS
Port Scan
Brute Force
```

The model outputs class probabilities.

The highest probability determines:

```text
ML Prediction
```

and its probability becomes:

```text
ML Confidence
```

---

# 14. Isolation Forest

The anomaly detector is:

```text
IsolationForest
```

with:

```text
n_estimators = 200
contamination = 0.03
random_state = 42
```

The Isolation Forest is trained only on Normal training samples.

This allows the anomaly detector to learn the expected normal traffic distribution.

---

# 15. Anomaly Calibration

Raw Isolation Forest scores are converted into a normalized anomaly score between:

```text
0.0 - 1.0
```

The stored calibration is:

```json
{
  "low_score": -0.6261537202615004,
  "high_score": -0.3988883051789054,
  "normal_false_positive_percentile": 2.5,
  "calibration_samples": 15529,
  "calibration_method": "normal_train_percentiles"
}
```

The calibration range is derived from Normal training data.

The 2.5th percentile is used as the low calibration boundary.

---

# 16. Behavioral Detection

Behavioral analysis is implemented in:

```text
src/detection/risk_engine.py
```

The detector examines:

```text
packets_per_sec
bytes_per_sec
duration
packet_count
destination_port
```

Behavioral indicators include:

### Extreme packet-rate surge

```text
packets_per_sec >= 2000
```

Adds:

```text
0.50
```

---

### High packet-rate surge

```text
packets_per_sec >= 500
```

Adds:

```text
0.30
```

---

### Elevated packet rate

```text
packets_per_sec >= 100
```

Adds:

```text
0.12
```

---

### High bandwidth utilization

```text
bytes_per_sec >= 5,000,000
```

Adds:

```text
0.20
```

---

### Elevated bandwidth utilization

```text
bytes_per_sec >= 1,000,000
```

Adds:

```text
0.10
```

---

### Rapid probe pattern

Triggered when:

```text
packet_count <= 5
duration < 0.1
destination_port > 1024
```

Adds:

```text
0.28
```

---

### Credential-service interaction

Triggered when:

```text
destination_port in {21, 22, 3389}
duration >= 2
packet_count > 150
```

Adds:

```text
0.22
```

The final behavior score is capped at:

```text
1.0
```

---

# 17. Historical Context

The detection engine calculates a historical score from recent suspicious activity for the same source IP.

The history window is:

```text
10 minutes
```

Suspicious events are those where:

```text
risk_score >= 35
```

and:

```text
ml_prediction != Normal
```

The historical score combines:

```text
Suspicious event count
+
Maximum previous risk
```

The result is normalized to:

```text
0.0 - 1.0
```

---

# 18. Risk Fusion

The risk engine combines four signals:

```text
ML classification
Anomaly detection
Behavioral analysis
Historical evidence
```

Current weights:

```text
ML_WEIGHT       = 50.0
ANOMALY_WEIGHT  = 20.0
BEHAVIOR_WEIGHT = 20.0
HISTORY_WEIGHT  = 10.0
```

The base weighted risk is:

```text
classification_signal × 50
+
anomaly_score × 20
+
behavior_score × 20
+
history_score × 10
```

---

# 19. Classification Weights

The classifier contributes according to the predicted class:

```text
Normal       = 0.00
Port Scan    = 0.62
Brute Force  = 0.78
DDoS         = 0.95
```

The classification signal is:

```text
attack_weight × ML_confidence
```

This means an ML prediction of DDoS contributes more to risk than a prediction of Port Scan.

---

# 20. Independent Attack Evidence

The risk engine does not rely exclusively on the ML classification.

Independent evidence uses:

```text
INDEPENDENT_ANOMALY_WEIGHT  = 75.0
INDEPENDENT_BEHAVIOR_WEIGHT = 100.0
```

This is important for ML misclassification resilience.

For example:

```text
ML Prediction:
Normal

Anomaly:
0.90

Behavior:
0.70
```

can still result in:

```text
CRITICAL
BLOCK
```

rather than allowing the ML classifier to override strong attack evidence.

---

# 21. Normal False-Positive Protection

Moderate anomaly scores for a Normal prediction are dampened.

For:

```text
Normal
```

with anomaly below:

```text
0.85
```

the independent anomaly component uses:

```text
anomaly_score² × 30
```

rather than directly applying the full independent anomaly weight.

This prevents moderately anomalous Normal traffic from automatically becoming high risk.

However, once the anomaly becomes strong:

```text
anomaly_score >= 0.85
```

the independent anomaly weight is restored.

---

# 22. Misclassification Resilience

A key security property is:

```text
ML says Normal
+
Strong independent evidence
=
Attack can still be escalated
```

For example:

```text
ML Prediction: Normal
ML Confidence: 0.99
Anomaly:       0.90
Behavior:      0.70
History:       0.00
```

The risk engine produces a CRITICAL-level result.

This prevents a single incorrect classifier prediction from suppressing strong independent attack evidence.

---

# 23. Risk Thresholds

The final risk score is normalized to:

```text
0 - 100
```

Decision thresholds:

| Risk Score | Severity | Action  |
| ---------: | -------- | ------- |
|       0-34 | LOW      | ALLOW   |
|      35-64 | MEDIUM   | MONITOR |
|      65-84 | HIGH     | ALERT   |
|     85-100 | CRITICAL | BLOCK   |

---

# 24. DDoS Override

A DDoS prediction receives an explicit high-risk protection condition.

If:

```text
prediction = DDoS
ML confidence >= 0.90
anomaly score >= 0.85
```

the risk is forced to at least:

```text
85
```

which produces:

```text
CRITICAL
BLOCK
```

---

# 25. Incident Correlation

Incident correlation is implemented in:

```text
src/detection/incident_engine.py
```

The correlation window is:

```text
10 minutes
```

Events are grouped by:

```text
source_ip
+
OPEN incident
+
last_seen within 10 minutes
```

A new incident receives an ID in the format:

```text
INC-YYYYMMDD-XXXXXX
```

Example:

```text
INC-20260911-A1B2C3
```

---

# 26. Attack Chain

When multiple attack stages originate from the same source within the correlation window, they can be represented as an attack chain.

Example:

```text
Port Scan
     |
     v
Brute Force
     |
     v
DDoS
```

The incident stores:

```text
event_count
max_risk
attack_types
status
action
```

The dashboard displays the chain as:

```text
Port Scan → Brute Force → DDoS
```

The same attack type is not duplicated in the stored attack list.

---

# 27. Incident Isolation

The incident engine prevents unrelated sources from being merged.

For example:

```text
Source A
Port Scan
```

and:

```text
Source B
Brute Force
```

produce separate incidents.

A closed incident also cannot receive later events.

An incident outside the 10-minute correlation window results in a new incident.

---

# 28. IPS Controller

IPS functionality is implemented in:

```text
src/security/ips_controller.py
```

The detection engine creates:

```python
IPSController(
    enforcement_mode=False
)
```

Therefore the current application runs in simulation mode.

When a critical event generates:

```text
BLOCK
```

the controller records the source in:

```text
blocked_sources
```

and returns:

```text
SIMULATED_BLOCK
```

No operating-system firewall rule is changed.

---

# 29. IPS Enforcement Modes

The controller supports two logical modes.

Simulation:

```text
enforcement_mode=False
```

returns:

```text
SIMULATED_BLOCK
```

Enforcement:

```text
enforcement_mode=True
```

returns:

```text
ENFORCED_BLOCK
```

The current application deliberately initializes the controller with:

```text
enforcement_mode=False
```

Therefore the current repository should be described as:

```text
IPS Simulation
```

rather than a production firewall enforcement system.

---

# 30. Explainability

Explainability is implemented in:

```text
src/detection/explainability.py
```

The system can produce explanations based on:

* ML classification
* ML confidence
* Packet rate
* Bandwidth
* Port behavior
* Rapid probing
* Authentication-service traffic
* Anomaly score
* Behavior score
* Historical score

Example explanation:

```text
XGBoost classified the flow as DDoS with 97.0% confidence.
```

or:

```text
Extreme traffic volume detected.
```

or:

```text
Isolation Forest identified anomalous behavior.
```

These explanations are displayed in the dashboard's AI Decision Inspector.

---

# 31. Dashboard Architecture

The Streamlit dashboard reads directly from SQLite.

```text
                  SQLite
                     |
       +-------------+-------------+
       |             |             |
       v             v             v
  flow_events    incidents    blocked_sources
       |             |             |
       +-------------+-------------+
                     |
                     v
              Streamlit Dashboard
                     |
       +-------------+-------------+
       |             |             |
       v             v             v
   SOC Metrics   Timeline      Incidents
       |
       +-------------------------------+
       |                               |
       v                               v
 AI Decision Inspector           IPS Quarantine
```

---

# 32. Dashboard Sections

The dashboard currently contains:

## SOC Overview

Displays:

```text
Flows
Threats
Anomalies
Critical
Open Incidents
Blocked Sources
```

---

## System Status

Displays:

```text
Detection Engine
Database
IPS
Live Model
```

The database status is:

```text
SQLite event and incident persistence
```

The IPS status is:

```text
SIMULATION
```

The live model is:

```text
XGBoost
Synthetic traffic demonstration model
```

---

## Live Threat Timeline

Plots risk over time.

Thresholds displayed:

```text
35 = MONITOR
65 = HIGH
85 = CRITICAL / BLOCK
```

---

## Threat Distribution

Displays the distribution of detected attack classes.

---

## Risk Distribution

Displays the distribution of risk scores.

---

## Incident Correlation

Displays:

```text
Incident
Source
Attack Chain
Events
Risk
Status
Action
First Seen
Last Seen
```

---

## Recent Network Events

Displays:

```text
ID
Timestamp
Source
Destination Port
Prediction
ML Confidence
Anomaly
Behavior
History
Risk
Severity
Action
Incident
```

---

## AI Decision Inspector

Allows an event to be selected and displays:

```text
Final Risk Score
Prediction
Action
XGBoost confidence
Anomaly
Behavior
History
Incident
```

It also displays the risk-fusion evidence and detection explanation.

---

## IPS Quarantine

Displays simulated blocked sources:

```text
Source
Reason
Risk
Blocked At
Status
```

---

# 33. Synthetic Model Evaluation

The repository contains:

```text
models/metrics.json
```

The stored evaluation is:

```text
Dataset:
synthetic_flow_dataset

Evaluation:
synthetic_holdout

Samples:
30,000
```

Metrics:

| Metric          |   Result |
| --------------- | -------: |
| Accuracy        | 99.9833% |
| Macro Precision | 99.9936% |
| Macro Recall    | 99.9578% |
| Macro F1        | 99.9757% |

Per-class results:

| Class       | Precision |    Recall |        F1 |
| ----------- | --------: | --------: | --------: |
| Normal      |  99.9742% | 100.0000% |  99.9871% |
| DDoS        | 100.0000% | 100.0000% | 100.0000% |
| Port Scan   | 100.0000% | 100.0000% | 100.0000% |
| Brute Force | 100.0000% |  99.8314% |  99.9156% |

These are synthetic hold-out results and should not be interpreted as real-world network performance.

---

# 34. CIC-IDS2017 Validation

The repository also contains:

```text
models/cic_metrics.json
```

The stored evaluation contains:

```text
Dataset:
CIC-IDS2017

Evaluated samples:
2,573,488
```

The reported metrics are:

| Metric          |   Result |
| --------------- | -------: |
| Accuracy        | 99.8918% |
| Macro Precision | 99.6223% |
| Macro Recall    | 97.5663% |
| Macro F1        | 98.5438% |

Per-class metrics:

| Class       | Precision |   Recall |       F1 |
| ----------- | --------: | -------: | -------: |
| Normal      |  99.9274% | 99.9516% | 99.9395% |
| DDoS        |  99.9492% | 99.8594% | 99.9043% |
| Port Scan   |  99.3990% | 99.9717% | 99.6845% |
| Brute Force |  99.2137% | 90.4824% | 94.6471% |

The Brute Force class has noticeably lower recall than the other classes.

This is important when presenting the results: the system should report the complete metrics rather than only highlighting accuracy.

---

# 35. CIC-IDS2017 Evaluation Script

The primary evaluation script is:

```text
src/ml/evaluate_cic_ids2017.py
```

It expects CIC-IDS2017 CSV files in:

```text
C:\Users\sarkar\Downloads\MachineLearningCVE
```

This path is currently hard-coded in the repository.

The script maps CIC labels to the four project classes:

```text
BENIGN
    -> Normal

DDoS
    -> DDoS

PortScan
    -> Port Scan

FTP-Patator
    -> Brute Force

SSH-Patator
    -> Brute Force

Web Attack – Brute Force
    -> Brute Force
```

The evaluation uses the seven project features.

Run:

```powershell
python -m src.ml.evaluate_cic_ids2017
```

The script loads:

```text
models/xgboost_model.pkl
models/scaler.pkl
models/label_encoder.pkl
```

and evaluates the available CIC-IDS2017 CSV files.

---

# 36. Scenario-Aware CIC Evaluation

The repository also contains:

```text
src/ml/evaluate_cic_scenario.py
```

This evaluation uses the following CIC files:

```text
Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
Friday-WorkingHours-Morning.pcap_ISCX.csv
Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
Tuesday-WorkingHours.pcap_ISCX.csv
```

Each file is split chronologically:

```text
80% training
20% testing
```

The script trains a scenario-aware XGBoost classifier using:

```text
n_estimators = 300
max_depth = 7
learning_rate = 0.05
subsample = 0.9
colsample_bytree = 0.9
random_state = 42
```

Run:

```powershell
python -m src.ml.evaluate_cic_scenario
```

---

# 37. Generating the Synthetic Dataset

Synthetic training data is generated by:

```text
src/ml/generate.py
```

Default number of samples:

```text
30,000
```

Class distribution:

```text
Normal       65%
DDoS         15%
Port Scan    10%
Brute Force  10%
```

The output is:

```text
data/sample/flow_dataset.csv
```

Run:

```powershell
python -m src.ml.generate
```

The generated CSV is ignored by Git because:

```text
data/sample/*.csv
```

is included in `.gitignore`.

---

# 38. Training the Live Models

Training is implemented in:

```text
src/ml/train_models.py
```

Before training, generate the synthetic dataset:

```powershell
python -m src.ml.generate
```

Then train:

```powershell
python -m src.ml.train_models
```

The training process:

```text
Synthetic CSV
     |
     v
Feature Validation
     |
     v
Train/Test Split
     |
     v
StandardScaler
     |
     +---------------------+
     |                     |
     v                     v
XGBoost              Isolation Forest
     |                     |
     |                     v
     |                Normal samples
     |                     |
     +----------+----------+
                |
                v
          Model Artifacts
```

The split is:

```text
80% training
20% testing
```

with:

```text
random_state = 42
stratify = labels
```

---

# 39. Generated Model Artifacts

Training generates:

```text
models/
├── xgboost_model.pkl
├── scaler.pkl
├── label_encoder.pkl
├── isolation_forest.pkl
├── training_metrics.pkl
└── anomaly_calibration.json
```

The `.pkl` files are ignored by Git.

The detection engine expects the live artifacts:

```text
xgboost_model.pkl
scaler.pkl
label_encoder.pkl
isolation_forest.pkl
```

---

# 40. Running the Complete Demo

Recommended sequence:

## 1. Activate the environment

```powershell
conda activate ai-ids-ips
```

## 2. Initialize SQLite

```powershell
python main.py
```

## 3. Start the dashboard

```powershell
streamlit run dashboard/app.py
```

## 4. Open the Streamlit interface

Use the local URL shown by Streamlit.

## 5. Clear previous data

Click:

```text
Clear SOC Data
```

## 6. Run Normal

Select:

```text
Normal
```

Expected behavior:

```text
Normal
LOW
ALLOW
```

## 7. Run Port Scan

Select:

```text
Port Scan
```

Expected behavior:

```text
Port Scan
Risk >= 35
MONITOR / ALERT / BLOCK depending on evidence
```

## 8. Run Brute Force

Select:

```text
Brute Force
```

Expected behavior:

```text
Brute Force
Risk >= 35
```

## 9. Run DDoS

Select:

```text
DDoS
```

Expected behavior:

```text
DDoS
CRITICAL
BLOCK
```

## 10. Inspect the incident

The incident table should show the correlated attack activity.

The attack chain can appear as:

```text
Port Scan → Brute Force → DDoS
```

## 11. Inspect IPS Quarantine

The source should appear as:

```text
BLOCKED
```

with:

```text
SIMULATED_BLOCK
```

No firewall rule is modified.

---

# 41. Testing

Run the full test suite:

```powershell
pytest -q
```

The current validated local repository state contains:

```text
21 passed
```

The tests cover:

```text
Risk engine
Detection robustness
Adversarial detection
Attack chain
Incident isolation
Incident time windows
Closed incident handling
Database failure
Database recovery
IPS failure
IPS recovery
Model failure
Calibration failure
Invalid flow handling
ML misclassification resilience
```

---

# 42. Important Risk-Engine Tests

The risk engine explicitly tests:

## Normal with weak evidence

```text
Normal
0.99 confidence
0.05 anomaly
0.05 behavior
```

Expected:

```text
LOW
ALLOW
```

---

## Normal with strong anomaly

```text
Normal
0.99 confidence
0.90 anomaly
0.05 behavior
```

Expected:

```text
HIGH
ALERT
```

---

## Normal with strong behavior

```text
Normal
0.99 confidence
0.05 anomaly
0.70 behavior
```

Expected:

```text
HIGH
ALERT
```

---

## Normal with strong combined evidence

```text
Normal
0.99 confidence
0.90 anomaly
0.70 behavior
```

Expected:

```text
CRITICAL
BLOCK
```

---

## Brute Force classification

```text
Brute Force
0.90 confidence
0.10 anomaly
0.10 behavior
```

Expected:

```text
MEDIUM
MONITOR
```

---

# 43. Failure Handling

The project explicitly tests failure conditions.

## Database failure

A database failure is surfaced instead of silently ignored.

---

## Database recovery

After a simulated database failure, the system can recover and successfully record later events.

---

## Model failure

The system detects a missing XGBoost model artifact.

---

## Calibration failure

Invalid anomaly calibration values cause a `ValueError`.

---

## IPS failure

IPS database failures are surfaced.

After recovery, simulated blocking works again.

---

## Invalid flow

Missing required model features cause validation failure rather than allowing malformed data through the detection pipeline.

---

# 44. Git Ignore Policy

The repository ignores:

```text
__pycache__/
*.py[oc]
build/
dist/
wheels/
*.egg-info
.venv
*.pyc
*.db
ids_ips.db
data/sample/*.csv
models/*.pkl
.env
```

Therefore:

* SQLite database files are not committed.
* Generated synthetic datasets are not committed.
* Trained model binaries are not committed.
* Environment files are not committed.

---

# 45. Current Model Architecture

The current live architecture is deliberately hybrid:

```text
                 Network Flow
                      |
          +-----------+-----------+
          |                       |
          v                       v
      XGBoost               Isolation Forest
          |                       |
          v                       v
     ML Prediction          Anomaly Score
     ML Confidence
          |                       |
          +-----------+-----------+
                      |
                      v
              Behavioral Engine
                      |
                      v
               Behavior Score
                      |
                      v
             Historical Score
                      |
                      v
                Risk Engine
                      |
                      v
             Risk Score 0-100
                      |
                      v
             Severity + Action
                      |
             +--------+--------+
             |                 |
             v                 v
          Incident          IPS
         Correlation       Simulation
```

The important architectural property is that no single detector is responsible for the final security decision.

---

# 46. Why Hybrid Detection?

The three main detection signals have different responsibilities.

## XGBoost

Answers:

```text
What attack class does this flow most resemble?
```

---

## Isolation Forest

Answers:

```text
How unusual is this flow compared with learned normal traffic?
```

---

## Behavioral Engine

Answers:

```text
Does this flow exhibit known suspicious network behavior?
```

---

## Historical Context

Answers:

```text
Has this source recently generated suspicious activity?
```

---

## Risk Engine

Answers:

```text
How serious is the combined evidence?
```

---

# 47. Security Decision Philosophy

The project follows:

```text
Classification
     +
Independent Evidence
     +
Context
     =
Security Decision
```

This avoids two major problems.

### False-positive problem

Moderately unusual Normal traffic should not automatically become a critical event.

### Misclassification problem

An incorrect `Normal` ML prediction should not suppress strong anomaly and behavioral evidence.

---

# 48. Limitations

This repository is a prototype and should not be presented as a production IDS/IPS.

## Synthetic live traffic

The dashboard's live traffic simulator generates synthetic flows.

It does not currently perform full production packet capture and real-time flow extraction.

---

## IPS simulation

The IPS records block decisions in SQLite.

It does not currently modify:

* iptables
* Windows Firewall
* nftables
* cloud security groups
* network ACLs

---

## SQLite

SQLite is appropriate for this prototype but is not a replacement for a production distributed event store.

---

## Hard-coded CIC dataset path

The CIC-IDS2017 evaluation scripts currently use:

```text
C:\Users\sarkar\Downloads\MachineLearningCVE
```

This path must be changed when running the evaluation on another machine.

---

## Synthetic model metrics

The synthetic dataset is intentionally generated from controlled distributions.

Therefore:

```text
99.98% synthetic accuracy
```

should not be interpreted as equivalent to production detection accuracy.

---

## CIC-IDS2017 limitations

CIC-IDS2017 provides benchmark validation but does not represent every modern network environment or attack type.

The lower Brute Force recall demonstrates that even strong aggregate metrics can hide class-specific weaknesses.

---

# 49. Recommended Hackathon Presentation

A concise demonstration should follow this sequence:

```text
1. Show architecture
2. Start dashboard
3. Show Normal traffic
4. Trigger Port Scan
5. Trigger Brute Force
6. Trigger DDoS
7. Show risk escalation
8. Show incident attack chain
9. Show CRITICAL / BLOCK
10. Show IPS SIMULATION
11. Show AI Decision Inspector
12. Show CIC-IDS2017 validation
13. Show 21/21 tests
```

The key story is:

```text
Detect
  ↓
Correlate
  ↓
Assess Risk
  ↓
Escalate
  ↓
Simulate Prevention
```

---

# 50. Recommended Demo Statement

The system can be described during a presentation as:

> AI Sentinel is a hybrid AI intrusion detection and prevention prototype that combines supervised classification, unsupervised anomaly detection, behavioral analysis, and historical context. These signals are fused into a normalized risk score, correlated into incidents, and converted into simulated IPS actions. The live dashboard uses controlled synthetic traffic for demonstration, while CIC-IDS2017 is used as an independent validation dataset.

---

# 51. Current Repository Status

Current validated capabilities:

```text
XGBoost Classification             READY
Isolation Forest                   READY
Anomaly Calibration                READY
Behavioral Detection               READY
Historical Risk                    READY
Risk Fusion                        READY
Normal False-Positive Protection   READY
Misclassification Resilience       READY
Incident Correlation               READY
Attack Chain                       READY
Incident Isolation                 READY
IPS Simulation                     READY
Failure Handling                   TESTED
Synthetic Evaluation               AVAILABLE
CIC-IDS2017 Evaluation             AVAILABLE
Streamlit Dashboard                READY
Automated Test Suite               PASSING
```

Current validated local test result:

```text
21 passed
```

Current risk-fusion commit:

```text
3eeae43 fix risk fusion for normal false positives
```

---

# 52. Development Commands

Generate synthetic data:

```powershell
python -m src.ml.generate
```

Train models:

```powershell
python -m src.ml.train_models
```

Run CIC-IDS2017 evaluation:

```powershell
python -m src.ml.evaluate_cic_ids2017
```

Run scenario-aware evaluation:

```powershell
python -m src.ml.evaluate_cic_scenario
```

Initialize the database:

```powershell
python main.py
```

Start the dashboard:

```powershell
streamlit run dashboard/app.py
```

Run tests:

```powershell
pytest -q
```

Check repository state:

```powershell
git status
```

View recent commits:

```powershell
git log --oneline -5
```

---

# 53. End-to-End Architecture Summary

```text
                    +-------------------+
                    | Streamlit UI      |
                    +---------+---------+
                              |
                              v
                    +-------------------+
                    | Traffic Simulator  |
                    +---------+---------+
                              |
                              v
                    +-------------------+
                    | Detection Engine   |
                    +---------+---------+
                              |
             +----------------+----------------+
             |                |                |
             v                v                v
         XGBoost        Isolation Forest   Behavior Rules
             |                |                |
             v                v                v
        Prediction        Anomaly Score    Behavior Score
             |                |                |
             +----------------+----------------+
                              |
                              v
                     Historical Context
                              |
                              v
                       Risk Fusion
                              |
                              v
                       Risk 0 - 100
                              |
                              v
                    Severity + Action
                              |
                +-------------+-------------+
                |                           |
                v                           v
        Incident Correlation          IPS Controller
                |                           |
                v                           v
             SQLite                 SIMULATED_BLOCK
                |
       +--------+---------+
       |        |         |
       v        v         v
    Events   Incidents  Blocks
       |        |         |
       +--------+---------+
                |
                v
          Streamlit Dashboard
```

---

# 54. Final Notes

AI Sentinel is intentionally designed around a small number of complementary detection mechanisms rather than a large collection of loosely integrated components.

The core security path is:

```text
XGBoost
    +
Isolation Forest
    +
Behavior
    +
History
    ↓
Risk Fusion
    ↓
Incident Correlation
    ↓
IPS Simulation
```

The current implementation prioritizes:

* Multiple independent detection signals
* False-positive control
* Misclassification resilience
* Risk-based escalation
* Incident correlation
* Failure testing
* Transparent detection evidence
* Safe IPS simulation
* Reproducible synthetic evaluation
* Independent CIC-IDS2017 validation

For production deployment, the system would require real packet/flow ingestion, stronger infrastructure, production persistence, authentication, monitoring, model governance, and a separately tested firewall enforcement layer.
