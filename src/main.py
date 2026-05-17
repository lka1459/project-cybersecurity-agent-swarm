from pathlib import Path
import pandas as pd

from agents.threat_classification_agent import ThreatClassificationAgent
from agents.severity_agent import SeverityAgent
from agents.mitigation_agent import MitigationAgent
from agents.coordinator_agent import CoordinatorAgent


def load_dataset() -> pd.DataFrame:
    project_root = Path(__file__).resolve().parent.parent
    data_path = project_root / "data" / "threat_intel_dataset.jsonl"

    return pd.read_json(data_path, lines=True)

def main() -> None:
    df = load_dataset()

    threat_agent = ThreatClassificationAgent()
    severity_agent = SeverityAgent()
    mitigation_agent = MitigationAgent()

    coordinator = CoordinatorAgent(
        threat_agent=threat_agent,
        severity_agent=severity_agent,
        mitigation_agent=mitigation_agent,
    )

    row_index = 0
    cve_text = df.loc[row_index, "input"]

    report = coordinator.format_report(cve_text)
    print(report)

if __name__ == '__main__':
    main()