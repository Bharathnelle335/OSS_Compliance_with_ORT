import yaml
import json
import pandas as pd
from pathlib import Path

# Define input paths
analyzer_path = Path("ort-output/analyzer/analyzer-result.yml")
advisor_path = Path("ort-output/advisor/advisor-result.yml")
evaluation_path = Path("ort-output/evaluator/evaluation-result.yml")
scanoss_path = Path("ort-output/scanner/scanoss.spdx.json")

# Load YAML and JSON
def load_yaml(path):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

# Load ORT files
analyzer_data = load_yaml(analyzer_path)
advisor_data = load_yaml(advisor_path)
evaluation_data = load_yaml(evaluation_path)

# --- ORT Excel Report ---
components = []
for project in analyzer_data.get("projects", []):
    project_name = project.get("id", "unknown")
    for scope in project.get("scopes", []):
        scope_name = scope.get("name", "unknown")
        for pkg in scope.get("dependencies", []):
            components.append({
                "project": project_name,
                "scope": scope_name,
                "package_id": pkg.get("id", "unknown")
            })

components_df = pd.DataFrame(components)

vulnerabilities = []
for result in advisor_data.get("advisor", {}).get("results", []):
    pkg_id = result.get("id", "unknown")
    for advisor in result.get("advisor", {}).get("issues", []):
        vulnerabilities.append({
            "package_id": pkg_id,
            "vulnerability_id": advisor.get("id", "N/A"),
            "severity": advisor.get("severity", "N/A"),
            "url": advisor.get("references", [{}])[0].get("url", "N/A") if advisor.get("references") else "N/A"
        })

vuln_df = pd.DataFrame(vulnerabilities)

violations = []
for rule_violation in evaluation_data.get("evaluator", {}).get("violations", []):
    violations.append({
        "package_id": rule_violation.get("pkg", {}).get("id", "N/A"),
        "rule": rule_violation.get("rule", "N/A"),
        "severity": rule_violation.get("severity", "N/A"),
        "message": rule_violation.get("message", "N/A")
    })

violations_df = pd.DataFrame(violations)

# Merge ORT data
result_df = components_df.merge(vuln_df, on="package_id", how="left").merge(violations_df, on="package_id", how="left")

# --- SCANOSS Excel Report ---
scanoss_components = []
if scanoss_path.exists():
    scanoss_data = load_json(scanoss_path)
    for match in scanoss_data.get("matches", []):
        scanoss_components.append({
            "component": match.get("name", "N/A"),
            "version": match.get("version", "N/A"),
            "license": match.get("licenses", [{}])[0].get("name", "N/A") if match.get("licenses") else "N/A"
        })

scanoss_df = pd.DataFrame(scanoss_components)

# --- Write to Excel with multiple sheets ---
with pd.ExcelWriter("ort_full_scan_report.xlsx", engine="openpyxl") as writer:
    result_df.to_excel(writer, index=False, sheet_name="ORT Full Report")
    scanoss_df.to_excel(writer, index=False, sheet_name="SCANOSS Components")

print("✅ Combined Excel report generated: ort_full_scan_report.xlsx")
