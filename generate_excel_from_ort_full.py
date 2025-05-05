
import yaml
import json
import pandas as pd
from pathlib import Path

# Define input paths
analyzer_path = Path("ort-output/analyzer/analyzer-result.yml")
advisor_path = Path("ort-output/advisor/advisor-result.yml")
evaluation_path = Path("ort-output/evaluator/evaluation-result.yml")
scanoss_path = Path("ort-output/scanner/scanoss.spdx.json")

# Safe YAML loader
def safe_load_yaml(path):
    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    else:
        print(f"⚠️ Skipping missing file: {path}")
        return {}

# Load YAML/JSON files safely
analyzer_data = safe_load_yaml(analyzer_path)
advisor_data = safe_load_yaml(advisor_path)
evaluation_data = safe_load_yaml(evaluation_path)

def load_json(path):
    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    else:
        print(f"⚠️ Skipping missing file: {path}")
        return {}

scanoss_data = load_json(scanoss_path)

# Initialize data lists
components = []
vulnerabilities = []
violations = []
scanoss_components = []

# ORT Analyzer
if "projects" in analyzer_data:
    for project in analyzer_data["projects"]:
        for scope in project.get("scopes", []):
            for pkg in scope.get("dependencies", []):
                components.append({
                    "project": project.get("id", "unknown"),
                    "scope": scope.get("name", "unknown"),
                    "package_id": pkg.get("id", "unknown")
                })

# ORT Advisor
if "advisor" in advisor_data:
    for result in advisor_data["advisor"].get("results", []):
        if not isinstance(result, dict):
            print(f"⚠️ Skipping malformed advisor result: {result}")
            continue
        pkg_id = result.get("id", "unknown")
        for advisor in result.get("advisor", {}).get("issues", []):
            vulnerabilities.append({
                "package_id": pkg_id,
                "vulnerability_id": advisor.get("id", "N/A"),
                "severity": advisor.get("severity", "N/A"),
                "url": advisor.get("references", [{}])[0].get("url", "N/A") if advisor.get("references") else "N/A"
            })

# ORT Evaluator
if "evaluator" in evaluation_data:
    for rule_violation in evaluation_data["evaluator"].get("violations", []):
        violations.append({
            "package_id": rule_violation.get("pkg", {}).get("id", "N/A"),
            "rule": rule_violation.get("rule", "N/A"),
            "severity": rule_violation.get("severity", "N/A"),
            "message": rule_violation.get("message", "N/A")
        })

# SCANOSS SPDX
for match in scanoss_data.get("matches", []):
    scanoss_components.append({
        "component": match.get("name", "N/A"),
        "version": match.get("version", "N/A"),
        "license": match.get("licenses", [{}])[0].get("name", "N/A") if match.get("licenses") else "N/A"
    })

# Convert to DataFrames
components_df = pd.DataFrame(components)
vuln_df = pd.DataFrame(vulnerabilities)
violations_df = pd.DataFrame(violations)
scanoss_df = pd.DataFrame(scanoss_components)

# Merge ORT dataframes if any data exists
if not components_df.empty:
    result_df = components_df.merge(vuln_df, on="package_id", how="left")                              .merge(violations_df, on="package_id", how="left")
else:
    result_df = pd.DataFrame()

# Write to Excel with multiple sheets
excel_written = False
with pd.ExcelWriter("ort_full_scan_report.xlsx", engine="openpyxl") as writer:
    if not result_df.empty:
        result_df.to_excel(writer, index=False, sheet_name="ORT Full Report")
        excel_written = True
    if not scanoss_df.empty:
        scanoss_df.to_excel(writer, index=False, sheet_name="SCANOSS Components")
        excel_written = True

# Final log summary
print("\n📋 Final Report Summary:")
print(f"✅ Analyzer processed: {len(components)} components" if components else "⚠️ Analyzer skipped or empty")
print(f"✅ Advisor processed: {len(vulnerabilities)} vulnerabilities" if vulnerabilities else "⚠️ Advisor skipped or empty")
print(f"✅ Evaluator processed: {len(violations)} violations" if violations else "⚠️ Evaluator skipped or empty")
print(f"✅ SCANOSS processed: {len(scanoss_components)} matches" if scanoss_components else "⚠️ SCANOSS skipped or empty")
print("✅ Excel report written: ort_full_scan_report.xlsx" if excel_written else "❌ Excel report not generated (no data)")
