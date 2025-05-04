import yaml
import pandas as pd
from pathlib import Path

# Define the paths to the input files
analyzer_path = Path("ort-output/analyzer/analyzer-result.yml")
advisor_path = Path("ort-output/advisor/advisor-result.yml")
evaluation_path = Path("ort-output/evaluator/evaluation-result.yml")

# Load YAML files
def load_yaml(path):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

analyzer_data = load_yaml(analyzer_path)
advisor_data = load_yaml(advisor_path)
evaluation_data = load_yaml(evaluation_path)

# Extract analyzer component info
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

# Extract vulnerabilities from advisor results
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

# Extract policy violations from evaluation results
violations = []
for rule_violation in evaluation_data.get("evaluator", {}).get("violations", []):
    violations.append({
        "package_id": rule_violation.get("pkg", {}).get("id", "N/A"),
        "rule": rule_violation.get("rule", "N/A"),
        "severity": rule_violation.get("severity", "N/A"),
        "message": rule_violation.get("message", "N/A")
    })

violations_df = pd.DataFrame(violations)

# Merge all results
result_df = components_df.merge(vuln_df, on="package_id", how="left").merge(violations_df, on="package_id", how="left")

# Save to Excel
output_file = "ort_full_scan_report.xlsx"
result_df.to_excel(output_file, index=False)
print(f"✅ Excel report generated: {output_file}")
