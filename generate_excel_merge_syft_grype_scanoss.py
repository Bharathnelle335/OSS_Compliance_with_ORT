import os
import json
import pandas as pd

def extract_ort_data(ort_analyzer_path, ort_report_path):
    components = []

    # Load analyzer-result.json
    with open(ort_analyzer_path, 'r', encoding='utf-8') as f:
        analyzer_data = json.load(f)

    projects = analyzer_data.get('analyzer', {}).get('result', {}).get('projects', [])
    for project in projects:
        for scope in project.get('scopes', []):
            for pkg in scope.get('dependencies', []):
                name = pkg.get('id', '').split(':')[1] if ':' in pkg.get('id', '') else pkg.get('id', '')
                version = pkg.get('id', '').split(':')[2] if ':' in pkg.get('id', '') else 'unknown'
                components.append({
                    'component': name,
                    'version': version,
                    'license': 'N/A',
                    'license_source': 'ORT Analyzer',
                    'license_url': 'N/A'
                })

    # Load ort-report.json if available and override license info
    if os.path.exists(ort_report_path):
        with open(ort_report_path, 'r', encoding='utf-8') as f:
            report_data = json.load(f)

        findings = report_data.get('report', {}).get('licenseFindings', [])
        for finding in findings:
            pkg_name = finding.get('packageId', '').split(':')[1]
            license_name = finding.get('license')
            for comp in components:
                if comp['component'] == pkg_name:
                    comp['license'] = license_name
                    comp['license_source'] = 'ORT Report'
                    comp['license_url'] = 'unknown'

    return components

def save_to_excel(data, image_name):
    df = pd.DataFrame(data)
    excel_name = f"{image_name}_ort_components_report.xlsx"
    df.to_excel(excel_name, index=False)
    print(f"✅ Excel report generated: {excel_name}")

if __name__ == "__main__":
    analyzer_result_file = "ort-output/analyzer/analyzer-result.json"
    report_result_file = "ort-output/report/ort-report.json"
    docker_image = os.getenv("IMAGE_NAME", "unknown-image").replace(":", "_").replace("/", "_")

    components = extract_ort_data(analyzer_result_file, report_result_file)
    save_to_excel(components, docker_image)
