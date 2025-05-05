// .ort/config/evaluation/rules.kts

import org.ossreviewtoolkit.model.EvaluatorIssue
import org.ossreviewtoolkit.model.Severity
import org.ossreviewtoolkit.model.Repository

// File: .ort/config/evaluation/rules.kts

rules = ruleSet("Default Rules") {
    rule("NO_MEDIUM_OR_HIGH_VULNERABILITIES") {
        severity = Severity.HINT
        condition {
            advisorIssues.none { it.severity >= Severity.MEDIUM }
        }
        hint("No medium or higher severity vulnerabilities found.")
    }
}
