// File: .ort/config/evaluation/rules.kts

import org.ossreviewtoolkit.evaluator.rules
import org.ossreviewtoolkit.evaluator.Severity

rules {
    rule("NO_MEDIUM_OR_HIGH_VULNERABILITIES") {
        severity = Severity.HINT

        condition {
            advisorIssues.none { it.severity >= Severity.MEDIUM }
        }

        hint("No medium or high severity vulnerabilities found.")
    }
}
