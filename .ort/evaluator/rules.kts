// .ort/config/evaluation/rules.kts

import org.ossreviewtoolkit.evaluator.EvaluatorRun
import org.ossreviewtoolkit.model.AdvisorIssue
import org.ossreviewtoolkit.model.EvaluatorIssue
import org.ossreviewtoolkit.model.Severity
import org.ossreviewtoolkit.model.Repository

rules = evaluatorRun {
    rule("NO_VULNERABILITIES") {
        severity = Severity.HINT
        condition {
            it.advisorIssues.none { issue -> issue.severity >= Severity.MEDIUM }
        }
        hint("No medium or higher severity vulnerabilities found.")
    }
}
