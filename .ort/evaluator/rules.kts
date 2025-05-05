import org.ossreviewtoolkit.evaluator.EvaluatorRun
import org.ossreviewtoolkit.evaluator.Severity

rules = EvaluatorRun {
    rule("NO_MEDIUM_OR_HIGH_VULNERABILITIES") {
        severity = Severity.HINT
        condition {
            it.advisorIssues.none { issue -> issue.severity >= Severity.MEDIUM }
        }
        hint("No medium or higher severity vulnerabilities found.")
    }
}
