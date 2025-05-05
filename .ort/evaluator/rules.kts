import org.ossreviewtoolkit.evaluator.RuleSet
import org.ossreviewtoolkit.evaluator.Severity

val rules = RuleSet("NO_MEDIUM_OR_HIGH_VULNERABILITIES") {
    rule("No medium or high severity vulnerabilities") {
        severity = Severity.HINT

        condition {
            advisorIssues.none { it.severity >= Severity.MEDIUM }
        }

        hint("No medium or high severity vulnerabilities found.")
    }
}
