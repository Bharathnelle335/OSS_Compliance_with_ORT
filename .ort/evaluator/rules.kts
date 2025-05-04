// .ort/config/evaluation/rules.kts

import org.ossreviewtoolkit.evaluator.EvaluatorRun
import org.ossreviewtoolkit.evaluator.Severity
import org.ossreviewtoolkit.model.Repository

rules = evaluatorRun {
    rule("NO_VULNERABILITIES") {
        severity = Severity.HINT
        condition {
            it.advisorIssues.isEmpty()
        }
        hint("No known vulnerabilities.")
    }
}
