// Evaluate packages using simple rules for security and license risks

package ort.evaluator.rules

import org.ossreviewtoolkit.evaluator.Evaluator
import org.ossreviewtoolkit.model.config.LicenseChoice

EvaluatorRuleSet {

    // Flag packages with unknown or no license
    rule("UNKNOWN_LICENSE") {
        condition {
            pkg.licenseDeclared == null || pkg.licenseDeclared.toString().contains("NONE", ignoreCase = true)
        }
        message = "Package has no declared license."
        severity = Severity.ERROR
    }

    // Flag copyleft licenses
    rule("STRONG_COPYLEFT_LICENSE") {
        condition {
            pkg.licenseDeclared?.toString()?.contains("GPL", ignoreCase = true) == true ||
                    pkg.licenseDeclared?.toString()?.contains("AGPL", ignoreCase = true) == true
        }
        message = "Strong copyleft license found: ${pkg.licenseDeclared}"
        severity = Severity.WARNING
    }

    // Allow permissive licenses (Apache, MIT, BSD, etc.)
    rule("PERMISSIVE_LICENSE") {
        condition {
            pkg.licenseDeclared?.toString()?.let {
                it.contains("Apache", true) || it.contains("MIT", true) || it.contains("BSD", true)
            } ?: false
        }
        message = "Permissive license allowed: ${pkg.licenseDeclared}"
        severity = Severity.HINT
    }

    // Flag high-severity vulnerabilities
    rule("VULNERABILITY_HIGH_SEVERITY") {
        condition {
            pkg.vulnerabilities.any { it.severity.equals("HIGH", ignoreCase = true) }
        }
        message = "High severity vulnerability found."
        severity = Severity.ERROR
    }
}
