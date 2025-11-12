/**
 * @name Cwe226 Sensitive Information Uncleared Before Release Dangerous Func 2
 * @description Use of fgets - ensure proper buffer size and null termination.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id cpp/cwe226_sensitive_information_uncleared_before_release_dangerous_func_2
 * @tags security
 *       external/cwe/cwe-226
 */

import cpp
from FunctionCall fc
where fc.getTarget().getName() = "fgets"
select fc, "Use of fgets - ensure proper buffer size and null termination."
