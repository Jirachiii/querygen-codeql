/**
 * @name Cwe226 Sensitive Information Uncleared Before Release Dangerous Func 3
 * @description Use of LogonUserA with sensitive credentials. Ensure passwords are cleared from memory after use.
 * @kind problem
 * @problem.severity error
 * @precision high
 * @id cpp/cwe226_sensitive_information_uncleared_before_release_dangerous_func_3
 * @tags security
 *       external/cwe/cwe-226
 */

import cpp
from FunctionCall fc
where fc.getTarget().getName() = "LogonUserA"
select fc, "Use of LogonUserA with sensitive credentials. Ensure passwords are cleared from memory after use."
