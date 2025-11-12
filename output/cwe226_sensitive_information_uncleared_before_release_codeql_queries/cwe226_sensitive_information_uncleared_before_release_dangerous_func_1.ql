/**
 * @name Cwe226 Sensitive Information Uncleared Before Release Dangerous Func 1
 * @description Use of ALLOCA allocates memory on stack without bounds checking. Consider using malloc with proper size validation.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id cpp/cwe226_sensitive_information_uncleared_before_release_dangerous_func_1
 * @tags security
 *       external/cwe/cwe-226
 */

import cpp
from FunctionCall fc
where fc.getTarget().getName() = "ALLOCA"
select fc, "Use of ALLOCA allocates memory on stack without bounds checking. Consider using malloc with proper size validation."
