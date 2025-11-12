/**
 * @name Cwe197 Numeric Truncation Error Dangerous Func 3
 * @description Use of fgets - ensure proper buffer size and null termination.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id cpp/cwe197_numeric_truncation_error_dangerous_func_3
 * @tags security
 *       external/cwe/cwe-197
 */

import cpp
from FunctionCall fc
where fc.getTarget().getName() = "fgets"
select fc, "Use of fgets - ensure proper buffer size and null termination."
