/**
 * @name Cwe197 Numeric Truncation Error Dangerous Func 1
 * @description Potentially dangerous function fscanf detected.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id cpp/cwe197_numeric_truncation_error_dangerous_func_1
 * @tags security
 *       external/cwe/cwe-197
 */

import cpp
from FunctionCall fc
where fc.getTarget().getName() = "fscanf"
select fc, "Potentially dangerous function fscanf detected."
