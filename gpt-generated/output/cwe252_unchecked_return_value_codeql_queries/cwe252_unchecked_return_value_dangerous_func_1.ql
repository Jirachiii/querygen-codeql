/**
 * @name Cwe252 Unchecked Return Value Dangerous Func 1
 * @description Use of fgets - ensure proper buffer size and null termination.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id cpp/cwe252_unchecked_return_value_dangerous_func_1
 * @tags security
 *       external/cwe/cwe-252
 */

import cpp
from FunctionCall fc
where fc.getTarget().getName() = "fgets"
select fc, "Use of fgets - ensure proper buffer size and null termination."
